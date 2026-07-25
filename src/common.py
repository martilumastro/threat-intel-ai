"""Shared validation, normalisation, paths, and JSON persistence helpers."""

import ipaddress
import json
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
EXTRACTED_DIR = DATA_DIR / "extracted"
CORRELATED_DIR = DATA_DIR / "correlated"

OLLAMA_URL = os.getenv("THREAT_INTEL_OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.getenv("THREAT_INTEL_MODEL", "qwen3.5:9b")
REQUEST_TIMEOUT = int(os.getenv("THREAT_INTEL_REQUEST_TIMEOUT", "600"))

IOC_CATEGORIES = ("ip", "domains", "hashes", "emails", "mitre_ttps", "actors_mentioned")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$")
TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

GENERIC_TTPS = {"T1059", "T1071", "T1105", "T1041"} 


# ===== DATABASE CONNECTION =====
KNOWLEDGE_DB_PATH = PROJECT_DIR / "knowledge" / "threat_intel.db"


@contextmanager
def get_knowledge_db():
    """Context manager for knowledge database connections.
    
    Enforces foreign keys automatically. Use this for read/write operations
    on the knowledge database.
    
    Example:
        with get_knowledge_db() as conn:
            cursor = conn.execute("SELECT * FROM actors")
            rows = cursor.fetchall()
    """
    if not KNOWLEDGE_DB_PATH.exists():
        raise FileNotFoundError(
            f"Knowledge database not found at {KNOWLEDGE_DB_PATH}. "
            "Run knowledge/init_db.py first."
        )
    conn = sqlite3.connect(str(KNOWLEDGE_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Returns a SQLite connection with foreign keys enforced.
    
    Use this for one-off connections where you don't need a context manager.
    For most use cases, prefer get_knowledge_db().
    
    NOTE: This function does NOT check if the database file exists.
    It is intentionally permissive so it can be used by setup scripts
    (init_db.py, migrate_aliases_json_to_db.py, add_actor_details.py)
    that need to create the database.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _string_list(value: Any, category: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"'{category}' must be a list of strings")
    return value


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def normalize_extraction(data: Any) -> dict[str, list[str]]:
    """Validate the LLM schema and return canonical, deduplicated IOC values."""
    if not isinstance(data, dict):
        raise TypeError("extraction result must be a JSON object")

    unknown = set(data) - set(IOC_CATEGORIES)
    if unknown:
        raise TypeError(f"unexpected extraction fields: {', '.join(sorted(unknown))}")

    result: dict[str, list[str]] = {category: [] for category in IOC_CATEGORIES}
    for raw in _string_list(data.get("ip", []), "ip"):
        value = raw.strip()
        try:
            result["ip"].append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    for raw in _string_list(data.get("domains", []), "domains"):
        value = raw.strip().lower().replace("[.]", ".").replace("(.)", ".").rstrip(".")
        if DOMAIN_RE.fullmatch(value):
            result["domains"].append(value)

    for raw in _string_list(data.get("hashes", []), "hashes"):
        value = re.sub(r"\s+", "", raw).lower()
        if HASH_RE.fullmatch(value):
            result["hashes"].append(value)

    for raw in _string_list(data.get("emails", []), "emails"):
        value = raw.strip().lower().replace("[at]", "@").replace("[.]", ".")
        if EMAIL_RE.fullmatch(value):
            result["emails"].append(value)

    for raw in _string_list(data.get("mitre_ttps", []), "mitre_ttps"):
        value = raw.strip().upper()
        if TTP_RE.fullmatch(value):
            result["mitre_ttps"].append(value)

    for raw in _string_list(data.get("actors_mentioned", []), "actors_mentioned"):
        value = " ".join(raw.split())
        if value:
            result["actors_mentioned"].append(value)

    return {category: _unique(values) for category, values in result.items()}


def safe_document_name(name: str) -> str:
    """Create a filename-safe document identifier without accepting a path."""
    if not isinstance(name, str):
        raise TypeError("document name must be a string")
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    if not normalized:
        raise TypeError("document name has no usable characters")
    return normalized[:120]


def atomic_write_json(path: Path, record: dict[str, Any]) -> None:
    """Write JSON atomically so readers do not see a partially written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        Path(temporary_path).replace(path)
    except Exception:
        Path(temporary_path).unlink(missing_ok=True)
        raise
