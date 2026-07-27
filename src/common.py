"""Shared validation, normalisation, paths, JSON persistence, and database helpers."""

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
REQUEST_TIMEOUT = int(os.getenv("THREAT_INTEL_REQUEST_TIMEOUT", "3600"))

MAX_DOCUMENT_CHARS = int(os.getenv("THREAT_INTEL_MAX_DOCUMENT_CHARS", "50000"))  # Default 50k chars

IOC_CATEGORIES = (
    "ip", 
    "domains", 
    "hashes", 
    "emails", 
    "mitre_ttps", 
    "actors_mentioned",
    "cve_ids",
    "urls",
    "suspicious_files"
)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$")
TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

GENERIC_TTPS = {"T1059", "T1071", "T1105", "T1041"}

# ===== NON-ACTOR FILTER =====
# This is a starter list of common cybersecurity vendors and research firms
# that are often mistaken for threat actors by the LLM.
# Feel free to extend this list based on your observed false positives.
NON_ACTOR_KEYWORDS = [
    # ... esistenti ...
    "github.com", "github", "microsoft.com", "microsoft", "google.com", 
    "google", "amazon.com", "aws", "azure", "check point", "intel 471", 
    "flashpoint", "constella", "crowdstrike", "mandiant", "secureworks", 
    "trend micro", "symantec", "kaspersky", "cisco", "palo alto", 
    "unit 42", "recorded future", "fireeye", "sentinel one", "carbon black", 
    "cylance", "eset", "sophos", "mcafee", "fortinet", "proofpoint", 
    "mimecast", "the hacker news", "sans institute", "isc sans", 
    "sans", "check point software", "constella intelligence",
    # Domini di fonti
    "sans.edu", "isc.sans.edu", "securelist.com", "checkpoint.com",
    "bleepingcomputer.com", "krebsonsecurity.com", "unit42.paloaltonetworks.com"
]


def is_non_actor(name: str) -> bool:
    """
    Check if a name is likely a cybersecurity vendor/researcher, not a threat actor.

    This is a simple keyword-based filter. It's not perfect but catches
    the most common false positives. Add new keywords to NON_ACTOR_KEYWORDS
    as you encounter them in your data.
    """
    name_lower = name.lower().strip()
    for keyword in NON_ACTOR_KEYWORDS:
        if keyword in name_lower:
            return True
    return False


# ===== DOCUMENT CHUNKING =====
def split_document(text: str, max_chars: int = 15000, overlap: int = 500) -> list[str]:
    """
    Split a long document into overlapping chunks.

    Args:
        text: The full document text
        max_chars: Maximum characters per chunk (default: 15k)
        overlap: Overlap between chunks to preserve context (default: 500)

    Returns:
        List of text chunks
    """
    if len(text) <= max_chars:
        return [text]

    chunks = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))

        # If not at the end, try to cut at paragraph or sentence boundary
        if end < len(text):
            # Find best cut point (paragraph first, then sentence)
            cut = text.rfind("\n\n", start, end)
            if cut == -1 or cut < start + max_chars // 2:
                cut = text.rfind(". ", start, end)
            if cut != -1 and cut > start + max_chars // 2:
                end = cut + 2  # Keep the period

        chunks.append(text[start:end])
        start = end - overlap  # Overlap for context

    return chunks


# ===== DATABASE CONNECTION =====
KNOWLEDGE_DB_PATH = PROJECT_DIR / "knowledge" / "threat_intel.db"


@contextmanager
def get_knowledge_db():
    """
    Context manager for knowledge database connections.

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
    """
    Returns a SQLite connection with foreign keys enforced.

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
    """Validate that a value is a list of strings."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"'{category}' must be a list of strings")
    return value


def _unique(values: list[str]) -> list[str]:
    """Deduplicate a list while preserving order."""
    return list(dict.fromkeys(values))


def normalize_extraction(data: Any) -> dict[str, list[str]]:
    """
    Validate the LLM schema and return canonical, deduplicated IOC values.

    This function also applies the non-actor filter to remove
    cybersecurity vendors and researchers from the actors_mentioned list.
    """
    if not isinstance(data, dict):
        raise TypeError("extraction result must be a JSON object")

    # --- IGNORA campi extra invece di sollevare errore ---
    # unknown = set(data) - set(IOC_CATEGORIES)
    # if unknown:
    #     raise TypeError(f"unexpected extraction fields: {', '.join(sorted(unknown))}")

    result: dict[str, list[str]] = {category: [] for category in IOC_CATEGORIES}

    # IP addresses
    for raw in _string_list(data.get("ip", []), "ip"):
        value = raw.strip()
        try:
            result["ip"].append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    # Domains
    for raw in _string_list(data.get("domains", []), "domains"):
        value = raw.strip().lower().replace("[.]", ".").replace("(.)", ".").rstrip(".")
        if DOMAIN_RE.fullmatch(value):
            result["domains"].append(value)

    # Hashes
    for raw in _string_list(data.get("hashes", []), "hashes"):
        value = re.sub(r"\s+", "", raw).lower()
        if HASH_RE.fullmatch(value):
            result["hashes"].append(value)

    # Emails
    for raw in _string_list(data.get("emails", []), "emails"):
        value = raw.strip().lower().replace("[at]", "@").replace("[.]", ".")
        if EMAIL_RE.fullmatch(value):
            result["emails"].append(value)

    # MITRE TTPs
    for raw in _string_list(data.get("mitre_ttps", []), "mitre_ttps"):
        value = raw.strip().upper()
        if TTP_RE.fullmatch(value):
            result["mitre_ttps"].append(value)

    # Actors mentioned - with non-actor filtering
    for raw in _string_list(data.get("actors_mentioned", []), "actors_mentioned"):
        value = " ".join(raw.split())
        if value and not is_non_actor(value):
            result["actors_mentioned"].append(value)

        # CVE IDs
    for raw in _string_list(data.get("cve_ids", []), "cve_ids"):
        value = raw.strip().upper()
        # Regex semplice per CVE (es. CVE-2024-1234)
        if re.match(r"^CVE-\d{4}-\d+$", value):
            result["cve_ids"].append(value)

    # URLs
    for raw in _string_list(data.get("urls", []), "urls"):
        value = raw.strip()
        if value.startswith(("http://", "https://")):
            result["urls"].append(value)

    # Suspicious files
    for raw in _string_list(data.get("suspicious_files", []), "suspicious_files"):
        value = " ".join(raw.split())
        if value:
            result["suspicious_files"].append(value)

    return {category: _unique(values) for category, values in result.items()}


def safe_document_name(name: str) -> str:
    """
    Create a filename-safe document identifier without accepting a path.

    This prevents path traversal attacks and ensures filenames are safe
    for all filesystems.
    """
    if not isinstance(name, str):
        raise TypeError("document name must be a string")
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    if not normalized:
        raise TypeError("document name has no usable characters")
    return normalized[:120]


def atomic_write_json(path: Path, record: dict[str, Any]) -> None:
    """
    Write JSON atomically so readers never see a partially written file.

    This uses a temporary file and atomic rename to ensure the write
    is either complete or not performed at all.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        Path(temporary_path).replace(path)
    except Exception:
        Path(temporary_path).unlink(missing_ok=True)
        raise