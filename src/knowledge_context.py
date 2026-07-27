"""Read curated threat-intelligence knowledge for extraction-time support."""

import sqlite3

from common import KNOWLEDGE_DB_PATH


def _connect() -> sqlite3.Connection | None:
    """Open the curated knowledge database, if it is available."""
    if not KNOWLEDGE_DB_PATH.exists():
        return None
    connection = sqlite3.connect(KNOWLEDGE_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)
    ).fetchone() is not None


def build_extraction_knowledge_context(text: str) -> str:
    """Build concise, relevant curated context for the local extraction model."""
    connection = _connect()
    if connection is None:
        return "No curated database is available for this extraction."

    try:
        sections: list[str] = []
        normalized_text = text.casefold()

        if _table_exists(connection, "actors") and _table_exists(connection, "actor_aliases"):
            rows = connection.execute(
                """
                SELECT a.canonical_name, GROUP_CONCAT(aa.alias, ', ') AS aliases
                FROM actors a
                LEFT JOIN actor_aliases aa ON aa.actor_id = a.id
                GROUP BY a.id
                ORDER BY a.canonical_name
                """
            ).fetchall()
            actor_lines = []
            for row in rows:
                names = [row["canonical_name"]]
                if row["aliases"]:
                    names.extend(alias.strip() for alias in row["aliases"].split(","))
                if any(name.casefold() in normalized_text for name in names):
                    actor_lines.append(
                        f"- {row['canonical_name']} (aliases: {row['aliases'] or 'none'})"
                    )
            if actor_lines:
                sections.append(
                    "CURATED ACTOR IDENTITIES (use the canonical name only when it is "
                    "actually mentioned or clearly identified in the report):\n"
                    + "\n".join(actor_lines)
                )

        if _table_exists(connection, "ioc_examples"):
            rows = connection.execute(
                "SELECT category, value, context, confidence FROM ioc_examples ORDER BY confidence DESC"
            ).fetchall()
            matches = [row for row in rows if row["value"].casefold() in normalized_text]
            if matches:
                lines = [
                    f"- {row['category']}: {row['value']} "
                    f"(confidence {row['confidence']}/5; {row['context'] or 'no context'})"
                    for row in matches
                ]
                sections.append("CURATED INDICATORS PRESENT IN THIS REPORT:\n" + "\n".join(lines))

        if _table_exists(connection, "domains"):
            rows = connection.execute(
                "SELECT domain, category, notes FROM domains ORDER BY domain"
            ).fetchall()
            matches = [row for row in rows if row["domain"].casefold() in normalized_text]
            if matches:
                lines = [
                    f"- domain: {row['domain']} ({row['category'] or 'unknown'}; "
                    f"{row['notes'] or 'no notes'})"
                    for row in matches
                ]
                sections.append("CURATED DOMAIN MATCHES IN THIS REPORT:\n" + "\n".join(lines))

        if _table_exists(connection, "false_positives"):
            rows = connection.execute(
                "SELECT category, value, context FROM false_positives ORDER BY category, value"
            ).fetchall()
            matches = [row for row in rows if row["value"].casefold() in normalized_text]
            if matches:
                lines = [
                    f"- {row['category']}: {row['value']} ({row['context'] or 'known false positive'})"
                    for row in matches
                ]
                sections.append(
                    "DO NOT EXTRACT THESE CURATED FALSE POSITIVES:\n" + "\n".join(lines)
                )

        return "\n\n".join(sections) or "No relevant curated database entries were found."
    finally:
        connection.close()


def filter_curated_false_positives(data: dict[str, list[str]]) -> dict[str, list[str]]:
    """Remove values explicitly curated as false positives in the database."""
    connection = _connect()
    if connection is None:
        return data

    category_to_field = {
        "actor": "actors_mentioned",
        "domain": "domains",
        "ip": "ip",
        "hash": "hashes",
        "email": "emails",
        "ttp": "mitre_ttps",
        "cve": "cve_ids",
        "url": "urls",
        "suspicious_file": "suspicious_files",
    }

    try:
        if not _table_exists(connection, "false_positives"):
            return data

        rows = connection.execute("SELECT category, value FROM false_positives").fetchall()
        excluded: dict[str, set[str]] = {}
        for row in rows:
            field = category_to_field.get(row["category"])
            if field:
                excluded.setdefault(field, set()).add(row["value"].casefold())

        filtered = {field: list(values) for field, values in data.items()}
        for field, values in filtered.items():
            blocked = excluded.get(field, set())
            filtered[field] = [value for value in values if value.casefold() not in blocked]
        return filtered
    finally:
        connection.close()
