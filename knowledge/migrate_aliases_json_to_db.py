"""
One-time migration: loads knowledge/actor_aliases.json into the
actors and actor_aliases tables of knowledge/threat_intel.db.

Safe to re-run: uses INSERT OR IGNORE, so running it twice won't
create duplicates. If you edit actor_aliases.json later and want to
re-sync, just run this again.

Usage:
    python knowledge/migrate_aliases_json_to_db.py
"""

import json
import sqlite3
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent
JSON_PATH = KNOWLEDGE_DIR / "actor_aliases.json"
DB_PATH = KNOWLEDGE_DIR / "threat_intel.db"


def load_json_aliases() -> dict[str, list[str]]:
    with JSON_PATH.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def migrate(aliases: dict[str, list[str]], db_path: Path = DB_PATH) -> None:
    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.cursor()
        actors_inserted = 0
        aliases_inserted = 0

        for canonical_name, alias_list in aliases.items():
            cursor.execute(
                "INSERT OR IGNORE INTO actors (canonical_name) VALUES (?)",
                (canonical_name,),
            )
            actors_inserted += cursor.rowcount

            cursor.execute(
                "SELECT id FROM actors WHERE canonical_name = ?",
                (canonical_name,),
            )
            actor_id = cursor.fetchone()[0]

            for alias in alias_list:
                cursor.execute(
                    "INSERT OR IGNORE INTO actor_aliases (actor_id, alias) VALUES (?, ?)",
                    (actor_id, alias),
                )
                aliases_inserted += cursor.rowcount

        connection.commit()
        print(f"Actors inserted (new): {actors_inserted}")
        print(f"Aliases inserted (new): {aliases_inserted}")
    finally:
        connection.close()


if __name__ == "__main__":
    aliases = load_json_aliases()
    print(f"Loaded {len(aliases)} canonical actors from {JSON_PATH.name}")
    migrate(aliases)
    print("Migration complete.")