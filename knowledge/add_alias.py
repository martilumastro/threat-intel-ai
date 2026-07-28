"""Add new aliases to existing actors."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from common import KNOWLEDGE_DB_PATH, get_connection

NEW_ALIASES = {
    "APT28": ["Fancy Bear", "Sofacy", "Forest Blizzard", "STRONTIUM", "Sednit", "Pawn Storm"],
    "Cavern Manticore": ["Cav3rn", "Lyceum"],
    "TeamPCP": ["TeamPCP", "Mini Shai-Hulud"],
    "The Gentlemen": ["Storm-2697", "ArmCorp"],
}

def add_aliases():
    conn = get_connection(KNOWLEDGE_DB_PATH)
    try:
        for canonical, aliases in NEW_ALIASES.items():
            cursor = conn.execute("SELECT id FROM actors WHERE canonical_name = ?", (canonical,))
            actor_row = cursor.fetchone()
            if actor_row:
                actor_id = actor_row[0]
                for alias in aliases:
                    conn.execute("""
                        INSERT OR IGNORE INTO actor_aliases (actor_id, alias)
                        VALUES (?, ?)
                    """, (actor_id, alias))
        conn.commit()
        print(f"Added aliases for {len(NEW_ALIASES)} actors.")
    finally:
        conn.close()

if __name__ == "__main__":
    add_aliases()