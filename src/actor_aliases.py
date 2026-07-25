"""Known threat-actor alias handling."""

import sqlite3

from common import PROJECT_DIR

DB_PATH = PROJECT_DIR / "knowledge" / "threat_intel.db"


def load_actor_aliases() -> dict[str, list[str]]:
    """Load and validate the local actor-alias catalogue from the database.

    Returns the same shape the JSON-based version used to return:
    {"APT29": ["Cozy Bear", "NOBELIUM", ...], ...}
    """
    if not DB_PATH.exists():
        raise TypeError(
            f"Knowledge database not found: {DB_PATH}. Run knowledge/init_db.py first."
        )

    try:
        connection = sqlite3.connect(DB_PATH)
    except sqlite3.Error as error:
        raise TypeError(f"Could not open knowledge database: {error}") from error

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, canonical_name FROM actors")
        actors = cursor.fetchall()

        aliases: dict[str, list[str]] = {}
        for actor_id, canonical_name in actors:
            cursor.execute(
                "SELECT alias FROM actor_aliases WHERE actor_id = ? ORDER BY alias",
                (actor_id,),
            )
            aliases[canonical_name] = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as error:
        raise TypeError(f"Failed to read alias catalogue from database: {error}") from error
    finally:
        connection.close()

    for canonical_name, known_aliases in aliases.items():
        if not isinstance(canonical_name, str):
            raise TypeError("Each canonical actor name must be a string.")
        if not isinstance(known_aliases, list) or not all(
            isinstance(alias, str) for alias in known_aliases
        ):
            raise TypeError(
                f"Aliases for '{canonical_name}' must be a list of strings."
            )

    return aliases


def canonical_actor_name(actor_name: str, aliases: dict[str, list[str]]) -> str:
    """Return the canonical actor name when a known alias is supplied."""
    normalized_name = actor_name.strip().casefold()

    for canonical_name, known_aliases in aliases.items():
        all_names = [canonical_name, *known_aliases]

        if any(normalized_name == name.strip().casefold() for name in all_names):
            return canonical_name

    return actor_name