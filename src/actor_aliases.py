"""Known threat-actor alias handling.
This file manages threat actor aliases—that is, the alternative names by which an APT group might be known.

In the realm of Cyber \u200b\u200bThreat Intelligence, a single actor can have multiple names. Example:

The canonical name --> APT29
is associated with various aliases --> Cozy Bear, NOBELIUM, The Dukes

If, while analyzing an article, the name: Cozy Bear, is encountered, 
the pipeline must recognize that it refers to the same actor: Cozy Bear → APT29
"""

import sqlite3

from common import PROJECT_DIR  # Imports a variable named PROJECT_DIR.

DB_PATH = PROJECT_DIR / "knowledge" / "threat_intel.db" # Constructs the database path.

""" This is the file's main function.
Its task is to:
read all the actors from the database and create a Python structure containing their aliases."""
def load_actor_aliases() -> dict[str, list[str]]: # The returned type is a dictionary where: the key is a string and the value is a list of strings.

    """Load and validate the local actor-alias catalogue from the database.
    Returns the same shape the JSON-based version used to return:
    {"APT29": ["Cozy Bear", "NOBELIUM", ...], ...}
    """
    if not DB_PATH.exists(): # Checks if the database file exists at the specified path.
        raise TypeError(
            f"Knowledge database not found: {DB_PATH}. Run knowledge/init_db.py first."
        )

    # Try opening the SQLite database; if all goes well:
    # connectid --> becomes an active connection.
    try:
        connection = sqlite3.connect(DB_PATH)
    except sqlite3.Error as error:
        """ If SQLite generates an error:
                corrupt database;
                missing permissions;
                unreadable file;
            go here.
        """
        # Converts the SQLite error into a more readable error.
        raise TypeError(f"Could not open knowledge database: {error}") from error

    try:
        # The cursor allows you to execute SQL queries.
        cursor = connection.cursor()
        # Run this query: SELECT id, canonical_name FROM actors;
        cursor.execute("SELECT id, canonical_name FROM actors")
        # It gets all the results
        actors = cursor.fetchall()

        # Creating an alias dictionary
        aliases: dict[str, list[str]] = {}
        # iterate over the actors
        for actor_id, canonical_name in actors:

            """ Retrieves the actors; executes a parameterized query.
                SELECT alias
                FROM actor_aliases
                WHERE actor_id = 1;"""
            cursor.execute(
                "SELECT alias FROM actor_aliases WHERE actor_id = ? ORDER BY alias", # ? Prevent SQL injection.
                (actor_id,),
            )
            # It takes all the aliases found
            aliases[canonical_name] = [row[0] for row in cursor.fetchall()]
    # Handles errors during queries
    except sqlite3.Error as error:
        raise TypeError(f"Failed to read alias catalogue from database: {error}") from error
    finally:
        """ This part is always executed. 
        Even if an error occurs.
        It closes the database.
        This is important because it prevents:
        connections being left open;
        database locks."""
        connection.close()

    # Check that the data is correct after reading the database.
    for canonical_name, known_aliases in aliases.items():
        # Verify that the canonical name is a string
        if not isinstance(canonical_name, str):
            raise TypeError("Each canonical actor name must be a string.")
        # Check that the aliases are a list
        if not isinstance(known_aliases, list) or not all(
            # Check that each alias is a string
            isinstance(alias, str) for alias in known_aliases
        ):
            raise TypeError(
                f"Aliases for '{canonical_name}' must be a list of strings."
            )

    return aliases # Returns the complete dictionary

""" This function normalizes a name.
It receives:
    a name found during analysis;
    the alias dictionary.
It returns:
    the canonical name, if found;
    the original name, if unknown.
"""
def canonical_actor_name(actor_name: str, aliases: dict[str, list[str]]) -> str:
    """Return the canonical actor name when a known alias is supplied."""
    normalized_name = actor_name.strip().casefold() # Clear name
    # strip() --> Removes leading and trailing spaces
    # casefold() --> Converts to lowercase more robustly than lower()
    
    # It cycles through all the known actors
    for canonical_name, known_aliases in aliases.items():
        # Combines: official name and alias
        all_names = [canonical_name, *known_aliases]

        # Check if the received name matches one of the known names
        if any(normalized_name == name.strip().casefold() for name in all_names):
            return canonical_name

    return actor_name