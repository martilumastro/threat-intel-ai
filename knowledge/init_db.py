"""
Initializes the local knowledge database (knowledge/threat_intel.db).

Creates the relational schema only - no vector/embedding tables yet
(that's a later phase). Safe to run multiple times: uses
CREATE TABLE IF NOT EXISTS, so it won't wipe existing data.

Usage:
    python knowledge/init_db.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "threat_intel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_name TEXT UNIQUE NOT NULL,
    country TEXT,
    motivation TEXT,           -- e.g. "cybercrime", "APT", "hacktivism"
    first_seen DATE,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS actor_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    alias TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT UNIQUE NOT NULL,   -- e.g. "CAMP-2024-001"
    first_seen DATE,
    last_seen DATE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS campaign_actors (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, actor_id)
);

CREATE TABLE IF NOT EXISTS ttps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ttp_code TEXT UNIQUE NOT NULL,      -- e.g. "T1566.001"
    is_generic BOOLEAN NOT NULL DEFAULT 0,  -- 1 if too common to be evidence alone
    description TEXT
);

CREATE TABLE IF NOT EXISTS campaign_ttps (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ttp_id INTEGER NOT NULL REFERENCES ttps(id) ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, ttp_id)
);


CREATE INDEX IF NOT EXISTS idx_actor_aliases_alias ON actor_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_ttps_code ON ttps(ttp_code);
"""


def init_db(db_path: Path = DB_PATH) -> None:
    """Creates the schema at db_path if it doesn't already exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    print(f"Schema ready at: {DB_PATH}")