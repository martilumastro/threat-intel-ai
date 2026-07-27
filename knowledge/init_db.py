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


-- DOMAINS TABLES (NEW)

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    description TEXT,
    category TEXT,               -- c2, phishing, malware, scanner, mining, impersonation, other
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS actor_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    frequency INTEGER DEFAULT 1,
    UNIQUE(domain_id, actor_id)
);


-- LEARNING TABLES (NEW)

-- Positive examples: what to extract
CREATE TABLE IF NOT EXISTS ioc_examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,              -- ip, domain, hash, actor, ttp, cve, url, suspicious_file
    value TEXT NOT NULL,
    context TEXT,                        -- brief context / source snippet
    source_article TEXT,                 -- which article this came from
    confidence INTEGER DEFAULT 1,        -- 1-5, how confident we are
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved BOOLEAN DEFAULT 0,          -- 0 = pending, 1 = approved by user
    UNIQUE(category, value)
);

-- Negative examples: what NOT to extract (false positives)
CREATE TABLE IF NOT EXISTS false_positives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    source_article TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved BOOLEAN DEFAULT 0,
    UNIQUE(category, value)
);

-- TTP patterns per actor (learned associations)
CREATE TABLE IF NOT EXISTS actor_ttp_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ttp_id INTEGER NOT NULL REFERENCES ttps(id) ON DELETE CASCADE,
    frequency INTEGER DEFAULT 1,
    confidence INTEGER DEFAULT 1,
    UNIQUE(actor_id, ttp_id)
);

-- Domain patterns per actor (learned associations)
CREATE TABLE IF NOT EXISTS actor_domain_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    domain_pattern TEXT NOT NULL,
    frequency INTEGER DEFAULT 1,
    confidence INTEGER DEFAULT 1,
    UNIQUE(actor_id, domain_pattern)
);

-- Extraction log: track what was processed and what was suggested
CREATE TABLE IF NOT EXISTS extraction_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_url TEXT,
    article_title TEXT,
    extraction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    iocs_found TEXT,                     -- JSON: what was extracted
    actors_found TEXT,                   -- JSON: actors found
    ttps_found TEXT,                     -- JSON: TTPs found
    new_iocs TEXT,                       -- JSON: new IOCs suggested to user
    user_approved BOOLEAN DEFAULT 0      -- 0 = pending, 1 = approved
);


-- INDEXES

CREATE INDEX IF NOT EXISTS idx_actor_aliases_alias ON actor_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_ttps_code ON ttps(ttp_code);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_actor_domains_actor ON actor_domains(actor_id);
CREATE INDEX IF NOT EXISTS idx_ioc_examples_category ON ioc_examples(category);
CREATE INDEX IF NOT EXISTS idx_false_positives_category ON false_positives(category);
CREATE INDEX IF NOT EXISTS idx_actor_ttp_patterns_actor ON actor_ttp_patterns(actor_id);
CREATE INDEX IF NOT EXISTS idx_actor_domain_patterns_actor ON actor_domain_patterns(actor_id);
CREATE INDEX IF NOT EXISTS idx_extraction_log_timestamp ON extraction_log(extraction_timestamp);
"""


def init_db(db_path: Path = DB_PATH) -> None:
    """Creates the schema at db_path if it doesn't already exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
        print(f"Schema ready at: {db_path}")
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()