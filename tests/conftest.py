"""
Pytest configuration and fixtures for the threat-intel-ai test suite.

This file provides shared fixtures for tests, including a temporary
in-memory SQLite database that mirrors the production schema.
This allows tests to run without requiring the actual threat_intel.db file.
"""

import json
import sqlite3
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent


@pytest.fixture
def fixture_texts() -> dict[str, str]:
    """Load test report texts from tests/fixtures/ directory."""
    return {
        path.stem: path.read_text(encoding="utf-8")
        for path in (TESTS_DIR / "fixtures").glob("test_report_*.txt")
    }


@pytest.fixture
def expected_extractions() -> dict[str, dict]:
    """Load expected extraction results from tests/expected/ directory."""
    return {
        path.stem.removeprefix("extraction_"): json.loads(path.read_text(encoding="utf-8"))
        for path in (TESTS_DIR / "expected").glob("extraction_*.json")
    }


@pytest.fixture
def temp_knowledge_db(tmp_path):
    """
    Create a temporary in-memory SQLite database with the full schema.
    
    This fixture is used by tests that require database access without
    relying on the real knowledge/threat_intel.db file.
    
    Returns:
        Path: Path to the temporary database file.
    """
    db_path = tmp_path / "test_threat_intel.db"
    conn = sqlite3.connect(str(db_path))
    
    # Create all tables matching the production schema
    conn.executescript("""
        -- Core tables
        CREATE TABLE IF NOT EXISTS actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            canonical_name TEXT UNIQUE NOT NULL,
            country TEXT,
            motivation TEXT,
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
            campaign_id TEXT UNIQUE NOT NULL,
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
            ttp_code TEXT UNIQUE NOT NULL,
            is_generic BOOLEAN NOT NULL DEFAULT 0,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS campaign_ttps (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            ttp_id INTEGER NOT NULL REFERENCES ttps(id) ON DELETE CASCADE,
            PRIMARY KEY (campaign_id, ttp_id)
        );

        -- Learning tables
        CREATE TABLE IF NOT EXISTS ioc_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            value TEXT NOT NULL,
            context TEXT,
            source_article TEXT,
            confidence INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved BOOLEAN DEFAULT 0,
            UNIQUE(category, value)
        );

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

        -- Domain tables
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            description TEXT,
            category TEXT,
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

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_actor_aliases_alias ON actor_aliases(alias);
        CREATE INDEX IF NOT EXISTS idx_ttps_code ON ttps(ttp_code);
        CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
        CREATE INDEX IF NOT EXISTS idx_ioc_examples_category ON ioc_examples(category);
        CREATE INDEX IF NOT EXISTS idx_false_positives_category ON false_positives(category);
    """)
    
    conn.commit()
    conn.close()
    
    return db_path


@pytest.fixture
def populated_knowledge_db(temp_knowledge_db):
    """
    Create a temporary database with seed data for testing.
    
    This fixture builds on temp_knowledge_db and adds test data
    for actors, aliases, and TTPs.
    
    Returns:
        Path: Path to the populated temporary database file.
    """
    db_path = temp_knowledge_db
    conn = sqlite3.connect(str(db_path))
    
    # Insert test actors
    conn.executescript("""
        INSERT OR IGNORE INTO actors (id, canonical_name, country, motivation) 
        VALUES 
            (1, 'APT29', 'Russia', 'Cyber espionage'),
            (2, 'APT28', 'Russia', 'Cyber espionage'),
            (3, 'Lazarus Group', 'North Korea', 'Cybercrime'),
            (4, 'MuddyWater', 'Iran', 'Cyber espionage'),
            (5, 'Wizard Spider', 'Russia', 'Cybercrime'),
            (6, 'Sandworm', 'Russia', 'Cyber warfare');
        
        INSERT OR IGNORE INTO actor_aliases (actor_id, alias) 
        VALUES 
            (1, 'Cozy Bear'),
            (1, 'NOBELIUM'),
            (2, 'Fancy Bear'),
            (3, 'Hidden Cobra'),
            (3, 'APT38'),
            (4, 'APT34'),
            (4, 'OilRig'),
            (5, 'TrickBot operators'),
            (6, 'Voodoo Bear');
        
        INSERT OR IGNORE INTO ttps (id, ttp_code, is_generic, description) 
        VALUES 
            (1, 'T1566', 0, 'Spear-phishing'),
            (2, 'T1059', 1, 'Command and Scripting Interpreter'),
            (3, 'T1071', 1, 'Application Layer Protocol'),
            (4, 'T1041', 0, 'Exfiltration Over C2 Channel'),
            (5, 'T1574.002', 0, 'DLL Side-Loading');
        
        INSERT OR IGNORE INTO ioc_examples (category, value, context, confidence) 
        VALUES 
            ('ip', '185.220.101.45', 'APT29 C2 server', 5),
            ('domain', 'malicious-update.net', 'APT29 C2 domain', 5);
        
        INSERT OR IGNORE INTO false_positives (category, value, context) 
        VALUES 
            ('actor', 'Check Point', 'Cybersecurity vendor'),
            ('actor', 'Microsoft', 'Technology vendor');
    """)
    
    conn.commit()
    conn.close()
    
    return db_path


@pytest.fixture
def mock_knowledge_db(monkeypatch, populated_knowledge_db):
    """
    Override the KNOWLEDGE_DB_PATH to use the temporary populated database.
    
    This fixture should be used in tests that need to import modules
    that reference common.KNOWLEDGE_DB_PATH.
    """
    import common
    import actor_aliases
    
    # Override the path in both modules
    monkeypatch.setattr(common, "KNOWLEDGE_DB_PATH", populated_knowledge_db)
    monkeypatch.setattr(actor_aliases, "DB_PATH", populated_knowledge_db)
    
    return populated_knowledge_db