import sqlite3

import knowledge_context


def _create_test_database(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE actors (id INTEGER PRIMARY KEY, canonical_name TEXT NOT NULL);
        CREATE TABLE actor_aliases (actor_id INTEGER NOT NULL, alias TEXT NOT NULL);
        CREATE TABLE ioc_examples (category TEXT, value TEXT, context TEXT, confidence INTEGER);
        CREATE TABLE domains (domain TEXT, category TEXT, notes TEXT);
        CREATE TABLE false_positives (category TEXT, value TEXT, context TEXT);
        """
    )
    connection.execute("INSERT INTO actors VALUES (1, 'APT29')")
    connection.execute("INSERT INTO actor_aliases VALUES (1, 'Cozy Bear')")
    connection.execute(
        "INSERT INTO ioc_examples VALUES ('domain', 'malicious.example', 'Known C2', 5)"
    )
    connection.execute(
        "INSERT INTO domains VALUES ('malicious.example', 'c2', 'Known command and control')"
    )
    connection.execute(
        "INSERT INTO false_positives VALUES ('actor', 'Example Security', 'Research vendor')"
    )
    connection.commit()
    connection.close()


def test_database_context_contains_relevant_curated_information(tmp_path, monkeypatch):
    database_path = tmp_path / "knowledge.db"
    _create_test_database(database_path)
    monkeypatch.setattr(knowledge_context, "KNOWLEDGE_DB_PATH", database_path)

    context = knowledge_context.build_extraction_knowledge_context(
        "Cozy Bear used malicious.example. Example Security reported it."
    )

    assert "APT29" in context
    assert "malicious.example" in context
    assert "Example Security" in context


def test_database_false_positives_are_removed(tmp_path, monkeypatch):
    database_path = tmp_path / "knowledge.db"
    _create_test_database(database_path)
    monkeypatch.setattr(knowledge_context, "KNOWLEDGE_DB_PATH", database_path)

    filtered = knowledge_context.filter_curated_false_positives(
        {
            "ip": [],
            "domains": [],
            "hashes": [],
            "emails": [],
            "mitre_ttps": [],
            "actors_mentioned": ["APT29", "Example Security"],
            "cve_ids": [],
            "urls": [],
            "suspicious_files": [],
        }
    )

    assert filtered["actors_mentioned"] == ["APT29"]
