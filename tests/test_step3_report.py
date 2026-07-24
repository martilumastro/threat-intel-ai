"""Tests for Step 3 Report Generation."""

import pytest

from src.step3_report import calculate_threat_score, generate_markdown_report


def test_calculate_threat_score_critical():
    data = {
        "exact_matches": [{"shared_values": ["185.220.101.45"]}],
        "known_actor_alias_matches": [{"canonical_actors": ["APT29"]}],
        "semantic_matches": [],
    }
    assert calculate_threat_score(data) == "CRITICAL"


def test_calculate_threat_score_type_error():
    with pytest.raises(TypeError, match="must be a dictionary"):
        calculate_threat_score(["invalid_list"])  # type: ignore


def test_generate_markdown_report_structure():
    data = {
        "correlation_timestamp": "2026-07-24T13:48:57Z",
        "exact_matches": [
            {
                "document_a": "doc1",
                "document_b": "doc2",
                "category": "ip",
                "shared_values": ["185.220.101.45"],
            }
        ],
        "known_actor_alias_matches": [
            {
                "document_a": "doc1",
                "document_b": "doc3",
                "canonical_actors": ["APT29"],
                "actor_names_a": ["APT29"],
                "actor_names_b": ["Cozy Bear"],
            }
        ],
        "semantic_matches": [],
    }
    report = generate_markdown_report(data, "CRITICAL")
    assert "# Threat Intelligence Analysis Report" in report
    assert "APT28" not in report
    assert "APT29" in report
    assert "185.220.101.45" in report
    assert "`CRITICAL`" in report