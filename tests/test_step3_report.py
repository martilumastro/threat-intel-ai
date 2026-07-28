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


def test_calculate_threat_score_high_via_alias():
    data = {
        "exact_matches": [],
        "known_actor_alias_matches": [{"canonical_actors": ["APT29"]}],
        "semantic_matches": [],
    }
    assert calculate_threat_score(data) == "HIGH"


def test_calculate_threat_score_high_via_multiple_exact():
    data = {
        "exact_matches": [{"shared_values": ["1.1.1.1"]}, {"shared_values": ["2.2.2.2"]}],
        "known_actor_alias_matches": [],
        "semantic_matches": [],
    }
    assert calculate_threat_score(data) == "HIGH"


def test_calculate_threat_score_medium_single_exact_match():
    data = {
        "exact_matches": [{"shared_values": ["1.1.1.1"]}],
        "known_actor_alias_matches": [],
        "semantic_matches": [],
    }
    assert calculate_threat_score(data) == "MEDIUM"


def test_calculate_threat_score_medium_semantic_only_never_escalates():
    """Semantic-only correlations are capped at MEDIUM regardless of
    volume or confidence - see the design note in calculate_threat_score."""
    data = {
        "exact_matches": [],
        "known_actor_alias_matches": [],
        "semantic_matches": [
            {"confidence": "high", "related": True},
            {"confidence": "high", "related": True},
            {"confidence": "high", "related": True},
        ],
    }
    assert calculate_threat_score(data) == "MEDIUM"


def test_calculate_threat_score_low_no_matches():
    data = {"exact_matches": [], "known_actor_alias_matches": [], "semantic_matches": []}
    assert calculate_threat_score(data) == "LOW"


def test_calculate_threat_score_type_error():
    with pytest.raises(TypeError, match="must be a dictionary"):
        calculate_threat_score(["invalid_list"])  # type: ignore


def test_generate_markdown_report_structure(mock_knowledge_db):
    """Test that the markdown report is generated correctly."""
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


def test_generate_markdown_report_semantic_section_shows_documents():
    """The semantic section must show which documents are linked, same
    as the exact-match and alias sections - this was missing before."""
    data = {
        "correlation_timestamp": "2026-07-24T13:48:57Z",
        "exact_matches": [],
        "known_actor_alias_matches": [],
        "semantic_matches": [
            {
                "document_a": "doc4",
                "document_b": "doc5",
                "confidence": "high",
                "reasoning": "Both describe a distinctive multi-TTP pattern.",
                "related": True,
            }
        ],
    }
    report = generate_markdown_report(data, "MEDIUM")
    assert "`doc4`" in report
    assert "`doc5`" in report
    assert "Both describe a distinctive multi-TTP pattern." in report


def test_generate_markdown_report_no_correlations():
    data = {
        "correlation_timestamp": "2026-07-24T13:48:57Z",
        "exact_matches": [],
        "known_actor_alias_matches": [],
        "semantic_matches": [],
    }
    report = generate_markdown_report(data, "LOW")
    assert "No correlations detected" in report