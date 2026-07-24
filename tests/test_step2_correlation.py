import json
import step2_correlation

from actor_aliases import load_actor_aliases

def _document(name, data):
    return {"source_document": name, "status": "extracted", "data": data}


def test_exact_match_uses_normalized_iocs(expected_extractions):
    documents = [
        _document("report_001", expected_extractions["001"]),
        _document("report_002", expected_extractions["002"]),
    ]

    matches = step2_correlation.find_exact_matches(documents)
    assert {match["category"] for match in matches} == {"ip"}
    assert matches[0]["shared_values"] == ["185.220.101.45"]


def test_semantic_candidates_require_structured_evidence(expected_extractions):
    first = _document("report_001", expected_extractions["001"])
    third = _document("report_003", expected_extractions["003"])
    unrelated = _document("unrelated", {key: [] for key in expected_extractions["001"]})

    assert step2_correlation.is_semantic_candidate(first, third)
    assert not step2_correlation.is_semantic_candidate(first, unrelated)


def test_load_skips_corrupt_records(tmp_path, monkeypatch, expected_extractions):
    monkeypatch.setattr(step2_correlation, "EXTRACTED_DIR", tmp_path)
    (tmp_path / "valid.json").write_text(
        json.dumps(_document("report_001", expected_extractions["001"])), encoding="utf-8"
    )
    (tmp_path / "broken.json").write_text("not json", encoding="utf-8")

    documents = step2_correlation.load_extracted_documents()
    assert [document["source_document"] for document in documents] == ["report_001"]


def test_known_actor_alias_match_is_deterministic(expected_extractions):
    documents = [
        _document("report_001", expected_extractions["001"]),
        _document("report_003", expected_extractions["003"]),
    ]

    matches = step2_correlation.find_known_actor_alias_matches(
        documents, load_actor_aliases()
    )

    assert matches == [
        {
            "document_a": "report_001",
            "document_b": "report_003",
            "match_type": "known_actor_alias",
            "canonical_actors": ["APT29"],
            "actor_names_a": ["APT29"],
            "actor_names_b": ["Cozy Bear"],
        }
    ]


def test_save_correlations_keeps_evidence_types_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(step2_correlation, "CORRELATED_DIR", tmp_path)
    known_alias_matches = [
        {
            "document_a": "report_001",
            "document_b": "report_003",
            "match_type": "known_actor_alias",
            "canonical_actors": ["APT29"],
            "actor_names_a": ["APT29"],
            "actor_names_b": ["Cozy Bear"],
        }
    ]

    path = step2_correlation.save_correlations(
        exact_matches=[],
        known_actor_alias_matches=known_alias_matches,
        semantic_matches=[],
    )
    record = json.loads((tmp_path / "correlations.json").read_text(encoding="utf-8"))

    assert path == str(tmp_path / "correlations.json")
    assert record["exact_matches"] == []
    assert record["known_actor_alias_matches"] == known_alias_matches
    assert record["semantic_matches"] == []
