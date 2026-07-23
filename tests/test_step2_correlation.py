import json

import step2_correlation


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
