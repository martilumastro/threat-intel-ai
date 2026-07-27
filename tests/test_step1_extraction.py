import json

import step1_extraction


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return {"response": json.dumps(self.payload)}


def test_extract_ioc_uses_and_validates_the_model_response(monkeypatch, expected_extractions):
    expected = expected_extractions["001"]
    # Aggiungi i nuovi campi all'expected
    expected_with_new_fields = {
        **expected,
        "cve_ids": [],
        "urls": [],
        "suspicious_files": []
    }
    monkeypatch.setattr(step1_extraction.requests, "post", lambda *args, **kwargs: FakeResponse(expected))
    assert step1_extraction.extract_ioc("untrusted test input") == expected_with_new_fields


def test_save_result_writes_a_normalized_record(tmp_path, monkeypatch):
    monkeypatch.setattr(step1_extraction, "EXTRACTED_DIR", tmp_path)
    path = step1_extraction.save_result(
        "../report 01",
        {"ip": ["185.220.101.45"], "domains": [], "hashes": [], "emails": [], "mitre_ttps": [], "actors_mentioned": []},
    )

    record = json.loads((tmp_path / "report_01.json").read_text(encoding="utf-8"))
    assert path == str(tmp_path / "report_01.json")
    assert record["status"] == "extracted"
    assert record["source_document"] == "report_01"
