import json

import step1_extraction


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return {"response": json.dumps(self.payload)}


def test_extract_ioc_combines_regex_iocs_with_the_model_response(
    monkeypatch, expected_extractions, fixture_texts
):
    expected = expected_extractions["001"]
    expected_with_new_fields = {
        **expected,
        "cve_ids": [],
        "urls": [],
        "suspicious_files": [],
    }
    llm_response = {"actors_mentioned": ["APT29"], "mitre_ttps": ["T1566"]}
    monkeypatch.setattr(
        step1_extraction.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(llm_response),
    )

    assert step1_extraction.extract_ioc(fixture_texts["test_report_001"]) == expected_with_new_fields


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
