import pytest

from common import normalize_extraction, safe_document_name


def test_normalize_extraction_canonicalizes_and_deduplicates():
    data = {
        "ip": [" 185.220.101.45 ", "invalid-ip", "185.220.101.45"],
        "domains": ["MALICIOUS-UPDATE[.]NET", "invalid domain"],
        "hashes": ["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"],
        "emails": ["Analyst[at]Example[.]ORG"],
        "mitre_ttps": ["t1566", "T000"],
        "actors_mentioned": ["  Cozy   Bear ", "Cozy Bear"],
    }

    assert normalize_extraction(data) == {
        "ip": ["185.220.101.45"],
        "domains": ["malicious-update.net"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "emails": ["analyst@example.org"],
        "mitre_ttps": ["T1566"],
        "actors_mentioned": ["Cozy Bear"],
    }


def test_normalize_extraction_rejects_a_wrong_schema():
    with pytest.raises(TypeError, match="list of strings"):
        normalize_extraction({"ip": "185.220.101.45"})


def test_safe_document_name_cannot_be_a_path():
    assert safe_document_name("../report 01.json") == "report_01.json"
