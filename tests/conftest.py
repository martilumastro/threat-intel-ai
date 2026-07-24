import json
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent


@pytest.fixture
def fixture_texts() -> dict[str, str]:
    return {
        path.stem: path.read_text(encoding="utf-8")
        for path in (TESTS_DIR / "fixtures").glob("test_report_*.txt")
    }


@pytest.fixture
def expected_extractions() -> dict[str, dict]:
    return {
        path.stem.removeprefix("extraction_"): json.loads(path.read_text(encoding="utf-8"))
        for path in (TESTS_DIR / "expected").glob("extraction_*.json")
    }
