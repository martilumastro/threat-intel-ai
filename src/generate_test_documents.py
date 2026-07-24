"""
Manual integration-test script for Step 1 + Step 2.

Document 1 and 2: share an identical IOC -> should produce an EXACT match
Document 1 and 3: same actor, different names, no shared IOC ->
                   should produce a SEMANTIC match (if the model is good enough)
Document 2 and 3: no real connection -> should produce no match

Run this script to populate data/extracted/, then run
step2_correlation.py to see the correlation in action.
"""

import requests

from common import PROJECT_DIR
from step1_extraction import extract_ioc, save_result

FIXTURE_DIR = PROJECT_DIR / "tests" / "fixtures"


def load_test_documents() -> dict[str, str]:
    """Load stable test inputs shared with the automated test suite."""
    return {
        path.stem: path.read_text(encoding="utf-8")
        for path in sorted(FIXTURE_DIR.glob("test_report_*.txt"))
    }

if __name__ == "__main__":
    for document_name, text in load_test_documents().items():
        print(f"Processing {document_name}...")
        try:
            data = extract_ioc(text)
        except (requests.RequestException, RuntimeError) as error:
            raise SystemExit(f"Extraction failed for {document_name}: {error}")
        path = save_result(document_name, data)
        print(f"  -> saved to {path}\n")

    print("Done. You can now run step2_correlation.py to see the correlation.")
