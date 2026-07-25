"""
STEP 4 - Pipeline Orchestrator
--------------------------------
Runs the full pipeline end to end: extraction (Step 1) on a folder of
raw text reports, correlation (Step 2), and report generation (Step 3).

This does not add new logic - it only sequences the existing, already
tested Step 1/2/3 functions, with shared error handling and a single
entry point for running the whole pipeline on a batch of reports.

Usage:
    python orchestrator.py --input-dir path/to/reports
    python orchestrator.py --input-dir path/to/reports --skip-existing
"""

import argparse
import sys
from itertools import combinations
from pathlib import Path

import requests

from common import CORRELATED_DIR, DATA_DIR, EXTRACTED_DIR, MODEL, OLLAMA_URL
from step1_extraction import extract_ioc, save_result
from step2_correlation import (
    evaluate_semantic_correlation,
    find_exact_matches,
    find_known_actor_alias_matches,
    is_semantic_candidate,
    load_actor_aliases,
    load_extracted_documents,
    save_correlations,
)
from step3_report import run_step3

FINAL_REPORTS_DIR = DATA_DIR / "final_reports"


def run_extraction_stage(input_dir: Path, skip_existing: bool) -> int:
    """Runs Step 1 on every .txt file in input_dir. Returns count processed."""
    report_paths = sorted(input_dir.glob("*.txt"))
    if not report_paths:
        print(f"No .txt reports found in {input_dir}")
        return 0

    processed = 0
    for report_path in report_paths:
        document_name = report_path.stem
        output_path = EXTRACTED_DIR / f"{document_name}.json"

        if skip_existing and output_path.exists():
            print(f"[extraction] {document_name}: already extracted, skipping")
            continue

        print(f"[extraction] {document_name}: processing...")
        text = report_path.read_text(encoding="utf-8")
        try:
            data = extract_ioc(text)
        except (requests.RequestException, RuntimeError) as error:
            print(f"[extraction] {document_name}: FAILED ({error}) - skipping this document")
            continue

        save_result(document_name, data)
        processed += 1
        print(f"[extraction] {document_name}: done")

    return processed


def run_correlation_stage() -> dict:
    """Runs Step 2 (exact match, known alias, semantic) and saves the result."""
    documents = load_extracted_documents()
    print(f"[correlation] {len(documents)} valid extracted documents loaded")

    if len(documents) < 2:
        print("[correlation] fewer than 2 documents - nothing to correlate")
        exact_matches, known_actor_alias_matches, semantic_matches = [], [], []
    else:
        exact_matches = find_exact_matches(documents)
        print(f"[correlation] {len(exact_matches)} exact matches")

        aliases = load_actor_aliases()
        known_actor_alias_matches = find_known_actor_alias_matches(documents, aliases)
        print(f"[correlation] {len(known_actor_alias_matches)} known actor alias matches")

        deterministic_matches = exact_matches + known_actor_alias_matches
        pairs_with_match = {
            (m["document_a"], m["document_b"]) for m in deterministic_matches
        }

        semantic_matches = []
        for doc_a, doc_b in combinations(documents, 2):
            key = (doc_a["source_document"], doc_b["source_document"])
            if key in pairs_with_match or not is_semantic_candidate(doc_a, doc_b):
                continue
            try:
                evaluation = evaluate_semantic_correlation(doc_a, doc_b)
            except requests.RequestException as error:
                print(f"[correlation] {key[0]} <-> {key[1]}: skipped ({error})")
                continue
            if evaluation.get("related"):
                semantic_matches.append({
                    "document_a": doc_a["source_document"],
                    "document_b": doc_b["source_document"],
                    "match_type": "semantic",
                    **evaluation,
                })
        print(f"[correlation] {len(semantic_matches)} semantic matches")

    path = save_correlations(exact_matches, known_actor_alias_matches, semantic_matches)
    print(f"[correlation] saved to {path}")
    return {
        "exact_matches": exact_matches,
        "known_actor_alias_matches": known_actor_alias_matches,
        "semantic_matches": semantic_matches,
    }


def run_reporting_stage() -> None:
    """Runs Step 3 on the correlation output just produced."""
    run_step3(
        input_file=CORRELATED_DIR / "correlations.json",
        output_dir=FINAL_REPORTS_DIR,
    )


def run_pipeline(input_dir: Path, skip_existing: bool, no_correlation: bool) -> None:
    """Run the full pipeline: extraction, correlation, reporting."""
    
    # Check Ollama availability
    try:
        requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": "test", "stream": False},
            timeout=10
        )
    except requests.RequestException:
        print("\n" + "!" * 60)
        print("WARNING: Ollama is not responding!")
        print(f"Check that Ollama is running at: {OLLAMA_URL}")
        print("!" * 60 + "\n")
    
    print(f"=== Step 1: extraction (input: {input_dir}) ===")
    processed = run_extraction_stage(input_dir, skip_existing)
    print(f"=== Step 1 complete: {processed} new document(s) extracted ===\n")

    if no_correlation:
        print("=== Skipping Step 2 (correlation) and Step 3 (reporting) ===")
        print(f"Extraction only. Results in: {EXTRACTED_DIR}")
        return

    print("=== Step 2: correlation ===")
    run_correlation_stage()
    print("=== Step 2 complete ===\n")

    print("=== Step 3: reporting ===")
    run_reporting_stage()
    print("=== Step 3 complete ===\n")

    print(f"Pipeline finished. Final reports in: {FINAL_REPORTS_DIR}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full threat intel pipeline.")
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Folder containing raw .txt reports to extract IOCs from.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip extraction for documents that already have a saved result.",
    )
    parser.add_argument(
        "--no-correlation",
        action="store_true",
        help="Skip correlation and reporting steps (only run extraction).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not args.input_dir.is_dir():
        print(f"Input directory not found: {args.input_dir}")
        sys.exit(1)

    run_pipeline(args.input_dir, args.skip_existing, args.no_correlation)