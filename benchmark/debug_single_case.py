"""Temporary debug script - runs a single benchmark case by id."""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from step2_correlation import evaluate_semantic_correlation

from benchmark_cases import BENCHMARK_CASES

CASE_ID = "same_actor_typo_variant"

case = next(c for c in BENCHMARK_CASES if c["id"] == CASE_ID)

print(f"Running case: {case['id']}")
result = evaluate_semantic_correlation(case["doc_a"], case["doc_b"])
print(f"\nResult: {result}")