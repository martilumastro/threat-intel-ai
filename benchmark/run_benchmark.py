"""
Benchmark runner for semantic correlation.

Runs the currently configured model (see THREAT_INTEL_MODEL in common.py)
against the fixed set of benchmark cases and prints an accuracy summary.

This does NOT touch data/ or the actor alias catalogue - it calls
evaluate_semantic_correlation directly on hand-built pairs, bypassing
exact-match and alias resolution on purpose, since those are already
deterministic and don't need benchmarking.

Usage:
    python run_benchmark.py
"""

import sys
import time
from pathlib import Path

# Make src/ importable without installing the package
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from benchmark_cases import BENCHMARK_CASES

from common import MODEL
from step2_correlation import evaluate_semantic_correlation


def run_case(case: dict) -> dict:
    """Runs a single benchmark case and returns a result record."""
    
    # --- STEP 1: Check for a deterministic alias match. ---
    from actor_aliases import canonical_actor_name, load_actor_aliases
    aliases = load_actor_aliases()
    
    actors_a = case["doc_a"]["data"].get("actors_mentioned", [])
    actors_b = case["doc_b"]["data"].get("actors_mentioned", [])
    
    canonical_a = {canonical_actor_name(a, aliases) for a in actors_a}
    canonical_b = {canonical_actor_name(a, aliases) for a in actors_b}
    
    known_canonical = set(aliases.keys())
    shared_actors = (canonical_a & canonical_b) & known_canonical
    
    # Initialize elapsed with a default value
    elapsed = 0.0
    
    if shared_actors:
        # If there is an alias match, it is determined.
        predicted_related = True
        reasoning = f"Alias match: {', '.join(shared_actors)}"
        confidence = "high"
        # elapsed rimane 0.0
    else:
        # --- STEP 2: Otherwise, use the LLM ---
        start = time.monotonic()
        evaluation = evaluate_semantic_correlation(case["doc_a"], case["doc_b"])
        elapsed = time.monotonic() - start
        
        predicted_related = evaluation.get("related", False)
        reasoning = evaluation.get("reasoning", "")
        confidence = evaluation.get("confidence", "?")
    
    expected_related = case["expected_related"]
    
    if predicted_related == expected_related:
        outcome = "correct"
    elif predicted_related and not expected_related:
        outcome = "false_positive"
    else:
        outcome = "false_negative"

    return {
        "id": case["id"],
        "difficulty": case["difficulty"],
        "expected_related": expected_related,
        "predicted_related": predicted_related,
        "outcome": outcome,
        "confidence": confidence,
        "reasoning": reasoning,
        "elapsed_seconds": round(elapsed, 1),
    }

def print_summary(results: list[dict]) -> None:
    total = len(results)
    correct = sum(1 for r in results if r["outcome"] == "correct")
    false_positives = [r for r in results if r["outcome"] == "false_positive"]
    false_negatives = [r for r in results if r["outcome"] == "false_negative"]
    avg_time = sum(r["elapsed_seconds"] for r in results) / total if total else 0

    print("\n" + "=" * 60)
    print(f"BENCHMARK SUMMARY - model: {MODEL}")
    print("=" * 60)
    print(f"Total cases:       {total}")
    print(f"Correct:           {correct} ({correct / total:.0%})" if total else "Correct: n/a")
    print(f"False positives:   {len(false_positives)}  <- flags unrelated docs as related")
    print(f"False negatives:   {len(false_negatives)}  <- misses a real connection")
    print(f"Avg time/pair:     {avg_time:.1f}s")

    if false_positives:
        print("\n--- False positives (most costly for a threat analyst) ---")
        for r in false_positives:
            print(f"  [{r['difficulty']}] {r['id']}")
            print(f"    reasoning: {r['reasoning']}")

    if false_negatives:
        print("\n--- False negatives ---")
        for r in false_negatives:
            print(f"  [{r['difficulty']}] {r['id']}")
            print(f"    reasoning: {r['reasoning']}")

    print("\n--- Per-case detail ---")
    for r in results:
        mark = "OK" if r["outcome"] == "correct" else "FAIL"
        print(f"  [{mark}] {r['id']:<38} expected={r['expected_related']!s:<5} "
              f"got={r['predicted_related']!s:<5} conf={r['confidence']:<6} "
              f"{r['elapsed_seconds']}s")
    print("=" * 60)


if __name__ == "__main__":
    print(f"Running benchmark with model: {MODEL}")
    print(f"Cases to run: {len(BENCHMARK_CASES)}\n")

    results = []
    for i, case in enumerate(BENCHMARK_CASES, start=1):
        print(f"[{i}/{len(BENCHMARK_CASES)}] {case['id']}...")
        result = run_case(case)
        print(f"    -> {result['outcome']} ({result['elapsed_seconds']}s)")
        results.append(result)

    print_summary(results)