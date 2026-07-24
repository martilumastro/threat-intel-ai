"""
STEP 2 - Correlation Module
------------------------------
Reads all JSON files produced by Step 1 (status: "extracted"),
looks for exact matches between IOCs (pure Python, no AI),
and only when needed asks an AI model whether different documents
seem to describe the same campaign/actor.

The result is saved with status "correlated", ready for Step 3
(reporting), to be written later.
"""

import json
from datetime import UTC, datetime
from itertools import combinations

import requests

from actor_aliases import canonical_actor_name, load_actor_aliases
from common import (
    CORRELATED_DIR,
    EXTRACTED_DIR,
    GENERIC_TTPS,
    MODEL,
    OLLAMA_URL,
    REQUEST_TIMEOUT,
    atomic_write_json,
    normalize_extraction,
)

CORRELATION_PROMPT = """You are a threat intelligence analyst. Compare the following two document summaries.

IMPORTANT: The following known actor aliases are already resolved by our system and should be considered as the SAME actor:
{known_aliases_hint}

DOCUMENT 1 ({name1}):
<document>
IOCs: {ioc1}
TTPs: {ttp1}
Actors: {actors1}
</document>

DOCUMENT 2 ({name2}):
<document>
IOCs: {ioc2}
TTPs: {ttp2}
Actors: {actors2}
</document>

RULES:
1. A single generic TTP (like T1059, T1071, T1105) shared between two documents is NOT sufficient evidence of a relationship.
2. Two different names that are in the known aliases list above should be treated as the SAME actor.
3. If two documents mention different TTPs but the same actor (or aliases), they ARE related.
4. **A combination of 2+ specific TTPs (sub-techniques like T1566.001, not just top-level) shared between documents IS strong evidence of a relationship, even without named actors.**
5. If two documents have no overlapping IOCs, no shared non-generic TTPs, and no shared actors, they are NOT related.

Respond ONLY with a JSON object:
{{"related": true/false, "confidence": "low/medium/high", "reasoning": "brief explanation"}}
"""

def load_extracted_documents() -> list[dict]:
    """Reads all JSON files with status 'extracted' from the input folder."""
    documents = []
    for path in EXTRACTED_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as file_handle:
                record = json.load(file_handle)
            if record.get("status") == "extracted" and isinstance(record.get("source_document"), str):
                record["data"] = normalize_extraction(record.get("data"))
                documents.append(record)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(f"Skipping invalid extraction file {path.name}: {error}")
    return documents


def find_exact_matches(documents: list[dict]) -> list[dict]:
    """Compares IOCs across every pair of documents: string matching, no AI."""
    matches_found = []

    for doc_a, doc_b in combinations(documents, 2):
        ioc_a = doc_a["data"]
        ioc_b = doc_b["data"]

        # Compare each IOC category (ip, domains, hashes, emails)
        for category in ["ip", "domains", "hashes", "emails"]:
            values_a = set(ioc_a.get(category, []))
            values_b = set(ioc_b.get(category, []))
            intersection = values_a & values_b

            if intersection:
                matches_found.append({
                    "document_a": doc_a["source_document"],
                    "document_b": doc_b["source_document"],
                    "match_type": "exact",
                    "category": category,
                    "shared_values": list(intersection),
                })

    return matches_found

def find_known_actor_alias_matches(
    documents: list[dict], aliases: dict[str, list[str]]
) -> list[dict]:
    """Find document pairs that mention different known aliases of one actor."""
    matches_found = []
    known_canonical_names = set(aliases)

    for doc_a, doc_b in combinations(documents, 2):
        actors_a = doc_a["data"].get("actors_mentioned", [])
        actors_b = doc_b["data"].get("actors_mentioned", [])

        canonical_a = {
            canonical_actor_name(actor, aliases)
            for actor in actors_a
        }
        canonical_b = {
            canonical_actor_name(actor, aliases)
            for actor in actors_b
        }

        shared_actors = sorted(
            (canonical_a & canonical_b) & known_canonical_names
        )

        if not shared_actors:
            continue

        actor_names_a = [
            actor
            for actor in actors_a
            if canonical_actor_name(actor, aliases) in shared_actors
        ]
        actor_names_b = [
            actor
            for actor in actors_b
            if canonical_actor_name(actor, aliases) in shared_actors
        ]

        matches_found.append(
            {
                "document_a": doc_a["source_document"],
                "document_b": doc_b["source_document"],
                "match_type": "known_actor_alias",
                "canonical_actors": shared_actors,
                "actor_names_a": actor_names_a,
                "actor_names_b": actor_names_b,
            }
        )

    return matches_found

def evaluate_semantic_correlation(doc_a: dict, doc_b: dict) -> dict:
    """Asks the AI model whether two documents seem related, without identical IOCs."""
    data_a, data_b = doc_a["data"], doc_b["data"]
    
    # Prepares the list of known aliases (limited to avoid cluttering the prompt)
    from actor_aliases import load_actor_aliases
    aliases = load_actor_aliases()
    
    # Only first 15 to avoid overloading the prompt
    aliases_list = list(aliases.items())[:15]
    known_aliases_hint = "\n".join([
        f"- {canonical}: {', '.join(aliases[:5])}{'...' if len(aliases) > 5 else ''}"
        for canonical, aliases in aliases_list
    ])

    prompt = CORRELATION_PROMPT.format(
        known_aliases_hint=known_aliases_hint,
        name1=doc_a["source_document"],
        ioc1=json.dumps(data_a, ensure_ascii=False),
        ttp1=json.dumps(data_a.get("mitre_ttps", []), ensure_ascii=False),
        actors1=json.dumps(data_a.get("actors_mentioned", []), ensure_ascii=False),
        name2=doc_b["source_document"],
        ioc2=json.dumps(data_b, ensure_ascii=False),
        ttp2=json.dumps(data_b.get("mitre_ttps", []), ensure_ascii=False),
        actors2=json.dumps(data_b.get("actors_mentioned", []), ensure_ascii=False),
    )

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "think": False,
            "options": {"temperature": 0},
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    try:
        result = json.loads(response.json()["response"])
        if not isinstance(result, dict) or not isinstance(result.get("related"), bool):
            raise TypeError("missing boolean 'related'")
        if result.get("confidence") not in {"low", "medium", "high"}:
            raise TypeError("invalid confidence")
        if not isinstance(result.get("reasoning"), str):
            raise TypeError("missing reasoning")
        return result
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"    RAW RESPONSE ON FAILURE: {response.json()['response']!r}")
        return {"related": False, "confidence": "low", "reasoning": f"invalid model response: {error}"}

def is_semantic_candidate(doc_a: dict, doc_b: dict) -> bool:
    """Avoid LLM calls for pairs with no structured evidence to compare."""
    data_a, data_b = doc_a["data"], doc_b["data"]
    
    # Filter generic TTPs
    ttps_a = set(data_a["mitre_ttps"]) - GENERIC_TTPS
    ttps_b = set(data_b["mitre_ttps"]) - GENERIC_TTPS
    
    # Consider only specific TTPs (sub-techniques) for correlation.
    specific_ttps_a = {t for t in ttps_a if "." in t}
    specific_ttps_b = {t for t in ttps_b if "." in t}
    
    return bool(
        (ttps_a & ttps_b)  # Shared TTPs (non-generic)
        or specific_ttps_a & specific_ttps_b  # Shared sub-techniques
        or (data_a["actors_mentioned"] and data_b["actors_mentioned"])
    )

def save_correlations(
    exact_matches: list[dict],
    known_actor_alias_matches: list[dict],
    semantic_matches: list[dict],
) -> str:
    """Saves all correlation results into a single JSON file."""
    record = {
        "correlation_timestamp": datetime.now(UTC).isoformat(),
        "status": "correlated",
        "exact_matches": exact_matches,
        "known_actor_alias_matches": known_actor_alias_matches,
        "semantic_matches": semantic_matches,
    }

    file_path = CORRELATED_DIR / "correlations.json"
    atomic_write_json(file_path, record)
    return str(file_path)


if __name__ == "__main__":
    print("Loading documents extracted in Step 1...")
    documents = load_extracted_documents()
    print(f"Found {len(documents)} documents.")

    if len(documents) < 2:
        print("Need at least 2 documents to run correlation. Run Step 1 on more reports first.")
    else:
        print("\nLooking for exact matches (no AI)...")
        exact_matches = find_exact_matches(documents)
        print(f"Found {len(exact_matches)} exact matches.")

        print("\nLooking for known actor aliases (no AI)...")
        aliases = load_actor_aliases()
        known_actor_alias_matches = find_known_actor_alias_matches(documents, aliases)
        print(f"Found {len(known_actor_alias_matches)} known actor alias matches.")

        # Semantic correlation only on pairs without deterministic evidence.
        deterministic_matches = exact_matches + known_actor_alias_matches
        pairs_with_match = {
            (match["document_a"], match["document_b"])
            for match in deterministic_matches
        }
        semantic_matches = []

        print("\nEvaluating semantic correlation on remaining pairs...")
        for doc_a, doc_b in combinations(documents, 2):
            key = (doc_a["source_document"], doc_b["source_document"])
            if key not in pairs_with_match and is_semantic_candidate(doc_a, doc_b):
                try:
                    evaluation = evaluate_semantic_correlation(doc_a, doc_b)
                except requests.RequestException as error:
                    print(f"  {doc_a['source_document']} <-> {doc_b['source_document']}: skipped ({error})")
                    continue
                print(f"  {doc_a['source_document']} <-> {doc_b['source_document']}: {evaluation}")
                if evaluation.get("related"):
                    semantic_matches.append({
                        "document_a": doc_a["source_document"],
                        "document_b": doc_b["source_document"],
                        "match_type": "semantic",
                        **evaluation,
                    })

        print(f"Found {len(semantic_matches)} semantic matches.")

        path = save_correlations(
            exact_matches,
            known_actor_alias_matches,
            semantic_matches,
        )
        print(f"\nSaved to: {path}")