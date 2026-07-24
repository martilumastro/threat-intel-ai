"""
Benchmark dataset for semantic correlation.

Each case is a pair of already-extracted, already-normalized records
(same shape as Step 1 output) plus the expected outcome, decided by us
in advance. These are NOT meant to be resolved by exact IOC match or by
the actor_aliases catalogue - that's the point: they test the model's
own reasoning on cases where the deterministic layers don't help.

expected_related: True / False, what a careful human analyst would say
difficulty: "easy" | "medium" | "hard" - for reporting, not for scoring
notes: why this case is interesting
"""

BENCHMARK_CASES = [
    {
        "id": "known_alias_not_in_catalogue",
        "difficulty": "medium",
        "expected_related": True,
        "notes": "Same actor (Wizard Spider / TrickBot operators), alias not in our catalogue yet.",
        "doc_a": {
            "source_document": "bench_001_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1486"],
                "actors_mentioned": ["Wizard Spider"],
            },
        },
        "doc_b": {
            "source_document": "bench_001_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1486"],
                "actors_mentioned": ["TrickBot operators"],
            },
        },
    },
    {
        "id": "same_ttp_different_actor",
        "difficulty": "easy",
        "expected_related": False,
        "notes": "Same TTP (very common one) but explicitly different, unrelated actors.",
        "doc_a": {
            "source_document": "bench_002_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1566"],
                "actors_mentioned": ["FIN7"],
            },
        },
        "doc_b": {
            "source_document": "bench_002_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1566"],
                "actors_mentioned": ["APT34"],
            },
        },
    },
    {
        "id": "unnamed_actor_same_campaign_signature",
        "difficulty": "hard",
        "expected_related": True,
        "notes": "No actor named in either doc, but a very specific multi-TTP combination "
                 "matches closely enough to suggest the same campaign.",
        "doc_a": {
            "source_document": "bench_003_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1566.001", "T1204.002", "T1059.001"],
                "actors_mentioned": [],
            },
        },
        "doc_b": {
            "source_document": "bench_003_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1566.001", "T1204.002", "T1059.001"],
                "actors_mentioned": [],
            },
        },
    },
    {
        "id": "unnamed_actor_generic_ttp_only",
        "difficulty": "medium",
        "expected_related": False,
        "notes": "No actor named, only one very generic TTP shared - not enough evidence.",
        "doc_a": {
            "source_document": "bench_004_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1059"],
                "actors_mentioned": [],
            },
        },
        "doc_b": {
            "source_document": "bench_004_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1059"],
                "actors_mentioned": [],
            },
        },
    },
    {
        "id": "same_actor_typo_variant",
        "difficulty": "easy",
        "expected_related": True,
        "notes": "Same actor name with a plausible extraction typo/casing difference.",
        "doc_a": {
            "source_document": "bench_005_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1071"],
                "actors_mentioned": ["Sandworm Team"],
            },
        },
        "doc_b": {
            "source_document": "bench_005_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1071"],
                "actors_mentioned": ["sandworm team"],
            },
        },
    },
    {
        "id": "related_but_different_stage",
        "difficulty": "hard",
        "expected_related": True,
        "notes": "Same actor, but one doc describes initial access and the other describes "
                 "exfiltration - different TTPs, same campaign because the actor is named.",
        "doc_a": {
            "source_document": "bench_006_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1566.002"],
                "actors_mentioned": ["APT41"],
            },
        },
        "doc_b": {
            "source_document": "bench_006_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1041"],
                "actors_mentioned": ["Winnti Group"],
            },
        },
    },
    {
        "id": "coincidental_shared_generic_ttp",
        "difficulty": "medium",
        "expected_related": False,
        "notes": "Two well-known but genuinely unrelated actors, one shared generic TTP.",
        "doc_a": {
            "source_document": "bench_007_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1105"],
                "actors_mentioned": ["Lazarus Group"],
            },
        },
        "doc_b": {
            "source_document": "bench_007_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1105"],
                "actors_mentioned": ["MuddyWater"],
            },
        },
    },
    {
        "id": "vague_actor_description_match",
        "difficulty": "hard",
        "expected_related": True,
        "notes": "Both mention a state-sponsored actor with matching regional/target "
                 "description but no exact name overlap in our catalogue.",
        "doc_a": {
            "source_document": "bench_008_a",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1584.001"],
                "actors_mentioned": ["a Russian state-sponsored group"],
            },
        },
        "doc_b": {
            "source_document": "bench_008_b",
            "data": {
                "ip": [], "domains": [], "hashes": [], "emails": [],
                "mitre_ttps": ["T1584.001"],
                "actors_mentioned": ["Russia-linked threat actor"],
            },
        },
    },
]