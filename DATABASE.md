# Knowledge Database

`knowledge/threat_intel.db` is a local SQLite knowledge base used to ground
the pipeline with curated threat-intelligence facts. It is intentionally kept
separate from the pipeline output under `data/`: the database contains
operator-curated records, while `data/` contains collected URLs and generated
analysis artifacts.

The ER diagram is maintained in `tests/er_diagram.drawio` and is the visual
reference for the schema described below.

## Privacy and distribution

The populated database, source configuration, alias catalogue, and population
scripts are local/private at the current stage. They are ignored by Git and
are not intended for publication. The public project contains the schema in
`knowledge/init_db.py`, code, tests, and documentation only.

Do not rely on `.gitignore` to protect files already committed: Git continues
to track them until they are explicitly removed from the index and, if needed,
from history before a public push.

## Purpose in the pipeline

The database is active during analysis, not merely a future storage layer.

- **Step 1** uses relevant curated actor aliases, IOC examples, and known
  domains as compact local context for the LLM. It also removes values stored
  as curated false positives from normalized output.
- **Step 2** resolves actor aliases deterministically before considering an
  LLM semantic correlation.
- **Step 3** enriches reports with known actor country, motivation, notes,
  associated campaigns, and TTPs.

Campaign/TTP and domain-pattern relationships are available in the schema for
future deterministic campaign-signature correlation once those relationships
are populated and validated.

## Core intelligence tables

| Table | Purpose |
|---|---|
| `actors` | Canonical actor name plus country, motivation, first-seen date, and notes. |
| `actor_aliases` | Globally unique aliases linked to one canonical actor. |
| `campaigns` | Curated campaign identifiers and date/description metadata. |
| `campaign_actors` | N:M relationship between campaigns and actors. |
| `ttps` | MITRE ATT&CK techniques, including an `is_generic` flag. |
| `campaign_ttps` | N:M relationship between campaigns and TTPs. |
| `domains` | Curated domains and their category, description, and notes. |
| `actor_domains` | Exact domains associated with an actor, with an observation frequency. |
| `actor_ttp_patterns` | Curated recurrent actor-to-TTP association, with frequency and confidence. |
| `actor_domain_patterns` | Curated recurring domain patterns associated with an actor. |

`campaign_ttps` describes a TTP used in one specific campaign;
`actor_ttp_patterns` describes a broader recurring actor pattern. They are
therefore related but not duplicates. Likewise, `actor_domains` stores exact
domains while `actor_domain_patterns` is reserved for broader patterns.

## Curated extraction-support tables

| Table | Purpose |
|---|---|
| `ioc_examples` | Positive examples of indicators worth extracting, with context and confidence. |
| `false_positives` | Values that must not be treated as indicators or actors, such as source domains and security vendors. |
| `extraction_log` | Operational audit trail for reviewed extraction outcomes and possible new indicators. |

The `approved` flags support a review workflow. A record should be treated as
curated only after human verification; seed data should follow the local
operator's review policy.

## Integrity rules

SQLite enforces the following rules:

- canonical actor names, aliases, campaign IDs, TTP codes, and exact domains
  are unique where ambiguity would be harmful;
- foreign keys use `ON DELETE CASCADE` for dependent aliases and associations;
- N:M tables use composite uniqueness to prevent duplicate links;
- identifiers and foreign keys are `NOT NULL` where required;
- lookup indexes support frequent actor-alias, TTP, domain, and review queries.

Every application database connection should be opened through
`common.get_knowledge_db()` or `common.get_connection()` so that SQLite foreign
keys are enabled with `PRAGMA foreign_keys = ON`.

## Initializing a local database

The schema initializer is additive and safe to rerun:

```bash
venv/bin/python knowledge/init_db.py
```

It creates missing tables and indexes but does not delete existing records.
Population scripts and records remain private in the current project policy.
