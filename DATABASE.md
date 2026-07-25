# Knowledge Database

This document describes the design of `knowledge/threat_intel.db`, the local
SQLite database that grounds the correlation step with curated,
human-verified facts (known actor aliases, and — from Phase 2 onward —
known campaigns and their characteristic TTPs).

An entity-relationship diagram is provided in `er_diagram.drawio`
(open with [draw.io](https://app.diagrams.net) or the VS Code Draw.io
Integration extension).

## 1. Conceptual model (ER)

**Entities and attributes:**

- **Actor**: `canonical_name` (identifying attribute), `country`,
  `motivation`, `first_seen`, `notes`
- **Alias**: `alias` — modeled conceptually as a **multivalued attribute**
  of Actor (an actor can have zero or more known aliases)
- **Campaign**: `campaign_id` (identifying attribute), `first_seen`,
  `last_seen`, `description`
- **TTP**: `ttp_code` (identifying attribute), `is_generic`, `description`

**Relationships and cardinalities:**

| Relationship | Cardinality | Meaning |
|---|---|---|
| Actor – has – Alias | 1:N | an actor has 0..N aliases; an alias belongs to exactly 1 actor |
| Campaign – involves – Actor | N:M | a campaign involves 1..N actors; an actor takes part in 0..N campaigns |
| Campaign – uses – TTP | N:M | a campaign is characterized by 1..N TTPs; a TTP appears in 0..N campaigns |

This database intentionally holds only curated, human-reviewed knowledge.
It does not store processed documents, extraction output, or correlation
results — those remain as JSON under `data/extracted/` and
`data/correlated/`, which are regenerable and gitignored. Keeping the two
concerns in separate files (rather than separate tables in one database)
matters because SQLite has no per-table access control: anyone with read
access to a `.db` file can read every table in it. A single shared file
would make it easy to accidentally commit sensitive processing output
alongside curated knowledge; two clearly separated files make the
public/private boundary structural rather than a matter of discipline.

## 2. From conceptual to logical model

Two decisions were made when moving from the ER diagram to actual tables:

**Alias became a table, not a JSON column or a repeated field on Actor.**
Conceptually it's a multivalued attribute, but 1NF (first normal form)
requires atomic column values — a single `aliases` column holding
`"Cozy Bear, NOBELIUM, The Dukes"` would not be queryable or constrainable
(e.g. we could not enforce alias uniqueness across actors). It was
therefore promoted to its own table, `actor_aliases`, linked back to
`actors` via a foreign key — the standard technique for representing a
1:N relationship in a relational schema. This also makes it a **weak
entity** in ER terms: an alias row has no independent identity without
its owning actor.

**Both N:M relationships became junction (associative) tables.**
`campaign_actors` and `campaign_ttps` exist purely to represent the two
N:M relationships; the relational model has no native way to store a
many-to-many relationship on the entities themselves. Each junction
table's primary key is the *combination* of the two foreign keys, which
also acts as a constraint: it is structurally impossible to insert the
same (campaign, actor) pair twice.

The full mapping:

| Conceptual entity/relationship | Logical table |
|---|---|
| Actor | `actors` |
| Alias (multivalued attribute) | `actor_aliases` |
| Campaign | `campaigns` |
| TTP | `ttps` |
| Campaign–Actor (N:M) | `campaign_actors` (junction) |
| Campaign–TTP (N:M) | `campaign_ttps` (junction) |

## 3. Constraints enforced at the database level

These are enforced by SQLite itself — not by application code in
`src/`. The point is that invalid data cannot reach the database
regardless of which script writes to it.

- **Primary keys**: every table has a single-column `INTEGER PRIMARY
  KEY` (actors, campaigns, ttps, actor_aliases) or a **composite primary
  key** on the two foreign keys (`campaign_actors`, `campaign_ttps`) —
  this composite PK is what prevents duplicate associations, described
  above.
- **Uniqueness (`UNIQUE`)**: `actors.canonical_name`,
  `actor_aliases.alias`, `campaigns.campaign_id`, `ttps.ttp_code`.
  Notably, `alias` is unique *globally*, not just per-actor — this is a
  deliberate design choice: the same alias string should never be
  claimed by two different canonical actors, since that would make
  `canonical_actor_name()` resolution ambiguous.
- **Foreign keys with `ON DELETE CASCADE`**: `actor_aliases.actor_id`,
  `campaign_actors.*`, `campaign_ttps.*`. Deleting an actor
  automatically removes its aliases and its campaign associations;
  deleting a campaign removes its actor/TTP associations. This was
  chosen over `ON DELETE RESTRICT` because aliases and associations have
  no meaning independent of their parent row — an orphaned alias
  pointing at a deleted actor is not a state we ever want to allow to
  exist, even temporarily.
- **`NOT NULL`**: applied to every foreign key and to identifying
  attributes (`canonical_name`, `alias`, `campaign_id`, `ttp_code`),
  preventing incomplete rows.
- **Default values**: `ttps.is_generic` defaults to `0` (false) —
  a TTP must be explicitly marked generic, rather than accidentally
  excluded from correlation evidence by omission.
- **Indexes**: `idx_actor_aliases_alias` and `idx_ttps_code` are
  non-unique indexes added purely for lookup performance (the alias
  and TTP-code lookups happen on every correlation run); they are not
  constraints, since uniqueness is already guaranteed by the `UNIQUE`
  clauses above.

### On triggers: intentionally none, for now

The schema currently has **no triggers**. Every invariant that matters
today (referential integrity, uniqueness, cascade deletes) is already
covered by declarative constraints (`FOREIGN KEY`, `UNIQUE`, `ON DELETE
CASCADE`), which SQLite enforces natively and which are easier to reason
about than procedural trigger logic. A trigger would only become
necessary for a rule that declarative constraints cannot express — for
example, automatically stamping `campaigns.last_seen` whenever a new
`campaign_ttps` row is inserted. That is a plausible Phase 2 addition,
not implemented yet, and will be documented here if/when it is added.

### Enabling foreign keys in SQLite

SQLite does not enforce foreign key constraints by default; each
connection must explicitly request it. To avoid relying on every script
remembering to do this, all database access goes through
`common.get_connection()`, which opens the connection and immediately
runs `PRAGMA foreign_keys = ON`. No part of the codebase should call
`sqlite3.connect()` on `threat_intel.db` directly.

## 4. Versioning

`knowledge/threat_intel.db` is versioned in Git, on the same basis as
`knowledge/actor_aliases.json` was before it: it holds curated,
human-reviewed knowledge (actors, aliases, and eventually campaigns/TTP
fingerprints), not pipeline output. `data/extracted/` and
`data/correlated/` remain gitignored, since they hold regenerable,
potentially sensitive analysis output.

`*.db-journal`, `*.db-wal`, and `*.db-shm` (SQLite's temporary
rollback/write-ahead-log files) are gitignored — only the main `.db`
file is committed.