# Collection Module (Step 0)

## Overview

Step 0 collects raw threat intelligence reports from public RSS feeds and
saves them as `.txt` files, ready for the rest of the pipeline. It handles
deduplication against previously collected articles, respects a
configurable maximum document size to avoid overloading local hardware,
and stores collected articles in a structured folder.

## Collection sources

### Narrative feeds (LLM-based extraction)

These feeds provide prose-style threat reports. The pipeline processes
them with the local LLM (Step 1) to extract IOCs, TTPs, and actors.

| Source | URL | Type |
|---|---|---|
| Unit 42 | `https://unit42.paloaltonetworks.com/feed/` | RSS |
| Securelist | `https://securelist.com/feed/` | RSS |
| SANS ISC | `https://isc.sans.edu/rssfeed.xml` | RSS |
| CrowdStrike Blog | `https://www.crowdstrike.com/en-us/blog/feed` | RSS |
| Krebs on Security | `https://krebsonsecurity.com/feed/` | RSS |
| Check Point Research | `https://research.checkpoint.com/feed/` | RSS |
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` | RSS |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` | RSS |
| Recorded Future | `https://www.recordedfuture.com/blog/feed` | RSS |
| Google Security Blog | `https://feeds.feedburner.com/GoogleSecurityBlog` | RSS |
| Microsoft Security Blog | `https://www.microsoft.com/en-us/security/blog/feed/` | RSS |

### Structured feeds (planned, not yet implemented)

These feeds provide machine-readable IOCs (IP lists, CVE catalogs, malware
hashes) and do not require LLM extraction. They will be processed through
a dedicated ingestion path that bypasses Step 1 entirely, once
implemented.

| Source | URL | Kind |
|---|---|---|
| Blocklist.de | `https://lists.blocklist.de/lists/all.txt` | IP list |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CVE catalog |
| Abuse.ch URLhaus | `https://urlhaus.abuse.ch/downloads/csv_recent/` | IOC CSV |
| Abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | IP JSON |
| Abuse.ch MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | Malware hash API |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | OTX pulses (requires a free API key — deferred) |
| HIBP breach metadata | `https://haveibeenpwned.com/api/v3/latestbreach` | Breach metadata (public endpoint only, no credential search) |
| MITRE ATT&CK STIX | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` | STIX bundle — candidate source for populating `campaigns`/`ttps` |

## Expected pipeline output

Each collected article, once processed by Step 1, produces a JSON
extraction with the following structure:

```json
{
  "ip": ["185.220.101.45"],
  "domains": ["malicious-update.net"],
  "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  "emails": ["attacker@mail.ru"],
  "mitre_ttps": ["T1566", "T1059.001"],
  "actors_mentioned": ["APT29", "Wizard Spider"]
}
```

> **Note:** an earlier draft of this document also listed `cve_ids`,
> `urls`, and `suspicious_files` as output fields. These are not part of
> the current `normalize_extraction()` schema in `common.py` — confirm
> whether they were actually added before treating them as part of the
> real output.

## Threat scoring rules

| Score | Condition |
|---|---|
| CRITICAL | At least 1 actor alias match **and** at least 1 exact IOC match |
| HIGH | At least 1 actor alias match **or** 2+ exact IOC matches |
| MEDIUM | Any correlation at all (exact, alias, or semantic) |
| LOW | No correlations detected |

Semantic matches alone never raise the score above MEDIUM — this is a
deliberate design choice (see `step3_report.py`), not a limitation:
semantic results are an analyst aid, not an automatic attribution
decision.

## Known limitations and current mitigations

| Issue | Description | Current mitigation | Possible future improvement |
|---|---|---|---|
| Document chunking | Splitting long documents for LLM processing | Disabled — caused instability and malformed JSON responses on this hardware | Re-evaluate with more capable hardware or a different backend |
| Document size limit | Very long documents (>60k characters) can cause timeouts or malformed JSON | Configurable limit via `THREAT_INTEL_MAX_DOCUMENT_CHARS`; oversized documents are skipped | Make the limit frontend-configurable |
| Non-actor false positives | The LLM sometimes lists cybersecurity vendors cited as sources (e.g. "according to Company X") as threat actors | Filtered via a `NON_ACTOR_KEYWORDS` list in `common.py` | Allow user-contributed additions to the list |
| Generic TTPs | A single generic TTP (e.g. `T1059`) alone was triggering false correlations | Filtered via the existing `GENERIC_TTPS` set, treated as insufficient standalone evidence | Contextual analysis instead of a static list |
| Malformed JSON | The model occasionally returns invalid JSON (e.g. truncated strings) | Best-effort regex-based recovery attempt on the raw response | Switch to a more reliable model, or use streaming output |

## Configuration variables

| Variable | Default | Description |
|---|---|---|
| `THREAT_INTEL_MAX_DOCUMENT_CHARS` | `50000` | Maximum document size (characters) before it is skipped |
| `THREAT_INTEL_REQUEST_TIMEOUT` | `3600` | HTTP timeout for Ollama requests, in seconds |
| `THREAT_INTEL_MODEL` | `qwen3.5:9b` | LLM model used for extraction and correlation |
| `THREAT_INTEL_OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama endpoint |

## Running the pipeline

```bash
# Process a single article
python src/step4_orchestrator.py --input-dir data/raw_reports_sample

# Process all collected articles
python src/step4_orchestrator.py --input-dir data/raw_reports

# Skip documents that were already extracted in a previous run
python src/step4_orchestrator.py --input-dir data/raw_reports --skip-existing

# Run extraction only, skipping correlation and reporting
python src/step4_orchestrator.py --input-dir data/raw_reports --no-correlation
```

## Recommendations

**For better extraction results:**
- Prefer specific, technical articles — general news or policy articles tend to yield fewer usable IOCs
- Keep the document size limit reasonable (50,000 characters is a safe default for CPU-only hardware)
- Monitor extraction logs for `skipped` or `FAILED` entries

**For production-style use:**
- Run Step 0 periodically (e.g. daily) to collect new articles incrementally
- Adjust `MAX_DOCUMENT_CHARS` upward only if the underlying hardware can support it
- Extend `NON_ACTOR_KEYWORDS` as new false positives are observed in practice

## Known issues and future work

- **Document chunking**: removed due to stability issues on CPU-only hardware; may be reconsidered with a more capable backend.
- **Structured feeds**: not yet implemented; planned as a separate ingestion path that writes directly into the extraction schema, bypassing the LLM.
- **Semantic correlation performance**: the current prompt scores ~6/8 on the benchmark suite (see `benchmark/`). The two remaining failure cases are:
  - `unnamed_actor_same_campaign_signature` — correlation based on a distinctive combination of TTPs, with no named actor
  - `vague_actor_description_match` — correlation based on vague, non-aliased actor descriptions
- **Frontend configuration**: planned to let users adjust, without editing code, the document size limit, feed selection, threat scoring thresholds, and the non-actor keyword list.

## Summary

Step 0 collects threat reports from 11 narrative feeds. The pipeline
extracts IOCs via the local LLM, correlates findings across documents,
and generates structured reports. Known limitations (document size,
disabled chunking, occasional false-positive actors) are mitigated but
not fully solved; the system is otherwise stable end to end. Planned
work includes implementing the structured feeds, improving semantic
correlation accuracy, and adding frontend-based configuration.