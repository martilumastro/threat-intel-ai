# Sources and Operational Limits

## Step 0: clearweb collection

Step 0 collects public RSS entries from the locally configured narrative feeds.
The feed configuration is stored in `knowledge/sources.json` and is private at
the current stage. It is a JSON configuration file, not the collected article
format.

For each unseen entry, Step 0 writes a small `.url` manifest under
`data/raw_reports/`:

```text
Source: Example Source
Title: Example report title
Published: Mon, 01 Jan 2026 12:00:00 +0000
URL: https://example.org/report
```

The pipeline does **not** persist article HTML or article text at collection
time. Step 1 retrieves the article later from the manifest URL, removes common
HTML boilerplate, and analyzes the resulting text. This keeps collection light,
avoids storing page bodies, and permits local/private handling of collected
references.

## Narrative feeds

Narrative feeds contain prose-style reporting and are processed through the
hybrid extraction path: deterministic IOC extraction plus local LLM extraction
for actors and TTPs. Current source selection is defined in the private
`knowledge/sources.json` file and includes public security-research feeds such
as Unit 42, Securelist, SANS ISC, CrowdStrike, Krebs on Security, Check Point
Research, The Hacker News, BleepingComputer, Recorded Future, Google Security,
and Microsoft Security.

Source configuration should be reviewed periodically because RSS endpoints,
publication formats, and access policies can change.

## Structured feeds

Structured feeds are configured but not implemented in Step 0 yet. They
provide ready-made indicators such as IP lists, CVE catalogues, hashes, or STIX
objects and should use a dedicated validated ingestion path rather than the
narrative LLM workflow.

Planned examples include Blocklist.de, CISA KEV, Abuse.ch URLhaus and Feodo
Tracker, MalwareBazaar, AlienVault OTX, HIBP breach metadata, and the MITRE
ATT&CK STIX dataset.

## Processing limits and expected failures

The pipeline processes URLs sequentially. A real run depends on:

- the remote site accepting the request and serving its current page layout;
- network and TLS connection latency;
- article size and HTML complexity;
- local memory and the performance of the configured Ollama model.

An individual URL may fail because of a timeout, a rate limit, a page redesign,
a removed article, or access restrictions. These are normal integration
conditions; a batch processor should log the failed manifest and continue with
the next one.

`THREAT_INTEL_MAX_DOCUMENT_CHARS` defaults to `50000`. Very long documents are
limited to protect CPU-only hardware. Document chunking is currently avoided
because it previously produced unstable local-model results.

## Running collection and processing

```bash
# Collect new article references from configured RSS feeds
venv/bin/python src/step0_collection.py --output-dir data/raw_reports

# Test article retrieval and extraction only on a small private set
venv/bin/python src/step4_orchestrator.py \
  --input-dir data/raw_reports_test \
  --no-correlation

# Run the complete pipeline on the same set
venv/bin/python src/step4_orchestrator.py \
  --input-dir data/raw_reports_test

# Process newly collected manifests incrementally
venv/bin/python src/step4_orchestrator.py \
  --input-dir data/raw_reports \
  --skip-existing
```

Use `--no-correlation` when validating retrieval/extraction or when the number
of documents would make semantic correlation too expensive for the available
hardware.

## Current improvement backlog

- Improve filtering of code-like strings and package names incorrectly matched
  as domains or email addresses.
- Recognize defanged IP addresses embedded in URLs as both URLs and IPs.
- Map explicit natural-language descriptions, such as password spraying, to
  MITRE ATT&CK techniques only when the mapping is reviewed and sufficiently
  specific.
- Improve actor and malware-family recall with test cases before broad prompt
  or parser changes.
- Implement the separate validated ingestion path for structured feeds.
