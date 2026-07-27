# Threat Intelligence AI

Threat Intelligence AI is a local, modular threat-intelligence pipeline for
collecting public clearweb reports, extracting structured indicators, finding
cross-report links, and producing analyst-readable reports. It is designed for
local execution with Ollama so that collected material and curated knowledge
remain under the operator's control.

The project does not train a model. It combines deterministic processing with a
local LLM: code handles format validation, IOC extraction, filtering, database
lookups, and deterministic correlations; the LLM is used only for the parts
that require interpretation, principally actor and TTP extraction and semantic
correlation.

## Pipeline

```text
Step 0  Clearweb RSS collection
          ↓ URL manifests (.url)
Step 1  Article retrieval, deterministic IOC extraction, database-grounded LLM extraction
          ↓ normalized extraction JSON
Step 2  Exact IOC, actor-alias, and semantic correlation
          ↓ correlation JSON
Step 3  Threat scoring and Markdown/JSON reporting
Step 4  Orchestration of Steps 1–3 for a folder of inputs
```

All five stages are implemented. Structured feeds are configured for a future
dedicated ingestion path; they are not yet processed by Step 0.

## Core design

### URL manifests instead of stored article bodies

Step 0 reads configured RSS feeds and writes a small `.url` manifest for each
new article. A manifest contains the source, title, publication date, and
canonical URL. Step 1 or Step 4 fetches the article body only when it is being
processed, strips unwanted HTML elements, and passes clean text onward.

This avoids storing large, potentially copyrighted or sensitive web pages in
the repository and keeps collection separate from analysis. A source can
change, disappear, reject a request, or time out after it has been collected;
such failures are expected operational conditions and should be logged per URL.

### Hybrid extraction

Step 1 uses deterministic regular expressions for IP addresses, domains,
hashes, email addresses, CVEs, URLs, and suspicious filenames. The local LLM
extracts actor names and MITRE ATT&CK TTPs. Results are normalized, validated,
deduplicated, and saved as JSON.

The local knowledge database supports extraction in two ways:

- relevant curated actor identities, known indicators, and known domains are
  included as compact context for the LLM;
- curated false positives are removed from the normalized output.

Only database entries relevant to the current article are included in the LLM
context, avoiding an unnecessary token and latency cost.

### Evidence-first correlation

Step 2 keeps evidence types separate:

1. **Exact matches**: shared IPs, domains, hashes, or email addresses.
2. **Known actor aliases**: aliases resolved through the curated SQLite
   knowledge database.
3. **Semantic matches**: remaining candidate pairs assessed by the local LLM.

Semantic output is an analyst aid, not an automatic attribution decision. A
single generic technique is not enough evidence on its own.

### Reporting and orchestration

Step 3 turns correlation results into a Markdown report and a frontend-ready
JSON summary. The report can enrich known actor aliases with country,
motivation, campaign, TTP, and analyst-note information from the database.

Step 4 runs extraction, correlation, and reporting for a folder of `.url` or
`.txt` inputs. It supports `--skip-existing` for incremental runs and
`--no-correlation` to isolate extraction.

## Repository layout

```text
src/
  common.py                 Shared paths, validation, deterministic extraction, DB helpers
  step0_collection.py       RSS collection into .url manifests
  step1_extraction.py       Retrieval and hybrid IOC/TTP/actor extraction
  step2_correlation.py      Deterministic and semantic correlation
  step3_report.py           Threat scoring and report generation
  step4_orchestrator.py     End-to-end batch runner
  actor_aliases.py          Alias lookup from the SQLite database
  knowledge_context.py      Relevant curated context and false-positive filtering
knowledge/
  init_db.py                SQLite schema initialization
  sources.json              Local feed configuration (private)
  threat_intel.db           Local curated knowledge records (private)
benchmark/
  benchmark_cases.py        Hand-labeled semantic-correlation cases
  run_benchmark.py          Model comparison runner
tests/                       Automated tests, no live Ollama required
data/                        Local collection state, manifests, output, and reports (private)
```

## Installation

Requirements:

- Python 3.11 or later
- Ollama running locally
- a local model compatible with the configured API; the current default is
  `qwen3.5:9b`

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

Configuration can be changed without editing code:

```bash
export THREAT_INTEL_OLLAMA_URL="http://localhost:11434/api/generate"
export THREAT_INTEL_MODEL="qwen3.5:9b"
export THREAT_INTEL_REQUEST_TIMEOUT="3600"
export THREAT_INTEL_MAX_DOCUMENT_CHARS="50000"
```

For WSL2 on Windows, allocate enough RAM to run the chosen local model. See
the WSL configuration guidance in the project history or adapt `.wslconfig` to
the available hardware.

## Common commands

```bash
# Run the automated suite
venv/bin/python -m pytest

# Initialize missing database tables; safe to rerun
venv/bin/python knowledge/init_db.py

# Collect new clearweb RSS article URLs
venv/bin/python src/step0_collection.py --output-dir data/raw_reports

# Test only retrieval and extraction on a small local URL set
venv/bin/python src/step4_orchestrator.py \
  --input-dir data/raw_reports_test \
  --no-correlation

# Run extraction, correlation, and reporting on that test set
venv/bin/python src/step4_orchestrator.py \
  --input-dir data/raw_reports_test

# Compare local models on semantic correlation
venv/bin/python benchmark/run_benchmark.py
```

## Testing and current limitations

The automated test suite uses mocks and temporary directories; it does not
contact RSS feeds, article sites, or Ollama. Real URL-manifest runs are
integration tests and depend on third-party availability, page layout, network
latency, and local model performance.

Known work items include improving precision for code-like domain and package
name false positives, recognizing de-fanged IP addresses embedded in URLs,
mapping explicit natural-language TTP descriptions to ATT&CK IDs, and
improving actor/malware recall. These should be evaluated with saved test cases
before changing extraction rules broadly.

## Privacy and version control

`data/` contains collected URLs, processing state, extraction results, and
generated reports. `knowledge/` contains source configuration and curated
records. These are local/private by default and are ignored by Git; only code,
schema, tests, and documentation are intended for publication.

Important: `.gitignore` affects only untracked files. Before publishing an
existing repository, check that no private record or configuration file is
already tracked or present in Git history.

## Security scope

The implemented collector is limited to public clearweb RSS sources. Any
future dark-web observation must be designed as a separate, legally reviewed,
isolated component with tightly controlled data transfer. This repository does
not implement dark-web collection.
