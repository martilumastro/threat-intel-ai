# Threat Intelligence AI

Threat Intelligence AI is a local, modular prototype that assists a threat
analyst with two tasks: extracting indicators of compromise (IOCs) from text
and correlating the extracted records. It uses a locally hosted LLM through
Ollama, keeping processing and data under the operator's control.

This project orchestrates existing models; it does not train a model from
scratch. Deterministic operations, such as matching the same IP address in two
reports, are performed in Python. The LLM is reserved for extraction and for
semantic correlation where a deterministic comparison is not sufficient.

## Current pipeline

```text
Step 0: Clearweb collection       Not implemented yet
Step 1: IOC and TTP extraction    Implemented
Step 2: Correlation               Implemented
Step 3: Reporting                 Planned
Step 4: Orchestration             Planned
```

The implemented stages communicate through JSON files on disk. Each stage can
be executed independently.

## Project layout

```text
src/
  common.py                    Shared configuration, validation, normalisation and JSON helpers
  step1_extraction.py          Step 1: extract IOCs, TTPs and actors through Ollama
  step2_correlation.py         Step 2: exact and semantic correlation
  generate_test_documents.py   Manual end-to-end test using the stable fixtures
tests/
  fixtures/                    Three simulated threat reports
  expected/                    Expected structured extraction results
  test_*.py                    Automated tests that do not require Ollama
data/
  extracted/                   Locally generated Step 1 output
  correlated/                  Locally generated Step 2 output
```

## Implemented stages

### Step 1: extraction

`step1_extraction.py` submits a raw report to Ollama and expects a JSON object
containing IP addresses, domains, hashes, email addresses, MITRE ATT&CK TTPs,
and mentioned actors. The response is validated and normalised before it is
stored in `data/extracted/`.

Normalisation includes de-fanging domains such as `example[.]com`, lowercasing
where appropriate, validation of IOC formats, and deduplication. Invalid or
out-of-schema LLM responses are rejected rather than being silently passed to
the next stage.

### Step 2: correlation

`step2_correlation.py` reads valid extraction records and first searches for
exact IOC matches using Python. It then asks the LLM to assess only candidate
pairs with structured evidence to compare, such as a shared TTP or actors
mentioned in both records. Exact and semantic matches are written separately to
`data/correlated/correlations.json`.

The semantic result is an analyst aid, not an automatic attribution decision.
Its confidence and reasoning should be reviewed by a human analyst.

## Requirements and installation

- Python 3.11 or newer
- Ollama running locally for manual pipeline runs
- The configured local model (default: `qwen3.5:9b`)

### Windows / WSL2 users

WSL2 limits itself to roughly 50% of total system RAM by default, which
is often not enough to run a 9B parameter model on CPU without the
Ollama process crashing mid-request. If you're on Windows, increase the
memory available to WSL2 before installing Ollama.

Create or edit `C:\Users\<your-username>\.wslconfig` on the Windows side:

```ini
[wsl2]
memory=12GB
processors=4
```

Adjust `memory` based on your total RAM, leaving a few GB free for
Windows itself. Restart WSL from PowerShell for the change to take
effect:

```bash
wsl --shutdown
```

Then reopen your WSL terminal and verify with `free -h`. If inference
fails with a connection/timeout error, this is the first thing to check.

### Environment setup

Create and activate a virtual environment, then install the project and its
development dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Configuration

The default Ollama configuration can be overridden without editing source code:

```bash
export THREAT_INTEL_OLLAMA_URL="http://localhost:11434/api/generate"
export THREAT_INTEL_MODEL="qwen3.5:9b"
export THREAT_INTEL_REQUEST_TIMEOUT="600"
```

## Running the pipeline manually

The fixture reports provide a small real integration test. It calls the local
model, so its duration depends on the hardware and model.

```bash
python src/generate_test_documents.py
python src/step2_correlation.py
```

The three reports are designed to cover an exact IOC match, a semantic
correlation candidate (APT29 and Cozy Bear), and an unrelated record. Results
are generated under `data/`.

## Automated tests

The automated tests mock Ollama responses and use temporary directories. They
are fast, do not require a model or GPU, and do not alter the local pipeline
output.

```bash
pytest
```

They currently cover IOC normalisation and validation, safe output names,
extraction-response validation, exact correlation, semantic candidate
selection, and graceful handling of corrupted extraction files.

## Versioned and local data

The simulated input reports and expected outputs under `tests/` are versioned:
they are part of the reproducible test suite. In contrast, `data/extracted/`
and `data/correlated/` contain regenerable local output and are ignored by Git.
This prevents routine runs, potentially sensitive collected data, and noisy
result changes from being committed accidentally.

## Security scope

The planned Step 0 will start with clearweb OSINT sources. Any future work
involving dark-web observation should be treated as a separate, legally and
operationally reviewed component, with isolation and strictly controlled data
transfer. This repository does not implement that capability.
