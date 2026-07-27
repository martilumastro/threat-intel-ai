"""
STEP 1 - IOC Extraction Module
--------------------------------
Takes a .url file (containing a link to an article) or a .txt file (raw text)
and extracts IOCs using a hybrid approach:
1. Regex (deterministic) for IPs, domains, hashes, emails, CVE, URLs, suspicious files
2. LLM for threat actors and MITRE ATT&CK TTPs

The result is saved to data/extracted/ as a JSON file, ready to be
read by the next module (correlation).
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import requests

from common import (
    EXTRACTED_DIR,
    MODEL,
    OLLAMA_URL,
    REQUEST_TIMEOUT,
    atomic_write_json,
    extract_iocs_with_regex,
    normalize_extraction,
    safe_document_name,
)
from knowledge_context import (
    build_extraction_knowledge_context,
    filter_curated_false_positives,
)

# --- Configuration ---
EXTRACTION_PROMPT = """Extract threat actors and MITRE ATT&CK techniques from the text below.

Return ONLY a JSON object with these fields:
- actors_mentioned: list of threat actor names, groups, and malware families
- mitre_ttps: list of MITRE ATT&CK technique IDs (T#### or T####.###)

RULES:
1. Include ONLY named threat actors, hacker groups, or malware families.
2. EXCLUDE cybersecurity vendors, researchers, and companies.
3. If a name appears as "according to X" or "X reported", EXCLUDE it.
4. Include malware family names (e.g., "Vidar Stealer", "XMRig", "TuxBot").
5. Include APT groups and nation-state actors (e.g., "APT29", "Cozy Bear").
6. If a name is clearly a threat actor, INCLUDE it.

GOOD examples: "APT29", "Cozy Bear", "Wizard Spider", "Vidar Stealer", "TuxBot", "TeamPCP", "CL-STA-1062"
BAD examples: "Check Point", "Microsoft", "Google", "Unit 42", "Palo Alto Networks"

Empty lists if nothing found.

<curated_knowledge>
{knowledge_context}
</curated_knowledge>

<untrusted_report>
{text}
</untrusted_report>"""


def fetch_article_from_url(url: str) -> str:
    """Fetch and clean article content from a URL."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise RuntimeError("BeautifulSoup not installed. Run: pip install beautifulsoup4")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Remove unwanted elements
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "iframe"]):
            tag.decompose()

        # Get the text
        text = soup.get_text(separator="\n", strip=True)

        # Clean up extra whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)

        if not text or len(text) < 100:
            print("    Warning: fetched content is very short or empty")

        return text

    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch {url}: {e}")
    except (AttributeError, ValueError, TypeError) as e:
        raise RuntimeError(f"Failed to parse {url}: {e}")


def read_article_file(file_path: Path) -> str:
    """
    Read a .url or .txt file and return the article text.

    - .url files: fetch the article from the URL
    - .txt files: read the text directly
    """
    content = file_path.read_text(encoding="utf-8")

    if file_path.suffix == ".url":
        # Parse the .url file to extract the URL
        url_match = re.search(r"URL: (.+)", content)
        if url_match:
            url = url_match.group(1).strip()
            print(f"    Fetching article from URL: {url[:80]}...")
            return fetch_article_from_url(url)
        else:
            # No URL found, fallback to content
            return content
    else:
        # .txt file: use as-is
        return content


def extract_ioc_llm(text: str) -> dict:
    """Extract actors and TTPs using the LLM."""
    prompt = EXTRACTION_PROMPT.format(
        text=text,
        knowledge_context=build_extraction_knowledge_context(text),
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
        raw_result = response.json()["response"]
    except (ValueError, KeyError, TypeError) as error:
        raise RuntimeError("Ollama returned an unexpected response format") from error

    # Try to extract JSON from the response using regex
    json_match = re.search(r"\{[^{}]*\}", raw_result, re.DOTALL)
    if json_match:
        json_str = json_match.group()
    else:
        json_str = raw_result

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        print(f"    RAW RESPONSE: {raw_result[:300]}...")
        return {"actors_mentioned": [], "mitre_ttps": []}


def extract_ioc(text: str) -> dict:
    # Step 1: Extract IOCs with regex (deterministic)
    regex_iocs = extract_iocs_with_regex(text)
    
    # Step 2: Extract actors and TTPs with LLM
    try:
        llm_result = extract_ioc_llm(text)
        llm_actors = llm_result.get("actors_mentioned", [])
        llm_ttps = llm_result.get("mitre_ttps", [])
    except (ValueError, KeyError, TypeError) as e:
        print(f"    LLM extraction failed: {e}, using regex only")
        llm_actors = []
        llm_ttps = []
    
    # Step 3: Combine results
    combined = {
        "ip": regex_iocs.get("ip", []),
        "domains": regex_iocs.get("domains", []),
        "hashes": regex_iocs.get("hashes", []),
        "emails": regex_iocs.get("emails", []),
        "mitre_ttps": llm_ttps,
        "actors_mentioned": llm_actors,
        "cve_ids": regex_iocs.get("cve_ids", []),
        "urls": regex_iocs.get("urls", []),
        "suspicious_files": regex_iocs.get("suspicious_files", [])
    }
    
    return filter_curated_false_positives(normalize_extraction(combined))


def save_result(document_name: str, extracted_data: dict) -> str:
    """Saves the result to a timestamped JSON file, ready for the next step."""
    document_name = safe_document_name(document_name)
    extracted_data = normalize_extraction(extracted_data)

    record = {
        "source_document": document_name,
        "extraction_timestamp": datetime.now(UTC).isoformat(),
        "status": "extracted",
        "data": extracted_data,
    }

    file_path = EXTRACTED_DIR / f"{document_name}.json"
    atomic_write_json(file_path, record)
    return str(file_path)


if __name__ == "__main__":
    # Example usage: a small test text
    sample_text = """
    The APT29 group used the IP 185.220.101.45 for C2 communications.
    The domain malicious-update[.]net was also observed, along with the
    SHA256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
    The main technique observed was spear-phishing (T1566).
    """

    print("Sending text to the model for extraction...")
    try:
        data = extract_ioc(sample_text)
    except (requests.RequestException, RuntimeError) as error:
        raise SystemExit(f"Extraction failed: {error}")

    print("Extracted result:")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    path = save_result("sample_report_001", data)
    print(f"\nSaved to: {path}")
