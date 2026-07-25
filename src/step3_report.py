"""Step 3: Intelligence Report Generation, Threat Scoring, and Export."""

import json
from pathlib import Path
from typing import Any

from common import CORRELATED_DIR, DATA_DIR, atomic_write_json, get_knowledge_db

FINAL_REPORTS_DIR = DATA_DIR / "final_reports"


def enrich_actor_info(canonical_name: str) -> dict | None:
    """Recupera informazioni aggiuntive su un attore dal database."""
    with get_knowledge_db() as conn:
        cursor = conn.execute("""
            SELECT 
                a.country,
                a.motivation,
                a.notes,
                GROUP_CONCAT(DISTINCT c.campaign_id) as campaigns,
                GROUP_CONCAT(DISTINCT t.ttp_code) as ttps
            FROM actors a
            LEFT JOIN campaign_actors ca ON a.id = ca.actor_id
            LEFT JOIN campaigns c ON ca.campaign_id = c.id
            LEFT JOIN campaign_ttps ct ON c.id = ct.campaign_id
            LEFT JOIN ttps t ON ct.ttp_id = t.id
            WHERE a.canonical_name = ?
            GROUP BY a.id
        """, (canonical_name,))
        row = cursor.fetchone()
        return dict(row) if row else None


def calculate_threat_score(data: dict[str, Any]) -> str:
    """Calculate an overall threat level based on correlation findings.

    Design note: semantic-only correlations can never raise the score
    above MEDIUM, regardless of how many there are or how high their
    confidence is. This is intentional, not an oversight: the README
    states that semantic results are an analyst aid, not an automatic
    attribution decision, so they should never drive the score into
    HIGH/CRITICAL territory on their own. Only deterministic evidence
    (exact IOC matches, known actor aliases) can do that.
    """
    if not isinstance(data, dict):
        raise TypeError("Correlations input must be a dictionary")

    exact = data.get("exact_matches", [])
    actor_aliases = data.get("known_actor_alias_matches", [])
    semantic = data.get("semantic_matches", [])

    total_matches = len(exact) + len(actor_aliases) + len(semantic)

    if len(actor_aliases) >= 1 and len(exact) >= 1:
        return "CRITICAL"
    if len(actor_aliases) >= 1 or len(exact) >= 2:
        return "HIGH"
    if total_matches > 0:
        return "MEDIUM"
    return "LOW"


def generate_markdown_report(
    data: dict[str, Any],
    threat_level: str,
    enrich_fn=enrich_actor_info,
) -> str:
    """Generate a structured Markdown report for analysts and frontend rendering.

    enrich_fn is injectable so tests can pass a fake lookup instead of
    hitting the real knowledge database - see test_step3_report.py.
    """
    timestamp = data.get("correlation_timestamp", "N/A")
    exact = data.get("exact_matches", [])
    actor_aliases = data.get("known_actor_alias_matches", [])
    semantic = data.get("semantic_matches", [])

    report_lines = [
        "# Threat Intelligence Analysis Report",
        "",
        f"- **Correlation Timestamp:** `{timestamp}`",
        f"- **Overall Threat Severity:** `{threat_level}`",
        "",
        "## Summary of Findings",
        "",
        f"- **Exact IOC Matches:** {len(exact)}",
        f"- **Threat Actor Alias Matches:** {len(actor_aliases)}",
        f"- **Semantic Correlations:** {len(semantic)}",
        "",
    ]

    # Section 1: Actor Alias Matches
    if actor_aliases:
        report_lines.extend(["### Threat Actor Alias Matches", ""])
        for idx, item in enumerate(actor_aliases, 1):
            actors = ", ".join(item.get("canonical_actors", []))
            doc_a = item.get("document_a")
            doc_b = item.get("document_b")
            names_a = ", ".join(item.get("actor_names_a", []))
            names_b = ", ".join(item.get("actor_names_b", []))

            report_lines.extend(
                [
                    f"#### {idx}. Canonical Actor: {actors}",
                    f"- **Documents Linked:** `{doc_a}` ↔ `{doc_b}`",
                    f"- **Aliases Identified:** {names_a} / {names_b}",
                    "",
                ]
            )

            # --- INTELLIGENCE ENRICHMENT from Knowledge DB ---
            for canonical in item.get("canonical_actors", []):
                if not canonical:
                    continue
                enrichment = enrich_fn(canonical)
                if enrichment and any([
                    enrichment.get("country"),
                    enrichment.get("motivation"),
                    enrichment.get("campaigns"),
                    enrichment.get("ttps"),
                    enrichment.get("notes")
                ]):
                    report_lines.append(f"**Intelligence Enrichment ({canonical}):**")
                    if enrichment.get("country"):
                        report_lines.append(f"- **Country:** {enrichment['country']}")
                    if enrichment.get("motivation"):
                        report_lines.append(f"- **Motivation:** {enrichment['motivation']}")
                    if enrichment.get("campaigns"):
                        report_lines.append(f"- **Known campaigns:** {enrichment['campaigns']}")
                    if enrichment.get("ttps"):
                        report_lines.append(f"- **Typical TTPs:** {enrichment['ttps']}")
                    if enrichment.get("notes"):
                        report_lines.append(f"- **Notes:** {enrichment['notes']}")
                    report_lines.append("")

    # Section 2: Exact IOC Matches
    if exact:
        report_lines.extend(["### Exact IOC Matches", ""])
        for idx, item in enumerate(exact, 1):
            category = item.get("category", "unknown").upper()
            values = ", ".join(item.get("shared_values", []))
            doc_a = item.get("document_a")
            doc_b = item.get("document_b")

            report_lines.extend(
                [
                    f"#### {idx}. Shared {category}: `{values}`",
                    f"- **Documents Linked:** `{doc_a}` ↔ `{doc_b}`",
                    "",
                ]
            )

    # Section 3: Semantic Matches
    if semantic:
        report_lines.extend(["### Semantic Correlations", ""])
        for idx, item in enumerate(semantic, 1):
            doc_a = item.get("document_a")
            doc_b = item.get("document_b")
            reasoning = item.get("reasoning", "No detailed reasoning.")
            confidence = item.get("confidence", "unknown").upper()

            report_lines.extend(
                [
                    f"#### {idx}. Semantic Link (Confidence: `{confidence}`)",
                    f"- **Documents Linked:** `{doc_a}` ↔ `{doc_b}`",
                    f"- **Analysis:** {reasoning}",
                    "",
                ]
            )

    if not (exact or actor_aliases or semantic):
        report_lines.append("_No correlations detected across input documents._\n")

    return "\n".join(report_lines)


def run_step3(
    input_file: Path = CORRELATED_DIR / "correlations.json",
    output_dir: Path = FINAL_REPORTS_DIR,
) -> None:
    """Read correlated data and export both JSON and Markdown artifacts."""
    if not input_file.exists():
        raise FileNotFoundError(f"Correlations file not found at {input_file}")

    with input_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise TypeError("Loaded correlations data must be a JSON object")

    threat_level = calculate_threat_score(data)
    markdown_content = generate_markdown_report(data, threat_level)

    # Enriched JSON structure for the API / frontend
    final_json_payload = {
        "summary": {
            "overall_threat_level": threat_level,
            "total_exact_matches": len(data.get("exact_matches", [])),
            "total_actor_alias_matches": len(
                data.get("known_actor_alias_matches", [])
            ),
            "total_semantic_matches": len(data.get("semantic_matches", [])),
        },
        "details": data,
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "threat_report.json"
    atomic_write_json(json_path, final_json_payload)

    md_path = output_dir / "threat_report.md"
    with md_path.open("w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"Step 3 complete. Reports generated in: {output_dir}")


if __name__ == "__main__":
    run_step3()