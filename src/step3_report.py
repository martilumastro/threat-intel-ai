"""Step 3: Intelligence Report Generation, Threat Scoring, and Export."""

import json
from pathlib import Path
from typing import Any


def calculate_threat_score(data: dict[str, Any]) -> str:
    """Calculate an overall threat level based on correlation findings."""
    if not isinstance(data, dict):
        raise TypeError("Correlations input must be a dictionary")

    exact = data.get("exact_matches", [])
    actor_aliases = data.get("known_actor_alias_matches", [])
    semantic = data.get("semantic_matches", [])

    total_matches = len(exact) + len(actor_aliases) + len(semantic)

    # Regole per lo score globale
    if len(actor_aliases) >= 1 and len(exact) >= 1:
        return "CRITICAL"
    if len(actor_aliases) >= 1 or len(exact) >= 2:
        return "HIGH"
    if total_matches > 0:
        return "MEDIUM"
    return "LOW"


def generate_markdown_report(data: dict[str, Any], threat_level: str) -> str:
    """Generate a structured Markdown report for analysts and frontend rendering."""
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

    # Sezione 1: Actor Alias Matches
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

    # Sezione 2: Exact IOC Matches
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

    # Sezione 3: Semantic Matches
    if semantic:
        report_lines.extend(["### Semantic Correlations", ""])
        for idx, item in enumerate(semantic, 1):
            reasoning = item.get("reasoning", "No detailed reasoning.")
            confidence = item.get("confidence", "unknown").upper()

            report_lines.extend(
                [
                    f"#### {idx}. Semantic Link (Confidence: `{confidence}`)",
                    f"- **Analysis:** {reasoning}",
                    "",
                ]
            )

    if not (exact or actor_aliases or semantic):
        report_lines.append("_No correlations detected across input documents._\n")

    return "\n".join(report_lines)


def run_step3(
    input_file: Path = Path("data/correlated/correlations.json"),
    output_dir: Path = Path("data/final_reports"),
) -> None:
    """Read correlated data and export both JSON and Markdown artifacts."""
    if not input_file.exists():
        raise FileNotFoundError(f"Correlations file not found at {input_file}")

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise TypeError("Loaded correlations data must be a JSON object")

    threat_level = calculate_threat_score(data)
    markdown_content = generate_markdown_report(data, threat_level)

    # Struttura JSON finale arricchita per l'API / Frontend
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

    # 1. Salviamo il file JSON
    json_path = output_dir / "threat_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_json_payload, f, indent=2)

    # 2. Salviamo il file Markdown
    md_path = output_dir / "threat_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"[+] Step 3 completato con successo! Report generati in: {output_dir}")


if __name__ == "__main__":
    run_step3()