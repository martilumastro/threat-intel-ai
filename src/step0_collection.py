"""
STEP 0 - Collection Module (Phase 1: narrative RSS feeds)
------------------------------------------------------------
Reads the list of narrative feeds from knowledge/sources.json, fetches
new articles via feedparser, deduplicates against a persistent registry
of already-seen article URLs, and saves new articles as .url files -
the same input format step4_orchestrator.py will expect.

Structured feeds (CISA KEV, Abuse.ch, Blocklist.de, HIBP metadata) are
listed in sources.json but not yet implemented here: they publish
ready-made IOCs rather than prose, so they need a different ingestion
path that bypasses Step 1's LLM extraction entirely. That's a separate
phase, tracked by the "status": "not_yet_implemented" field in
sources.json.

Usage:
    python step0_collection.py --output-dir path/to/raw_reports
"""

import argparse
import html
import json
import re
from pathlib import Path

import feedparser
import requests

from common import DATA_DIR, PROJECT_DIR, safe_document_name

SOURCES_PATH = PROJECT_DIR / "knowledge" / "sources.json"
SEEN_REGISTRY_PATH = PROJECT_DIR / "data" / "collection_state.json"

REQUEST_TIMEOUT = 30
TAG_RE = re.compile(r"<[^>]+>")


def load_narrative_feeds() -> list[dict]:
    """Load the configured list of narrative (text) RSS feeds."""
    with SOURCES_PATH.open("r", encoding="utf-8") as f:
        sources = json.load(f)
    return sources.get("narrative_feeds", [])


def load_seen_registry() -> set[str]:
    """Load the set of article URLs already collected in past runs."""
    if not SEEN_REGISTRY_PATH.exists():
        return set()
    with SEEN_REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return set(json.load(f))


def save_seen_registry(seen_urls: set[str]) -> None:
    """Persist the updated set of seen article URLs."""
    SEEN_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SEEN_REGISTRY_PATH.open("w", encoding="utf-8") as f:
        json.dump(sorted(seen_urls), f, indent=2)


def strip_html(raw_html: str) -> str:
    """Naive HTML-to-text conversion for feed content.

    This is intentionally simple: it strips tags and unescapes entities,
    it does not handle complex layouts well. Good enough for feed
    summaries/content; if extraction quality turns out to be a problem
    on real articles, swap this for a proper library like trafilatura.
    """
    text = TAG_RE.sub(" ", raw_html)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_entry_text(entry: feedparser.FeedParserDict) -> str:
    """Get the best available text for a feed entry: full content if the
    feed provides it, otherwise fall back to the summary."""
    if "content" in entry and entry.content:
        raw = entry.content[0].value
    else:
        raw = entry.get("summary", "")
    return strip_html(raw)


def collect_feed(feed_name: str, feed_url: str, seen_urls: set[str], output_dir: Path) -> int:
    """Fetch one feed, save new entries as .url files, return count saved."""
    parsed = feedparser.parse(feed_url)

    if parsed.bozo:
        print(f"[{feed_name}] warning: feed may be malformed ({parsed.bozo_exception})")

    new_count = 0
    for entry in parsed.entries:
        link = entry.get("link")
        if not link or link in seen_urls:
            continue

        title = entry.get("title", "untitled")
        published = entry.get("published", "")

        # --- Save ONLY the URL (no text) ---
        document_name = safe_document_name(f"{feed_name}_{title}")
        output_path = output_dir / f"{document_name}.url"
        report_content = f"Source: {feed_name}\nTitle: {title}\nPublished: {published}\nURL: {link}\n"
        output_path.write_text(report_content, encoding="utf-8")
        seen_urls.add(link)
        new_count += 1
        print(f"[{feed_name}] saved URL: {title}")

    return new_count


def run_collection(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    feeds = load_narrative_feeds()
    seen_urls = load_seen_registry()

    total_new = 0
    for feed in feeds:
        try:
            new_count = collect_feed(feed["name"], feed["url"], seen_urls, output_dir)
            total_new += new_count
            print(f"[{feed['name']}] {new_count} new URL(s)")
        except requests.RequestException as error:
            print(f"[{feed['name']}] FAILED to fetch feed: {error}")

    save_seen_registry(seen_urls)
    print(f"\nCollection complete: {total_new} new URL(s) saved to {output_dir}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect new articles from configured narrative RSS feeds.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DATA_DIR / "raw_reports",
        help="Folder to save new articles as .url files, ready for the orchestrator.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_collection(args.output_dir)