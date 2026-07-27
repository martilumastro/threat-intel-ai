"""Tests for Step 0 - Collection Module."""

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from step0_collection import (
    collect_feed,
    load_narrative_feeds,
    load_seen_registry,
    run_collection,
    save_seen_registry,
    strip_html,
)

# ===== FIXTURES =====

@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary output directory."""
    output_dir = tmp_path / "raw_reports"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def mock_feed_entry():
    """
    Create a mock feed entry that mimics feedparser's behavior.
    feedparser entries have both attributes and support .get().
    """
    entry = MagicMock()
    entry.link = "https://example.com/article1"
    entry.title = "Test Article"
    entry.published = "Mon, 01 Jan 2026 12:00:00 +0000"
    entry.summary = "This is a test article summary."

    # Content must be a list of objects with a 'value' attribute
    content_obj = MagicMock()
    content_obj.value = "<p>This is the full article content.</p>"
    entry.content = [content_obj]

    # Make .get() work like a dictionary
    def get_side_effect(key, default=None):
        return getattr(entry, key, default)
    entry.get.side_effect = get_side_effect

    return entry


@pytest.fixture
def sample_sources_json(tmp_path):
    """Create a temporary sources.json file."""
    sources = {
        "narrative_feeds": [
            {"name": "Test Feed", "url": "https://test.feed/rss", "kind": "rss"}
        ]
    }
    sources_path = tmp_path / "knowledge" / "sources.json"
    sources_path.parent.mkdir(parents=True, exist_ok=True)
    with sources_path.open("w") as f:
        json.dump(sources, f)
    return sources_path


# ===== TESTS =====

class TestStripHtml:
    """Test HTML stripping functionality."""

    def test_strip_html_basic(self):
        """Should remove HTML tags and unescape entities."""
        html = "<p>This is a <b>test</b> &amp; article.</p>"
        result = strip_html(html)
        assert result == "This is a test & article."

    def test_strip_html_with_extra_spaces(self):
        """Should normalize whitespace."""
        html = "<p>First</p><p>Second</p>"
        result = strip_html(html)
        assert result == "First Second"

    def test_strip_html_empty(self):
        """Should handle empty input."""
        assert strip_html("") == ""


class TestLoadSeenRegistry:
    """Test loading the seen URL registry."""

    def test_load_seen_registry_not_exists(self, tmp_path, monkeypatch):
        """Should return empty set if registry doesn't exist."""
        monkeypatch.setattr("step0_collection.SEEN_REGISTRY_PATH", tmp_path / "nonexistent.json")
        result = load_seen_registry()
        assert result == set()

    def test_load_seen_registry_exists(self, tmp_path, monkeypatch):
        """Should load existing registry."""
        registry_path = tmp_path / "registry.json"
        registry_path.write_text('["https://example.com/1", "https://example.com/2"]')
        monkeypatch.setattr("step0_collection.SEEN_REGISTRY_PATH", registry_path)

        result = load_seen_registry()
        assert result == {"https://example.com/1", "https://example.com/2"}


class TestSaveSeenRegistry:
    """Test saving the seen URL registry."""

    def test_save_seen_registry_creates_file(self, tmp_path, monkeypatch):
        """Should create the registry file with sorted URLs."""
        registry_path = tmp_path / "collection_state.json"
        monkeypatch.setattr("step0_collection.SEEN_REGISTRY_PATH", registry_path)

        seen_urls = {"https://example.com/b", "https://example.com/a"}
        save_seen_registry(seen_urls)

        assert registry_path.exists()
        with registry_path.open() as f:
            data = json.load(f)
        assert data == ["https://example.com/a", "https://example.com/b"]


class TestLoadNarrativeFeeds:
    """Test loading narrative feeds from sources.json."""

    def test_load_narrative_feeds_success(self, sample_sources_json, monkeypatch):
        """Should load narrative feeds from sources.json."""
        monkeypatch.setattr("step0_collection.SOURCES_PATH", sample_sources_json)

        feeds = load_narrative_feeds()
        assert len(feeds) == 1
        assert feeds[0]["name"] == "Test Feed"

    def test_load_narrative_feeds_missing_file(self, tmp_path, monkeypatch):
        """Should raise FileNotFoundError if sources.json doesn't exist."""
        missing_path = tmp_path / "missing.json"
        monkeypatch.setattr("step0_collection.SOURCES_PATH", missing_path)

        with pytest.raises(FileNotFoundError):
            load_narrative_feeds()


class TestCollectFeed:
    """Test collecting articles from a single feed."""

    def test_collect_feed_saves_new_articles(self, temp_output_dir, mock_feed_entry):
        """Should save new articles that aren't in the seen registry."""
        seen_urls = set()

        with patch("step0_collection.feedparser.parse") as mock_parse:
            mock_feed = MagicMock()
            mock_feed.bozo = False
            mock_feed.entries = [mock_feed_entry]
            mock_parse.return_value = mock_feed

            new_count = collect_feed(
                "Test Feed",
                "https://test.feed/rss",
                seen_urls,
                temp_output_dir
            )

            assert new_count == 1
            saved_file = temp_output_dir / "Test_Feed_Test_Article.url"
            assert saved_file.exists()
            content = saved_file.read_text()
            assert "Source: Test Feed" in content
            assert "Title: Test Article" in content
            assert "https://example.com/article1" in content
            assert "Published:" in content

    def test_collect_feed_skips_seen_articles(self, temp_output_dir, mock_feed_entry):
        """Should skip articles already in the seen registry."""
        seen_urls = {"https://example.com/article1"}

        with patch("step0_collection.feedparser.parse") as mock_parse:
            mock_feed = MagicMock()
            mock_feed.bozo = False
            mock_feed.entries = [mock_feed_entry]
            mock_parse.return_value = mock_feed

            new_count = collect_feed(
                "Test Feed",
                "https://test.feed/rss",
                seen_urls,
                temp_output_dir
            )

            assert new_count == 0
            assert not list(temp_output_dir.glob("*.txt"))

    def test_collect_feed_handles_bozo_warning(self, temp_output_dir, capsys):
        """Should print a warning for malformed feeds."""
        seen_urls = set()

        with patch("step0_collection.feedparser.parse") as mock_parse:
            mock_feed = MagicMock()
            mock_feed.bozo = True
            mock_feed.bozo_exception = "Malformed XML"
            mock_feed.entries = []
            mock_parse.return_value = mock_feed

            new_count = collect_feed(
                "Test Feed",
                "https://test.feed/rss",
                seen_urls,
                temp_output_dir
            )

            assert new_count == 0
            captured = capsys.readouterr()
            assert "warning: feed may be malformed" in captured.out

    def test_collect_feed_saves_entries_without_feed_text(self, temp_output_dir, capsys):
        """Should save a URL even when the feed has no summary or content."""
        seen_urls = set()

        # Create an entry without text
        entry = MagicMock()
        entry.link = "https://example.com/article1"
        entry.title = "Test Article"
        entry.published = "Mon, 01 Jan 2026 12:00:00 +0000"
        entry.summary = ""  # Empty summary
        entry.content = []  # Empty content list

        # Make .get() work like a dictionary
        def get_side_effect(key, default=None):
            return getattr(entry, key, default)
        entry.get.side_effect = get_side_effect

        with patch("step0_collection.feedparser.parse") as mock_parse:
            mock_feed = MagicMock()
            mock_feed.bozo = False
            mock_feed.entries = [entry]
            mock_parse.return_value = mock_feed

            new_count = collect_feed(
                "Test Feed",
                "https://test.feed/rss",
                seen_urls,
                temp_output_dir
            )

            assert new_count == 1
            assert (temp_output_dir / "Test_Feed_Test_Article.url").exists()
            captured = capsys.readouterr()
            assert "saved URL: Test Article" in captured.out


class TestRunCollection:
    """Test the main collection runner."""

    def test_run_collection_processes_all_feeds(self, temp_output_dir, sample_sources_json, monkeypatch):
        """Should process all configured feeds."""
        monkeypatch.setattr("step0_collection.SOURCES_PATH", sample_sources_json)
        monkeypatch.setattr("step0_collection.SEEN_REGISTRY_PATH", temp_output_dir / "collection_state.json")

        with patch("step0_collection.collect_feed") as mock_collect:
            mock_collect.return_value = 3

            run_collection(temp_output_dir)

            mock_collect.assert_called_once()
            assert (temp_output_dir / "collection_state.json").exists()

    def test_run_collection_handles_feed_failure(self, temp_output_dir, sample_sources_json, monkeypatch, capsys):
        """Should handle feed fetch failures gracefully."""
        monkeypatch.setattr("step0_collection.SOURCES_PATH", sample_sources_json)

        with patch("step0_collection.collect_feed") as mock_collect:
            mock_collect.side_effect = requests.RequestException("Connection error")

            run_collection(temp_output_dir)

            captured = capsys.readouterr()
            assert "FAILED to fetch feed" in captured.out

    def test_run_collection_creates_output_directory(self, tmp_path, sample_sources_json, monkeypatch):
        """Should create the output directory if it doesn't exist."""
        output_dir = tmp_path / "new_reports"
        assert not output_dir.exists()

        monkeypatch.setattr("step0_collection.SOURCES_PATH", sample_sources_json)
        monkeypatch.setattr("step0_collection.SEEN_REGISTRY_PATH", tmp_path / "collection_state.json")

        with patch("step0_collection.collect_feed", return_value=0):
            run_collection(output_dir)

            assert output_dir.exists()


class TestArgumentParsing:
    """Test command-line argument parsing."""

    def test_default_output_dir(self, monkeypatch):
        """Should use default output directory when not specified."""
        import step0_collection

        with patch("argparse.ArgumentParser.parse_args") as mock_parse:
            mock_args = argparse.Namespace(output_dir=Path("/default/path"))
            mock_parse.return_value = mock_args

            args = step0_collection.parse_args()
            assert args.output_dir == Path("/default/path")

    def test_custom_output_dir(self, monkeypatch):
        """Should accept custom output directory."""
        import step0_collection

        with patch("argparse.ArgumentParser.parse_args") as mock_parse:
            mock_args = argparse.Namespace(output_dir=Path("/custom/path"))
            mock_parse.return_value = mock_args

            args = step0_collection.parse_args()
            assert args.output_dir == Path("/custom/path")
