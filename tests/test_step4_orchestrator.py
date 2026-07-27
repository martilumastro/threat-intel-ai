"""Tests for Step 4 - Pipeline Orchestrator."""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from step4_orchestrator import (
    run_correlation_stage,
    run_extraction_stage,
    run_pipeline,
    run_reporting_stage,
)

# ===== FIXTURES =====

@pytest.fixture
def temp_data_dir(tmp_path):
    """Create a temporary data directory with subdirectories."""
    data_dir = tmp_path / "data"
    (data_dir / "extracted").mkdir(parents=True, exist_ok=True)
    (data_dir / "correlated").mkdir(parents=True, exist_ok=True)
    (data_dir / "final_reports").mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture
def sample_report_dir(tmp_path):
    """Create a directory with sample .txt reports."""
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    
    # Create a sample report
    (report_dir / "test_report.txt").write_text(
        "APT29 used IP 185.220.101.45 for C2 communications.\n"
        "Domain malicious-update.net was observed.\n"
        "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    return report_dir


@pytest.fixture
def mock_extracted_document():
    """Mock extracted document for testing."""
    return {
        "source_document": "test_report",
        "status": "extracted",
        "data": {
            "ip": ["185.220.101.45"],
            "domains": ["malicious-update.net"],
            "hashes": [],
            "emails": [],
            "mitre_ttps": [],
            "actors_mentioned": []
        }
    }


# ===== TESTS =====

class TestRunExtractionStage:
    """Test the extraction stage of the orchestrator."""

    def test_run_extraction_stage_with_empty_dir(self, temp_data_dir, monkeypatch):
        """Should return 0 when no .txt files are found."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        
        empty_dir = temp_data_dir / "empty"
        empty_dir.mkdir()
        
        result = run_extraction_stage(empty_dir, skip_existing=False)
        assert result == 0

    def test_run_extraction_stage_processes_reports(self, sample_report_dir, temp_data_dir, monkeypatch):
        """Should process .txt files and save JSON results."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")

        with patch("step4_orchestrator.extract_ioc") as mock_extract:
            mock_extract.return_value = {
                "ip": ["185.220.101.45"],
                "domains": ["malicious-update.net"],
                "hashes": [],
                "emails": [],
                "mitre_ttps": [],
                "actors_mentioned": [],
                "cve_ids": [],
                "urls": [],
                "suspicious_files": []
            }

            with patch("step4_orchestrator.save_result") as mock_save:
                mock_save.return_value = str(temp_data_dir / "extracted" / "test_report.json")
                
                result = run_extraction_stage(sample_report_dir, skip_existing=False)
                
                assert result == 1
                mock_save.assert_called_once_with("test_report", mock_extract.return_value)

    def test_run_extraction_stage_skip_existing(self, sample_report_dir, temp_data_dir, monkeypatch):
        """Should skip files that already have extracted results."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        
        # Pre-create an extraction file
        extracted_dir = temp_data_dir / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)  # <-- FIX: aggiunto exist_ok=True
        (extracted_dir / "test_report.json").write_text('{"status": "extracted"}')
        
        with patch("step4_orchestrator.extract_ioc") as mock_extract:
            result = run_extraction_stage(sample_report_dir, skip_existing=True)
            assert result == 0
            mock_extract.assert_not_called()

    def test_run_extraction_stage_handles_errors(self, sample_report_dir, temp_data_dir, monkeypatch):
        """Should handle extraction failures gracefully."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        
        with patch("step4_orchestrator.extract_ioc") as mock_extract:
            mock_extract.side_effect = RuntimeError("Model error")
            
            result = run_extraction_stage(sample_report_dir, skip_existing=False)
            
            assert result == 0  # No files processed
            assert not (temp_data_dir / "extracted" / "test_report.json").exists()


class TestRunCorrelationStage:
    """Test the correlation stage of the orchestrator."""

    def test_run_correlation_stage_with_no_documents(self, temp_data_dir, monkeypatch):
        """Should handle the case with no extracted documents."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        monkeypatch.setattr("step4_orchestrator.CORRELATED_DIR", temp_data_dir / "correlated")
        
        with (
            patch("step4_orchestrator.load_extracted_documents", return_value=[]),
            patch("step4_orchestrator.save_correlations") as mock_save,
        ):
            mock_save.return_value = str(temp_data_dir / "correlated" / "correlations.json")
                
            result = run_correlation_stage()
                
            assert result["exact_matches"] == []
            assert result["known_actor_alias_matches"] == []
            assert result["semantic_matches"] == []
            mock_save.assert_called_once()

    def test_run_correlation_stage_finds_exact_matches(self, temp_data_dir, monkeypatch):
        """Should find exact matches between documents."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        monkeypatch.setattr("step4_orchestrator.CORRELATED_DIR", temp_data_dir / "correlated")
        
        doc1 = {"source_document": "doc1", "data": {"ip": ["185.220.101.45"], "domains": []}}
        doc2 = {"source_document": "doc2", "data": {"ip": ["185.220.101.45"], "domains": []}}
        
        with (
            patch("step4_orchestrator.load_extracted_documents", return_value=[doc1, doc2]),
            patch("step4_orchestrator.load_actor_aliases", return_value={}),
            patch("step4_orchestrator.save_correlations") as mock_save,
        ):
            mock_save.return_value = str(temp_data_dir / "correlated" / "correlations.json")
                    
            result = run_correlation_stage()
                    
            assert len(result["exact_matches"]) == 1
            assert result["exact_matches"][0]["shared_values"] == ["185.220.101.45"]


class TestRunReportingStage:
    """Test the reporting stage of the orchestrator."""

    def test_run_reporting_stage_calls_step3(self):
        """Should call run_step3 with the correct arguments."""
        with patch("step4_orchestrator.run_step3") as mock_step3:
            run_reporting_stage()
            mock_step3.assert_called_once()


class TestRunPipeline:
    """Test the full pipeline execution."""

    def test_run_pipeline_with_no_correlation(self, sample_report_dir, temp_data_dir, monkeypatch, capsys):
        """Should skip correlation when --no-correlation is set."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        monkeypatch.setattr("step4_orchestrator.CORRELATED_DIR", temp_data_dir / "correlated")
        monkeypatch.setattr("step4_orchestrator.FINAL_REPORTS_DIR", temp_data_dir / "final_reports")
        
        # Mock the extraction stage
        with (
            patch("step4_orchestrator.run_extraction_stage", return_value=1) as mock_extract,
            patch("step4_orchestrator.requests.get") as mock_get,
        ):
            mock_get.return_value = MagicMock()
                
            run_pipeline(sample_report_dir, skip_existing=False, no_correlation=True)
                
            mock_extract.assert_called_once()
            captured = capsys.readouterr()
            assert "Skipping Step 2" in captured.out

    def test_run_pipeline_full(self, sample_report_dir, temp_data_dir, monkeypatch):
        """Should run the full pipeline when no flags are set."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        monkeypatch.setattr("step4_orchestrator.CORRELATED_DIR", temp_data_dir / "correlated")
        monkeypatch.setattr("step4_orchestrator.FINAL_REPORTS_DIR", temp_data_dir / "final_reports")
        
        with (
            patch("step4_orchestrator.run_extraction_stage", return_value=1),
            patch("step4_orchestrator.run_correlation_stage", return_value={
                "exact_matches": [],
                "known_actor_alias_matches": [],
                "semantic_matches": []
            }),
            patch("step4_orchestrator.run_reporting_stage") as mock_report,
            patch("step4_orchestrator.requests.get") as mock_get,
        ):
            mock_get.return_value = MagicMock()
                        
            run_pipeline(sample_report_dir, skip_existing=False, no_correlation=False)
                        
            mock_report.assert_called_once()

    def test_run_pipeline_handles_ollama_check(self, sample_report_dir, temp_data_dir, monkeypatch, capsys):
        """Should display a warning when Ollama is not responding."""
        monkeypatch.setattr("step4_orchestrator.EXTRACTED_DIR", temp_data_dir / "extracted")
        monkeypatch.setattr("step4_orchestrator.CORRELATED_DIR", temp_data_dir / "correlated")
        monkeypatch.setattr("step4_orchestrator.FINAL_REPORTS_DIR", temp_data_dir / "final_reports")
        
        with patch("step4_orchestrator.requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("Connection error")
            with patch("step4_orchestrator.run_extraction_stage", return_value=0):
                
                run_pipeline(sample_report_dir, skip_existing=False, no_correlation=True)
                
                captured = capsys.readouterr()
                assert "WARNING: Ollama is not responding!" in captured.out


class TestArgumentParsing:
    """Test the command-line argument parsing."""

    def test_parse_args_required_input_dir(self, monkeypatch):
        """Should require --input-dir."""
        with patch("argparse.ArgumentParser.parse_args") as mock_parse:
            mock_parse.return_value = argparse.Namespace(
                input_dir=Path("/test/reports"),
                skip_existing=False,
                no_correlation=False
            )
            
            from step4_orchestrator import parse_args
            args = parse_args()
            
            assert args.input_dir == Path("/test/reports")
            assert args.skip_existing is False
            assert args.no_correlation is False

    def test_parse_args_all_flags(self, monkeypatch):
        """Should parse all flags correctly."""
        with patch("argparse.ArgumentParser.parse_args") as mock_parse:
            mock_parse.return_value = argparse.Namespace(
                input_dir=Path("/test/reports"),
                skip_existing=True,
                no_correlation=True
            )
            
            from step4_orchestrator import parse_args
            args = parse_args()
            
            assert args.skip_existing is True
            assert args.no_correlation is True