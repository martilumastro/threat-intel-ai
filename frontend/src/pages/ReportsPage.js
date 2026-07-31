import React, { useState, useEffect } from 'react';
import './ReportsPage.css';

const API_BASE = 'http://127.0.0.1:8000/api';

// Fields shown as clickable entities in the extraction cards, in display order.
// Each entry maps the extraction JSON field name to the category value
// sent to the /explain endpoint, and to a short label for the UI.
const ENTITY_FIELDS = [
    { field: 'actors_mentioned', category: 'actor', label: 'Actors' },
    { field: 'mitre_ttps', category: 'ttp', label: 'MITRE TTPs' },
    { field: 'cve_ids', category: 'cve', label: 'CVEs' },
    { field: 'ip', category: 'ip', label: 'IP addresses' },
    { field: 'domains', category: 'domains', label: 'Domains' },
    { field: 'hashes', category: 'hashes', label: 'Hashes' },
    { field: 'emails', category: 'emails', label: 'Emails' },
    { field: 'urls', category: 'urls', label: 'URLs' },
    { field: 'suspicious_files', category: 'suspicious_files', label: 'Suspicious files' },
];

const SEVERITY_LABELS = {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
};

const ReportsPage = () => {
    const [extractedReports, setExtractedReports] = useState([]);
    const [finalReport, setFinalReport] = useState(null);
    const [loadingExtracted, setLoadingExtracted] = useState(true);
    const [loadingFinal, setLoadingFinal] = useState(true);
    const [error, setError] = useState(null);

    // Explanation panel state: which entity is selected, and what the
    // backend returned for it (or whether it is still loading)
    const [selectedEntity, setSelectedEntity] = useState(null);
    const [explanation, setExplanation] = useState(null);
    const [explanationLoading, setExplanationLoading] = useState(false);

    useEffect(() => {
        fetch(`${API_BASE}/reports/extracted`)
            .then((res) => res.json())
            .then((data) => setExtractedReports(data.reports || []))
            .catch((err) => {
                console.error('Failed to load extracted reports:', err);
                setError('Could not load Step 1 extraction results.');
            })
            .finally(() => setLoadingExtracted(false));

        fetch(`${API_BASE}/reports/final`)
            .then((res) => res.json())
            .then((data) => {
                if (data.error) {
                    setFinalReport(null);
                } else {
                    setFinalReport(data);
                }
            })
            .catch((err) => {
                console.error('Failed to load final report:', err);
                setError('Could not load the final correlated report.');
            })
            .finally(() => setLoadingFinal(false));
    }, []);

    // Triggers a browser download of the final report in the given format,
    // via the backend endpoint that serves the raw file with the correct
    // Content-Disposition header
    const handleDownload = (format) => {
        window.open(`${API_BASE}/reports/final/download?format=${format}`, '_blank');
    };

    // Opens the explanation panel for a specific entity value and fetches
    // its explanation from the backend. Clicking the same entity again
    // closes the panel instead of re-fetching.
    const handleEntityClick = (category, value) => {
        if (selectedEntity && selectedEntity.category === category && selectedEntity.value === value) {
            setSelectedEntity(null);
            setExplanation(null);
            return;
        }

        setSelectedEntity({ category, value });
        setExplanation(null);
        setExplanationLoading(true);

        fetch(`${API_BASE}/explain?category=${encodeURIComponent(category)}&value=${encodeURIComponent(value)}`)
            .then((res) => res.json())
            .then((data) => setExplanation(data))
            .catch((err) => {
                console.error('Failed to load explanation:', err);
                setExplanation({ error: 'Could not load an explanation for this entity.' });
            })
            .finally(() => setExplanationLoading(false));
    };

    const renderExplanationContent = () => {
        if (explanationLoading) {
            return <p className="explanation-loading">Loading explanation...</p>;
        }
        if (!explanation) {
            return null;
        }
        if (explanation.error) {
            return <p className="explanation-empty">{explanation.error}</p>;
        }
        if (explanation.found === false) {
            return (
                <p className="explanation-empty">
                    No entry found for this value in the local knowledge base.
                    {explanation.external_url && (
                        <>
                            {' '}
                            <a href={explanation.external_url} target="_blank" rel="noopener noreferrer">
                                View on the external reference source
                            </a>
                            .
                        </>
                    )}
                </p>
            );
        }

        // Actor result
        if (explanation.canonical_name) {
            return (
                <div className="explanation-body">
                    <div className="explanation-field">
                        <span className="explanation-field-label">Canonical name</span>
                        <span>{explanation.canonical_name}</span>
                    </div>
                    {explanation.country && (
                        <div className="explanation-field">
                            <span className="explanation-field-label">Country</span>
                            <span>{explanation.country}</span>
                        </div>
                    )}
                    {explanation.motivation && (
                        <div className="explanation-field">
                            <span className="explanation-field-label">Motivation</span>
                            <span>{explanation.motivation}</span>
                        </div>
                    )}
                    {explanation.aliases && explanation.aliases.length > 0 && (
                        <div className="explanation-field">
                            <span className="explanation-field-label">Known aliases</span>
                            <span>{explanation.aliases.join(', ')}</span>
                        </div>
                    )}
                    {explanation.notes && <p className="explanation-notes">{explanation.notes}</p>}
                </div>
            );
        }

        // TTP result
        if (explanation.ttp_code) {
            return (
                <div className="explanation-body">
                    <div className="explanation-field">
                        <span className="explanation-field-label">Technique</span>
                        <span>{explanation.ttp_code}</span>
                    </div>
                    {explanation.description && <p className="explanation-notes">{explanation.description}</p>}
                    {explanation.mitre_url && (
                        <a href={explanation.mitre_url} target="_blank" rel="noopener noreferrer" className="explanation-link">
                            View on MITRE ATT&CK
                        </a>
                    )}
                </div>
            );
        }

        // Curated IOC example
        if (explanation.curated_context) {
            return (
                <div className="explanation-body">
                    <p className="explanation-notes">{explanation.curated_context}</p>
                    {explanation.source_article && (
                        <div className="explanation-field">
                            <span className="explanation-field-label">Source</span>
                            <span>{explanation.source_article}</span>
                        </div>
                    )}
                </div>
            );
        }

        // Generic category explanation (indicators with no per-value definition)
        if (explanation.generic_explanation) {
            return (
                <div className="explanation-body">
                    <p className="explanation-notes">{explanation.generic_explanation}</p>
                    {explanation.note && <p className="explanation-caveat">{explanation.note}</p>}
                </div>
            );
        }

        return <p className="explanation-empty">No explanation available for this entity.</p>;
    };

    return (
        <div className="reports-page">
            <div className="page-content">
                <h1>Reports</h1>
                <p className="subtitle">Extraction results and correlated threat intelligence output</p>

                {error && <div className="page-error">{error}</div>}

                {/* BLOCK 1: STEP 1 RAW EXTRACTIONS */}
                <section className="report-block">
                    <h2>Extraction results (Step 1)</h2>
                    <p className="block-subtitle">
                        Raw indicators extracted from each processed document, before correlation.
                    </p>

                    {loadingExtracted ? (
                        <div className="loading">Loading extraction results...</div>
                    ) : extractedReports.length === 0 ? (
                        <div className="empty-state">No extraction results yet. Run the pipeline first.</div>
                    ) : (
                        <div className="extraction-list">
                            {extractedReports.map((report) => (
                                <div className="extraction-card" key={report.source_document}>
                                    <div className="extraction-card-header">
                                        <span className="extraction-doc-name">{report.source_document}</span>
                                        <span className="extraction-timestamp">{report.extraction_timestamp}</span>
                                    </div>

                                    <div className="entity-groups">
                                        {ENTITY_FIELDS.map(({ field, category, label }) => {
                                            const values = report.data ? report.data[field] : null;
                                            if (!values || values.length === 0) {
                                                return null;
                                            }
                                            return (
                                                <div className="entity-group" key={field}>
                                                    <span className="entity-group-label">{label}</span>
                                                    <div className="entity-chip-row">
                                                        {values.map((value) => (
                                                            <button
                                                                key={value}
                                                                type="button"
                                                                className={`entity-chip ${selectedEntity &&
                                                                        selectedEntity.category === category &&
                                                                        selectedEntity.value === value
                                                                        ? 'active'
                                                                        : ''
                                                                    }`}
                                                                onClick={() => handleEntityClick(category, value)}
                                                            >
                                                                {value}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </section>

                {/* EXPLANATION PANEL */}
                {/* Rendered right after Block 1 so it sits close to the
                    entities that trigger it, regardless of which block
                    the click came from. */}
                {selectedEntity && (
                    <section className="explanation-panel">
                        <div className="explanation-panel-header">
                            <span className="explanation-panel-title">{selectedEntity.value}</span>
                            <button
                                type="button"
                                className="explanation-close"
                                onClick={() => {
                                    setSelectedEntity(null);
                                    setExplanation(null);
                                }}
                            >
                                Close
                            </button>
                        </div>
                        {renderExplanationContent()}
                    </section>
                )}

                {/* BLOCK 2: FINAL CORRELATED REPORT */}
                <section className="report-block">
                    <h2>Final report (Step 3)</h2>
                    <p className="block-subtitle">
                        Correlated findings across all processed documents, with the computed threat severity.
                    </p>

                    {loadingFinal ? (
                        <div className="loading">Loading final report...</div>
                    ) : !finalReport ? (
                        <div className="empty-state">No final report available yet. Run the pipeline first.</div>
                    ) : (
                        <div className="final-report-card">
                            <div className="final-report-summary">
                                <div
                                    className={`severity-badge severity-${finalReport.summary.overall_threat_level.toLowerCase()}`}
                                >
                                    {SEVERITY_LABELS[finalReport.summary.overall_threat_level] ||
                                        finalReport.summary.overall_threat_level}
                                </div>
                                <div className="final-report-counts">
                                    <div className="count-item">
                                        <span className="count-value">{finalReport.summary.total_exact_matches}</span>
                                        <span className="count-label">Exact IOC matches</span>
                                    </div>
                                    <div className="count-item">
                                        <span className="count-value">
                                            {finalReport.summary.total_actor_alias_matches}
                                        </span>
                                        <span className="count-label">Actor alias matches</span>
                                    </div>
                                    <div className="count-item">
                                        <span className="count-value">
                                            {finalReport.summary.total_semantic_matches}
                                        </span>
                                        <span className="count-label">Semantic correlations</span>
                                    </div>
                                </div>
                            </div>

                            <div className="download-row">
                                <button type="button" className="btn-outline" onClick={() => handleDownload('json')}>
                                    Download JSON
                                </button>
                                <button type="button" className="btn-outline" onClick={() => handleDownload('md')}>
                                    Download Markdown
                                </button>
                            </div>

                            <pre className="final-report-details">
                                {JSON.stringify(finalReport.details, null, 2)}
                            </pre>
                        </div>
                    )}
                </section>
            </div>
        </div>
    );
};

export default ReportsPage;