/* 
useState: Used to create component states.
A state is a special variable that, when changed, automatically triggers a refresh of the relevant part of the UI.

useEffect: Used to execute code when something happens
*/
import React, { useState, useEffect } from 'react';
import './SourcesPage.css';

/* Create a page where the user can:
    search for cybersecurity articles;
    filter RSS sources;
    choose a time range;
    view the results;
    select multiple articles;
    prepare them for a subsequent analysis process.
*/
const SourcesPage = () => { // Everything contained within this function represents the page's logic and interface.

    // It stores what the user types in the search bar
    const [searchTerm, setSearchTerm] = useState('');
    // Contains the sources selected by the user
    const [selectedSources, setSelectedSources] = useState([]);
    // Save the selected period. e.g. 30 days
    const [timeRange, setTimeRange] = useState('30d');
    // Contains the articles returned by the backend
    const [results, setResults] = useState([]);
    // Indicates whether the page is waiting for a response
    const [loading, setLoading] = useState(false);
    // Contains the complete list of RSS sources
    const [allSources, setAllSources] = useState([]);
    /* STATES FOR MULTIPLE SELECTION 
    Indicates whether the user is in the following mode:
    normal or multiple selection */
    const [selectionMode, setSelectionMode] = useState(false);
    // Contains the indices of the selected articles
    const [selectedArticles, setSelectedArticles] = useState([]);
    // Creates an array used by the HTML select element. The value is sent to the backend
    const timeRanges = [
        { label: 'Last 24h', value: '24h' },
        { label: 'Last 7 days', value: '7d' },
        { label: 'Last 30 days', value: '30d' },
        { label: 'Last 90 days', value: '90d' },
        { label: 'All time', value: 'all' },
    ];

    // This block executes when the page is opened
    useEffect(() => {
        /* The connection is established via HTTP calls (/api/sources/list):
        The backend returns JSON, and React automatically updates the page. */
        fetch('http://127.0.0.1:8000/api/sources/list')
            // Converts the HTTP response to JSON
            .then(res => res.json())
            // Converts the HTTP response to JSON
            .then(data => setAllSources(data.sources || []))
            .catch(err => console.error('Errore nel caricare la lista fonti:', err));

        /* Enables loading.
        Load the actual articles (slow, performs live feed fetches) */
        setLoading(true);
        // Calls the other Django endpoint. This retrieves articles from RSS feeds
        fetch('http://127.0.0.1:8000/api/sources/search')
            .then(res => res.json())
            .then(data => {
                // Saves the received articles
                setResults(data.results || []);
            })
            .catch(err => {
                console.error('Errore nel caricare le fonti:', err);
            })
            // At the end of the request, disable loading
            .finally(() => setLoading(false));
    }, []);

    // SOURCE SEARCH FUNCTION

    // Called when the user presses the button: Search
    const handleSearch = async () => {
        setLoading(true);  // Enable loading state

        try {
            // Create URL parameters. Used to dynamically construct the HTTP query
            const params = new URLSearchParams();
            // If the user has entered something, it is added
            if (searchTerm) params.append('q', searchTerm);
            if (selectedSources.length > 0) {
                // Adding sources
                params.append('sources', selectedSources.join(','));
            }
            params.append('time_range', timeRange);

            // Backend call. Sends the request with the filters
            const response = await fetch(`http://127.0.0.1:8000/api/sources/search?${params}`);
            const data = await response.json();

            setResults(data.results || []);
            // Reset the selected articles when a new search is performed
            setSelectedArticles([]);
        } catch (error) {
            console.error('Search failed:', error);
            alert('Error: backend not available. Make sure Django is running.');
        } finally {
            setLoading(false);
        }
    };

    // Handles the selection/deselection of sources.
    /* 
    If you click: Talos --> it adds the source.
    If you uncheck it: Talos --> it removes it. 
    */
    const toggleSource = (source) => {
        setSelectedSources(prev => {
            if (prev.includes(source)) {
                return prev.filter(s => s !== source);
            } else {
                return [...prev, source];
            }
        });
    };

    /* 
    Resets the page to its initial state. Resets:
        search;
        sources;
        time period;
        selections.
    Then reloads the articles.
    */
    const handleReset = () => {
        setSearchTerm('');
        setSelectedSources([]);
        setTimeRange('30d');
        setSelectedArticles([]);
        fetch('http://127.0.0.1:8000/api/sources/search')
            .then(res => res.json())
            .then(data => setResults(data.results || []))
            .catch(err => console.error('Reset failed:', err));
    };

    // Handling article selection
    /*
    Activates/deactivates the selection mode. When deactivated, it resets the selected articles
    Switches from: Select Articles
    to: Close Selection
    */
    const toggleSelectionMode = () => {
        setSelectionMode(!selectionMode);
        if (selectionMode) {
            setSelectedArticles([]); // Reset selected articles when exiting selection mode
        }
    };

    // Selection of individual articles 
    // If the article is already selected, it is deselected; otherwise, it is selected
    const toggleArticleSelection = (index) => {
        setSelectedArticles(prev => {
            if (prev.includes(index)) {
                return prev.filter(i => i !== index);
            } else {
                return [...prev, index];
            }
        });
    };

    // Select all articles. Takes all indices
    const selectAllArticles = () => {
        const allIndices = results.map((_, index) => index);
        setSelectedArticles(allIndices);
    };

    // Deselect all articles. Clears the array of selected indices
    const deselectAllArticles = () => {
        setSelectedArticles([]);
    };

    // Process Selected Articles 
    // Handles the button: Process
    const processSelectedArticles = () => {
        if (selectedArticles.length === 0) {
            alert('Select at least one item to process.');
            return;
        }
        // It takes the selected articles and saves them
        const selected = selectedArticles.map(index => results[index]);
        console.log('Items selected for processing:', selected);

        // ou can make the backend call to start the pipeline or pass the data to the next page
        alert(`${selected.length} article(i) selected for processing!\n\nThe details have been saved and will be processed.`);

        // Save articles in the browser
        // This allows other React pages to retrieve them.
        localStorage.setItem('selectedArticles', JSON.stringify(selected));

    };

    // This is where the graphics begin. React returns the page's HTML code.
    return (
        <div className="sources-page">
            <div className="page-content">
                <h1>Source Intelligence</h1>
                <p className="subtitle">Search and extract intelligence from cybersecurity sources</p>

                {/* Search Section */}
                <div className="search-section">
                    <div className="search-row">
                        <input
                            type="text"
                            className="search-input"
                            placeholder="Search by keyword, malware name, CVE, actor..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                        />
                        <button className="btn-primary" onClick={handleSearch}>
                            Search
                        </button>
                        <button className="btn-secondary" onClick={handleReset}>
                            Reset
                        </button>
                    </div>

                    <div className="filters-row">
                        <div className="filter-group">
                            <label>Sources</label>
                            <div className="source-checkboxes">
                                <label className="source-checkbox">
                                    <input
                                        type="checkbox"
                                        checked={selectedSources.length === 0}
                                        onChange={() => setSelectedSources([])}
                                    />
                                    All Sources
                                </label>
                                {allSources.map((source) => (
                                    <label key={source} className="source-checkbox">
                                        <input
                                            type="checkbox"
                                            checked={selectedSources.includes(source)}
                                            onChange={() => toggleSource(source)}
                                        />
                                        {source}
                                    </label>
                                ))}
                            </div>
                            <small>{selectedSources.length} source(s) selected</small>
                        </div>

                        <div className="filter-group">
                            <label>Time Range</label>
                            <select
                                className="time-select"
                                value={timeRange}
                                onChange={(e) => setTimeRange(e.target.value)}
                            >
                                {timeRanges.map((range) => (
                                    <option key={range.value} value={range.value}>
                                        {range.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                {/* Results */}
                <div className="results-section">
                    {loading ? (
                        <div className="loading">Loading articles...</div>
                    ) : (
                        <>
                            {results.length > 0 && (
                                <div className="results-header">
                                    {/* Selection Button */}
                                    <div className="results-actions-bar">
                                        <button
                                            className={`btn-selection ${selectionMode ? 'active' : ''}`}
                                            onClick={toggleSelectionMode}
                                        >
                                            {selectionMode ? 'Close Selection' : 'Select Articles'}
                                        </button>

                                        {selectionMode && (
                                            <>
                                                <button className="btn-sm btn-select-all" onClick={selectAllArticles}>
                                                    Select All
                                                </button>
                                                <button className="btn-sm btn-deselect-all" onClick={deselectAllArticles}>
                                                    Deselect All
                                                </button>
                                                <button className="btn-sm btn-process" onClick={processSelectedArticles}>
                                                    Process {selectedArticles.length > 0 ? `(${selectedArticles.length})` : ''}
                                                </button>
                                            </>
                                        )}

                                        <span className="results-count">
                                            {results.length} result(s) found
                                            {selectionMode && selectedArticles.length > 0 && (
                                                <span className="selected-count"> • {selectedArticles.length} selected</span>
                                            )}
                                        </span>
                                    </div>
                                </div>
                            )}

                            <div className="results-list">
                                {results.map((article, index) => (
                                    <div
                                        key={index}
                                        className={`result-card ${selectionMode && selectedArticles.includes(index) ? 'selected' : ''}`}
                                    >
                                        {/* Selection Checkbox (visible only in selection mode) */}
                                        {selectionMode && (
                                            <div className="result-checkbox">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedArticles.includes(index)}
                                                    onChange={() => toggleArticleSelection(index)}
                                                    id={`article-${index}`}
                                                />
                                                <label htmlFor={`article-${index}`}></label>
                                            </div>
                                        )}

                                        <div className="result-content">
                                            <div className="result-title">

                                                <span className="result-source">{article.source}</span>
                                            </div>
                                            <h3 className="result-headline">{article.title}</h3>
                                            <div className="result-meta">
                                                <span className="result-date">{article.published}</span>
                                            </div>
                                            <div className="result-url">
                                                <a href={article.url} target="_blank" rel="noopener noreferrer">
                                                    {article.url}
                                                </a>
                                            </div>
                                            <div className="result-actions">
                                                <button
                                                    className="btn-sm btn-outline"
                                                    onClick={() => window.open(article.url, '_blank')}
                                                >
                                                    Read article
                                                </button>
                                                {!selectionMode && (
                                                    <button
                                                        className="btn-sm btn-primary-sm"
                                                        onClick={() => alert(`Extraction started for:\n${article.url}`)}
                                                    >
                                                        Extract IOCs
                                                    </button>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {results.length === 0 && (
                                <div className="no-results">
                                    <p>No results found. Try adjusting your search or filters.</p>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SourcesPage;