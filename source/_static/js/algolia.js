(function() {
    // Configuration
    const configElement = document.getElementById('algolia-config');
    if (!configElement) return;
    
    const config = JSON.parse(configElement.textContent);
    const isDevMode = config.app_id.includes('dev_') || config.api_key.includes('dev_');
    
    // Debug information object
    const debugInfo = {
        mode: isDevMode ? 'DEVELOPMENT' : 'PRODUCTION',
        config: config,
        lastSearch: null,
        lastResponse: null,
        lastError: null,
        environment: {
            algoliaClientLoaded: false,
            userAgent: navigator.userAgent,
            online: navigator.onLine,
            windowLoaded: false
        }
    };

    // DOM Elements
    const searchInput = document.querySelector('.sidebar-search-container input');
    const searchResults = document.createElement('div');
    searchResults.className = 'algolia-results-container';

    // Insert results container
    if (searchInput && searchInput.parentNode) {
        searchInput.parentNode.appendChild(searchResults);
    }

    // Debounce function
    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // Mock search for development
    function mockSearch(query) {
        return [
            {
                url: 'index.html',
                title: 'Mock Result for "' + query + '"',
                content: 'This is a mock search result. In production, you would see real results from Algolia.'
            },
            {
                url: 'other.html',
                title: 'Another Mock Result',
                content: 'This demonstrates what search results will look like.'
            }
        ];
    }

    // Render debug information
    function renderDebugInfo() {
        return `
            <div class="algolia-debug-info">
                <h4>Debug Information</h4>
                <p><strong>Mode:</strong> ${debugInfo.mode}</p>
                <p><strong>Last Query:</strong> ${debugInfo.lastSearch || 'None'}</p>
                <p><strong>Config:</strong></p>
                <pre>${JSON.stringify(debugInfo.config, null, 2)}</pre>
                ${debugInfo.lastError ? `
                    <p><strong>Last Error:</strong></p>
                    <pre class="algolia-error">${JSON.stringify(debugInfo.lastError, null, 2)}</pre>
                ` : ''}
                <p><strong>Environment:</strong></p>
                <pre>${JSON.stringify(debugInfo.environment, null, 2)}</pre>
            </div>
        `;
    }

    // Display results with debug info
    function displayResults(results, query) {
        debugInfo.lastSearch = query;
        debugInfo.lastResponse = results;

        if (!results || !results.length) {
            searchResults.innerHTML = `
                <div class="algolia-no-results">
                    No results found for "${query}"
                    ${renderDebugInfo()}
                </div>
            `;
            searchResults.style.display = 'block';
            return;
        }

        let html = `
            <div class="algolia-results-list">
                <div class="algolia-debug-header">
                    Search mode: ${debugInfo.mode}
                    ${renderDebugInfo()}
                </div>
        `;

        results.forEach(result => {
            html += `
                <a href="${result.url}" class="algolia-result-item">
                    <div class="algolia-result-title">${result.title}</div>
                    <div class="algolia-result-content">${result.content}</div>
                </a>
            `;
        });
        html += '</div>';

        searchResults.innerHTML = html;
        searchResults.style.display = 'block';
    }

    // Handle search
    function handleSearch(query) {
        if (!query || query.length < 2) {
            searchResults.style.display = 'none';
            return;
        }

        if (isDevMode) {
            displayResults(mockSearch(query), query);
            return;
        }

        // Load Algolia client if not already loaded
        if (!window.algoliasearch) {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3/dist/algoliasearch-lite.umd.js';
            script.onload = () => {
                debugInfo.environment.algoliaClientLoaded = true;
                performAlgoliaSearch(query);
            };
            script.onerror = () => {
                debugInfo.lastError = {
                    message: 'Failed to load Algolia client',
                    type: 'script-load-error'
                };
                displayResults([{
                    url: '#',
                    title: 'Error',
                    content: 'Failed to load Algolia client'
                }], query);
            };
            document.head.appendChild(script);
        } else {
            debugInfo.environment.algoliaClientLoaded = true;
            performAlgoliaSearch(query);
        }
    }

    // Perform actual Algolia search
    function performAlgoliaSearch(query) {
        const client = window.algoliasearch(config.app_id, config.api_key);
        debugInfo.environment.algoliaClientLoaded = true;

        // Debug: Log which indices we're searching
        console.log('Searching indices:', config.indices.map(i => config.index_prefix + i));

        return Promise.all(config.indices.map(index => {
            const indexName = `${config.index_prefix}${index}`;
            return client.initIndex(indexName).search(query, {
                hitsPerPage: 10,
                attributesToRetrieve: ['u', 't', 'c'],
                attributesToSnippet: ['c:40'],
                restrictSearchableAttributes: ['t', 'c'],
                responseFields: ['hits', 'query'],
                advancedSyntax: true
            });
        }))
        .then(responses => {
            // Debug: Show raw response
            console.log('Raw Algolia response:', responses);

            const hits = responses.flatMap(r =>
                r.hits.map(hit => ({
                    url: hit.u || '#',
                    title: hit.t || 'Untitled',
                    content: hit._snippetResult?.c?.value || hit.c || '',
                    _rankingInfo: hit._rankingInfo // Preserve ranking info for debugging
                }))
            );

            // Debug: Show processed hits
            console.log('Processed hits:', hits);
            return hits;
        })
        .then(hits => {
            // Sort hits by relevance across all indices
            return hits.sort((a, b) => {
                // Algolia returns _rankingInfo in production
                if (a._rankingInfo && b._rankingInfo) {
                    return b._rankingInfo.userScore - a._rankingInfo.userScore;
                }
                return 0;
            });
        })
        .then(sortedHits => {
            displayResults(sortedHits, query);
            return sortedHits;
        })
        .catch(error => {
            console.error('Algolia error:', error);
            debugInfo.lastError = {
                message: error.message,
                stack: error.stack,
                name: error.name
            };
            displayResults([], query);
            return [];
        });
    }

    // Set up event listeners
    window.addEventListener('load', () => {
        debugInfo.environment.windowLoaded = true;
        if (searchInput) {
            searchInput.addEventListener('input', debounce((e) => {
                handleSearch(e.target.value.trim());
            }, 300));
        }
    });

    // Initial debug log
    console.log('Algolia search initialized:', debugInfo);
})();
