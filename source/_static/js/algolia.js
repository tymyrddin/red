console.log("Algolia JS loaded successfully");

// Main initialization function
function initializeAlgoliaSearch(searchInput, searchResults) {
    // Check if config exists
    const configElement = document.getElementById('algolia-config');
    if (!configElement) {
        console.warn('Algolia search disabled - no configuration found');
        return;
    }

    // Parse config safely
    let config;
    try {
        config = JSON.parse(configElement.textContent);
    } catch (e) {
        console.error('Failed to parse Algolia config:', e);
        return;
    }

    // Validate config
    const requiredKeys = ['app_id', 'api_key', 'indices', 'index_prefix'];
    if (!requiredKeys.every(key => key in config)) {
        console.error('Invalid Algolia configuration - missing required keys');
        return;
    }

    console.log('Algolia search initialized with config:', {
        appId: config.app_id,
        apiKey: config.api_key ? '***REDACTED***' : 'MISSING',
        indices: config.indices,
        prefix: config.index_prefix
    });

    // Create results container if not provided
    if (!searchResults) {
        searchResults = document.createElement('div');
        searchResults.className = 'algolia-results-container';
        searchResults.style.display = 'none';
        searchInput.parentNode.appendChild(searchResults);
    }

    // Focus management
    searchInput.addEventListener('focus', () => {
        if (searchResults.innerHTML) searchResults.style.display = 'block';
    });

    document.addEventListener('click', (e) => {
        if (!searchResults.contains(e.target) && e.target !== searchInput) {
            searchResults.style.display = 'none';
        }
    });

    // Debounce function
    const debounce = (func, wait) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    };

    // Search function
    const performSearch = debounce(async (query) => {
        query = query.trim();
        console.log('Search triggered for:', query);

        if (query.length < 2) {
            searchResults.style.display = 'none';
            searchResults.innerHTML = '';
            return;
        }

        try {
            // Load Algolia client if not already loaded
            if (!window.algoliasearch) {
                console.log("Attempting to load Algolia client...");
                try {
                    await new Promise((resolve, reject) => {
                        const script = document.createElement('script');
                        script.src = 'https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3/dist/algoliasearch-lite.umd.js';
                        script.onload = () => {
                            console.log("Algolia client successfully loaded");
                            resolve();
                        };
                        script.onerror = () => {
                            console.error("Failed to load Algolia client script");
                            reject(new Error("Algolia client load failed"));
                        };
                        document.head.appendChild(script);
                    });
                } catch (err) {
                    console.error("Algolia client loading error:", err);
                    throw err;
                }
            } else {
                console.log("Algolia client already loaded");
            }

            const client = window.algoliasearch(config.app_id, config.api_key);

            // Search all indices
            const searches = config.indices.map(index => {
                const indexName = `${config.index_prefix}${index}`;
                console.log(`Searching index: ${indexName}`);
                return client.initIndex(indexName).search(query, {
                    hitsPerPage: 5,
                    attributesToRetrieve: ['u', 't', 'c'],
                    attributesToHighlight: ['t', 'c']
                });
            });

            const results = await Promise.all(searches);
            console.debug('Raw results:', results);

            if (results.some(r => !r.hits)) {
                throw new Error('Malformed response - missing hits array');
            }

            const hits = results.flatMap(r => r.hits.map(hit => ({
                url: hit.u || '#',
                title: hit._highlightResult?.t?.value || hit.t || 'Untitled',
                content: hit._highlightResult?.c?.value || hit.c || ''
            })));

            displayResults(hits, query);
        } catch (error) {
            console.error('Search error:', error);
            displayError(query, error.message);
        }
    }, 300);

    // Display results
    function displayResults(results, query) {
        if (!results.length) {
            searchResults.innerHTML = `
                <div class="no-results">
                    No results found for "${query}"
                </div>
            `;
            searchResults.style.display = 'block';
            return;
        }

        searchResults.innerHTML = results.map(result => `
            <a href="${result.url}" class="result">
                <h3>${sanitizeHTML(result.title)}</h3>
                <p>${sanitizeHTML(result.content)}</p>
            </a>
        `).join('');
        searchResults.style.display = 'block';
    }

    // Display error with details
    function displayError(query, error = '') {
        searchResults.innerHTML = `
            <div class="error">
                <p>Search error for "${query}":</p>
                ${error ? `<pre>${sanitizeHTML(error)}</pre>` : ''}
                <p>Please try again later</p>
            </div>
        `;
        searchResults.style.display = 'block';
    }

    // Basic HTML sanitization
    function sanitizeHTML(str) {
        return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Event listeners
    searchInput.addEventListener('input', (e) => {
        performSearch(e.target.value);
    });

    // Handle form submission
    const searchForm = searchInput.closest('form');
    if (searchForm) {
        searchForm.addEventListener('submit', (e) => {
            e.preventDefault();
            performSearch(searchInput.value);
        });
    }

    // Handle Enter key
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && searchInput.value.trim()) {
            const firstResult = searchResults.querySelector('.result');
            if (firstResult) {
                window.location.href = firstResult.getAttribute('href');
            }
        }
    });
}

// Initialize all search boxes on page
document.addEventListener('DOMContentLoaded', function() {
    // Navbar search (Furo theme)
    const navbarSearch = document.querySelector('.sidebar-search-container input');
    if (navbarSearch) {
        initializeAlgoliaSearch(navbarSearch);
    }

    // Search page search
    const pageSearch = document.querySelector('.search-page-container input, .search-container input');
    if (pageSearch) {
        const resultsContainer = document.querySelector('.search-results, #search-results');
        initializeAlgoliaSearch(pageSearch, resultsContainer);
    }
});