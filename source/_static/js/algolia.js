console.log("Algolia JS loaded successfully");

document.addEventListener('DOMContentLoaded', function() {
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

    console.log('Algolia search initialized');

    // Get DOM elements
    const searchInput = document.querySelector('.sidebar-search-container input');
    if (!searchInput) {
        console.warn('Search input not found');
        return;
    }

    // Create results container
    const searchResults = document.createElement('div');
    searchResults.className = 'algolia-results-container';
    searchResults.style.display = 'none';
    searchInput.parentNode.appendChild(searchResults);

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

        if (query.length < 2) {
            searchResults.style.display = 'none';
            searchResults.innerHTML = '';
            return;
        }

        try {
            // Load Algolia client if not already loaded
            if (!window.algoliasearch) {
                await new Promise((resolve, reject) => {
                    const script = document.createElement('script');
                    script.src = 'https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3/dist/algoliasearch-lite.umd.js';
                    script.onload = resolve;
                    script.onerror = reject;
                    document.head.appendChild(script);
                });
            }

            const client = window.algoliasearch(config.app_id, config.api_key);

            // Search all indices
            const searches = config.indices.map(index => {
                return client.initIndex(`${config.index_prefix}${index}`)
                    .search(query, {
                        hitsPerPage: 5,
                        attributesToRetrieve: ['u', 't', 'c'],
                        attributesToHighlight: ['t', 'c']
                    });
            });

            const results = await Promise.all(searches);
            const hits = results.flatMap(r => r.hits.map(hit => ({
                url: hit.u || '#',
                title: hit._highlightResult?.t?.value || hit.t || 'Untitled',
                content: hit._highlightResult?.c?.value || hit.c || ''
            })));

            displayResults(hits, query);
        } catch (error) {
            console.error('Search error:', error);
            displayError(query);
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

    // Display error
    function displayError(query) {
        searchResults.innerHTML = `
            <div class="error">
                Search temporarily unavailable. Please try again later.
            </div>
        `;
        searchResults.style.display = 'block';
    }

    // Basic HTML sanitization
    function sanitizeHTML(str) {
        return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Event listener
    searchInput.addEventListener('input', (e) => {
        performSearch(e.target.value);
    });

    // Handle Enter key
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && searchInput.value.trim()) {
            const firstResult = searchResults.querySelector('.result');
            if (firstResult) {
                window.location.href = firstResult.getAttribute('href');
            }
        }
    });
});
