// Wrap the entire implementation in a DOMContentLoaded event listener
document.addEventListener('DOMContentLoaded', function() {
    (function() {
        // Configuration - MODIFY THIS SECTION
        const configElement = document.getElementById('algolia-config');
        if (!configElement) {
            console.error('Algolia config element not found - check if script is placed correctly');
            return;
        }

        let config;
        try {
            config = JSON.parse(configElement.textContent.trim());
        } catch (e) {
            console.error('Failed to parse Algolia config:', e, '\nConfig content:', configElement.textContent);
            return;
        }

        // Validate minimum required config
        if (!config.app_id || !config.api_key || !config.indices) {
            console.error('Invalid Algolia config - missing required fields');
            return;
        }

        const isDevMode = config.app_id.includes('dev_') || config.api_key.includes('dev_');

        // Initial debug log
        console.log("Algolia Search Initialized", {
            mode: isDevMode ? "DEVELOPMENT" : "PRODUCTION",
            config: {
                ...config,
                api_key: "***REDACTED***"
            },
            ready: document.readyState
        });

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

    // Display results
    function displayResults(results, query) {
        if (!results || !results.length) {
            searchResults.innerHTML = `
                <div class="algolia-no-results">
                    No results found for "${query}"
                </div>
            `;
            searchResults.style.display = 'block';
            return;
        }

        let html = '<div class="algolia-results-list">';
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
            console.log("Dev mode - using mock results");
            displayResults(mockSearch(query), query);
            return;
        }

        // Load Algolia client if not already loaded
        if (!window.algoliasearch) {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3/dist/algoliasearch-lite.umd.js';
            script.onload = () => {
                console.log("Algolia client loaded");
                performAlgoliaSearch(query);
            };
            script.onerror = () => {
                console.error("Failed to load Algolia client");
                displayResults([{
                    url: '#',
                    title: 'Error',
                    content: 'Failed to load Algolia client'
                }], query);
            };
            document.head.appendChild(script);
        } else {
            performAlgoliaSearch(query);
        }
    }

    // Perform actual Algolia search
    function performAlgoliaSearch(query) {
        console.log("Performing search for:", query);
        const client = window.algoliasearch(config.app_id, config.api_key);

        console.log("Searching indices:", config.indices.map(i => config.index_prefix + i));

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
            console.log("Search responses received", responses);
            const hits = responses.flatMap(r =>
                r.hits.map(hit => ({
                    url: hit.u || '#',
                    title: hit.t || 'Untitled',
                    content: hit._snippetResult?.c?.value || hit.c || ''
                }))
            );
            return hits;
        })
        .then(hits => {
            return hits.sort((a, b) => {
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
            console.error("Algolia search error:", error);
            displayResults([{
                url: '#',
                title: 'Search Error',
                content: 'An error occurred while searching'
            }], query);
            return [];
        });
    }

    // Set up event listeners
    window.addEventListener('load', () => {
       if (searchInput) {
            searchInput.addEventListener('input', debounce((e) => {
                handleSearch(e.target.value.trim());
            }, 300));
        } else {
            console.warn('Algolia search input element not found');
        }

    })();
});
