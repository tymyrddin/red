console.log("Algolia JS loaded successfully");

document.addEventListener('DOMContentLoaded', function() {
    // 1. Safely get configuration
    const configElement = document.getElementById('algolia-config');
    if (!configElement) {
        console.error('Algolia config element not found');
        return;
    }

    let config;
    try {
        config = JSON.parse(configElement.textContent.trim());
    } catch (e) {
        console.error('Failed to parse Algolia config:', e);
        return;
    }

    // 2. Validate configuration
    if (!config.app_id || !config.api_key || !config.indices) {
        console.error('Invalid Algolia configuration');
        return;
    }

    const isDevMode = config.app_id.includes('dev_');
    console.log('Algolia initialized', { mode: isDevMode ? 'DEV' : 'PROD' });

    // 3. DOM Elements
    const searchInput = document.querySelector('.sidebar-search-container input');
    if (!searchInput) {
        console.warn('Search input element not found');
        return;
    }

    const searchResults = document.createElement('div');
    searchResults.className = 'algolia-results-container';
    searchInput.parentNode.appendChild(searchResults);

    // 4. Debounce function
    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // 5. Mock search (dev only)
    function mockSearch(query) {
        return [{
            url: 'index.html',
            title: 'Mock: ' + query,
            content: 'Sample result for development'
        }];
    }

    // 6. Display results
    function displayResults(results, query) {
        if (!results || !results.length) {
            searchResults.innerHTML = `<div class="no-results">No results for "${query}"</div>`;
            return;
        }
        
        searchResults.innerHTML = results.map(result => `
            <a href="${result.url}" class="result">
                <h3>${result.title}</h3>
                <p>${result.content}</p>
            </a>
        `).join('');
    }

    // 7. Handle search
    function handleSearch(query) {
        if (!query || query.length < 2) {
            searchResults.style.display = 'none';
            return;
        }

        if (isDevMode) {
            displayResults(mockSearch(query), query);
            return;
        }

        if (!window.algoliasearch) {
            loadAlgoliaClient(query);
        } else {
            performSearch(query);
        }
    }

    // 8. Load Algolia client
    function loadAlgoliaClient(query) {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3/dist/algoliasearch-lite.umd.js';
        script.onload = () => performSearch(query);
        script.onerror = () => console.error('Failed to load Algolia client');
        document.head.appendChild(script);
    }

    // 9. Perform actual search
    function performSearch(query) {
        const client = window.algoliasearch(config.app_id, config.api_key);
        
        Promise.all(config.indices.map(index => {
            return client.initIndex(`${config.index_prefix}${index}`)
                .search(query, {
                    hitsPerPage: 5,
                    attributesToRetrieve: ['u', 't', 'c']
                });
        }))
        .then(responses => {
            const hits = responses.flatMap(r => r.hits.map(hit => ({
                url: hit.u || '#',
                title: hit.t || 'Untitled',
                content: hit.c || ''
            })));
            displayResults(hits, query);
        })
        .catch(error => {
            console.error('Search failed:', error);
            displayResults([], query);
        });
    }

    // 10. Initialize
    searchInput.addEventListener('input', debounce(e => {
        handleSearch(e.target.value.trim());
    }, 300));
});

// Last line of algolia.js
console.log("Algolia JS fully executed");
