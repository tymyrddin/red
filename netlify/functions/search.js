const algoliasearch = require('algoliasearch');

exports.handler = async (event, context) => {
    try {
        const { query, index } = JSON.parse(event.body);
        const client = algoliasearch(process.env.ALGOLIA_APP_ID, process.env.ALGOLIA_API_KEY);
        const searchIndex = client.initIndex(`${process.env.ALGOLIA_INDEX_PREFIX}${index}`);

        const results = await searchIndex.search(query, {
            hitsPerPage: 10,
            attributesToRetrieve: ['*'],
            attributesToSnippet: ['content:20'],
            snippetEllipsisText: '…',
            enablePersonalization: true,
            enableReRanking: true,
        });

        return {
            statusCode: 200,
            body: JSON.stringify(results),
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message }),
        };
    }
};