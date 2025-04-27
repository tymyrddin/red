from sphinx.application import Sphinx
from sphinx.util import logging
import json
import os

logger = logging.getLogger(__name__)


def setup(app: Sphinx):
    # Get configuration from environment with safe defaults
    app.add_config_value('algolia_app_id', os.getenv('ALGOLIA_APP_ID', 'dev_app_id'), 'html')
    app.add_config_value('algolia_api_key', os.getenv('ALGOLIA_API_KEY', 'dev_api_key'), 'html')
    app.add_config_value('algolia_indices', os.getenv('ALGOLIA_INDICES', 'in,through,out').split(','), 'html')
    app.add_config_value('algolia_index_prefix', os.getenv('ALGOLIA_INDEX_PREFIX', 'red_'), 'html')

    def add_algolia_context(app, pagename, templatename, context, doctree):
        # Add configuration data
        context['algolia_config'] = {
            'app_id': app.config.algolia_app_id,
            'api_key': app.config.algolia_api_key,
            'indices': app.config.algolia_indices,
            'index_prefix': app.config.algolia_index_prefix
        }

        # Disable Furo's default search
        context["generate_search_index"] = False

    app.connect('html-page-context', add_algolia_context)

    # Add our JS after Furo's JS
    app.add_js_file('js/algolia.js', priority=200)

    # Add our CSS
    app.add_css_file('css/algolia.css')

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
