from sphinx.application import Sphinx
from sphinx.util import logging
import json
import os

logger = logging.getLogger(__name__)

def setup(app: Sphinx):
    # Config setup (unchanged)
    app.add_config_value('algolia_app_id', os.getenv('ALGOLIA_APP_ID', 'dev_app_id'), 'html')
    app.add_config_value('algolia_api_key', os.getenv('ALGOLIA_API_KEY', 'dev_api_key'), 'html')
    app.add_config_value('algolia_indices', os.getenv('ALGOLIA_INDICES', 'in,through,out').split(','), 'html')
    app.add_config_value('algolia_index_prefix', os.getenv('ALGOLIA_INDEX_PREFIX', 'red_'), 'html')

    # 1. Early script injection (for all pages)
    def inject_config_script(app):
        config = {
            "app_id": app.config.algolia_app_id,
            "api_key": app.config.algolia_api_key,
            "indices": app.config.algolia_indices,
            "index_prefix": app.config.algolia_index_prefix
        }
        app.add_js_file(
            None,
            body=f"""
            <script id="algolia-config" type="application/json">
                {json.dumps(config, indent=4)}
            </script>
            """,
            priority=200  # Early load
        )
        logger.verbose(f"Injected Algolia config: {config['app_id']}")  # Debug

    # 2. Disable Furo search
    def disable_furo_search(app, pagename, templatename, context, doctree):
        if context:
            context["generate_search_index"] = False

    # Connect events
    app.connect('builder-inited', inject_config_script)  # Single injection point
    app.connect('html-page-context', disable_furo_search)

    # Add Algolia JS/CSS
    app.add_js_file('js/algolia.js', priority=300)  # Loads after config
    app.add_css_file('css/algolia.css')

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
