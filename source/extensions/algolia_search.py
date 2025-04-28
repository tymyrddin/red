from sphinx.application import Sphinx
from sphinx.util import logging
from dotenv import load_dotenv
from pathlib import Path
import json
import os

logger = logging.getLogger(__name__)

def setup(app: Sphinx):
    # Load environment variables
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(f"Loaded .env from: {env_path}")

    # Configuration setup
    app.add_config_value('algolia_app_id', os.getenv('ALGOLIA_APP_ID', 'dev_app_id'), 'html')
    app.add_config_value('algolia_api_key', os.getenv('ALGOLIA_API_KEY', 'dev_api_key'), 'html')
    app.add_config_value('algolia_indices', os.getenv('ALGOLIA_INDICES', 'in,through,out').split(','), 'html')
    app.add_config_value('algolia_index_prefix', os.getenv('ALGOLIA_INDEX_PREFIX', 'red_'), 'html')

    def inject_config_script(app):
        if all([
            app.config.algolia_app_id,
            app.config.algolia_app_id != 'dev_app_id',
            app.config.algolia_api_key,
            app.config.algolia_api_key != 'dev_api_key'
        ]):
            config = {
                "app_id": app.config.algolia_app_id,
                "api_key": app.config.algolia_api_key,
                "indices": app.config.algolia_indices,
                "index_prefix": app.config.algolia_index_prefix
            }

            # Proper script injection
            app.add_js_file(
                None,  # No external file
                body=json.dumps(config, indent=2),  # Just the JSON content
                id="algolia-config",  # Sets the HTML id attribute
                type="application/json",  # Critical for JSON scripts
                priority=200
            )
            logger.info("Algolia configuration injected")

    def disable_furo_search(app, pagename, templatename, context, doctree):
        """Completely disable Furo's search functionality"""
        if context:
            # Disable search index generation
            context["generate_search_index"] = False

            # Remove Furo's search assets if they exist
            for asset_type in ["css_files", "js_files"]:
                if asset_type in context:
                    context[asset_type] = [
                        f for f in context[asset_type]
                        if not any(search_term in f.lower()
                                   for search_term in ["searchbox", "searchtools"])
                    ]

    # Connect events
    app.connect('builder-inited', inject_config_script)
    app.connect('html-page-context', disable_furo_search)

    # Add Algolia assets if configured
    if all([
        app.config.algolia_app_id,
        app.config.algolia_app_id != 'dev_app_id',
        app.config.algolia_api_key,
        app.config.algolia_api_key != 'dev_api_key'
    ]):
        app.add_js_file('js/algolia.js', priority=300)
        app.add_css_file('css/algolia.css')

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }