from sphinx.application import Sphinx
from sphinx.util import logging
from dotenv import load_dotenv
import json
import os

logger = logging.getLogger(__name__)


def setup(app: Sphinx):
    # Load .env from the source directory (where conf.py is)
    env_path = os.path.join(app.srcdir, '.env')  # Points to source/.env

    print(f"[DEBUG] Looking for .env at: {env_path}")  # Debug line

    if os.path.exists(env_path):
        load_dotenv(env_path)
        print("[DEBUG] .env loaded successfully!")
        print(f"ALGOLIA_APP_ID={os.getenv('ALGOLIA_APP_ID')}")  # Verify
    else:
        print(f"[ERROR] .env not found at: {env_path}")

    # Set default values if not in environment
    app.add_config_value('algolia_app_id', os.getenv('ALGOLIA_APP_ID', 'dev_app_id'), 'html')
    app.add_config_value('algolia_api_key', os.getenv('ALGOLIA_API_KEY', 'dev_api_key'), 'html')
    app.add_config_value('algolia_indices', os.getenv('ALGOLIA_INDICES', 'in,through,out').split(','), 'html')
    app.add_config_value('algolia_index_prefix', os.getenv('ALGOLIA_INDEX_PREFIX', 'red_'), 'html')

    def inject_config_script(app):
        # Only inject in production or if we have valid credentials
        if (app.config.algolia_app_id and app.config.algolia_app_id != 'dev_app_id' and
                app.config.algolia_api_key and app.config.algolia_api_key != 'dev_api_key'):

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
                    {json.dumps(config)}
                </script>
                """,
                priority=200
            )
            logger.info("Injected Algolia search configuration")
        else:
            logger.warning("Algolia search disabled - missing or invalid credentials")

    def disable_furo_search(app, pagename, templatename, context, doctree):
        if context:
            context["generate_search_index"] = False
            # Also disable other search-related features
            context["display_global_toc"] = False
            context["globaltoc_collapse"] = False

    # Connect events
    app.connect('builder-inited', inject_config_script)
    app.connect('html-page-context', disable_furo_search)

    # Add Algolia JS/CSS only if we have valid credentials
    if (app.config.algolia_app_id and app.config.algolia_app_id != 'dev_app_id' and
            app.config.algolia_api_key and app.config.algolia_api_key != 'dev_api_key'):
        app.add_js_file('js/algolia.js', priority=300)
        app.add_css_file('css/algolia.css')

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
