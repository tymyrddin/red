# source/extensions/algolia_search.py
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List
from sphinx.application import Sphinx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def setup(app: Sphinx) -> Dict[str, Any]:
    """Setup Algolia search with all issues resolved."""
    # Load .env from project root
    env_path = Path(__file__).parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(f"Loaded .env from {env_path}")

    # Default indices configuration
    default_indices = ['in', 'through', 'out']  # Lowercase variable name fixed

    def get_indices() -> List[str]:
        """Get indices from env or use defaults."""
        try:
            indices = json.loads(os.getenv('ALGOLIA_INDICES', '[]'))
            return indices if indices else default_indices
        except json.JSONDecodeError:
            logger.warning("Invalid ALGOLIA_INDICES, using default indices")
            return default_indices

    # Config values with proper types
    app.add_config_value('algolia_app_id',
                         os.getenv('ALGOLIA_APP_ID', 'dev_app_id'),
                         'html')
    app.add_config_value('algolia_api_key',
                         os.getenv('ALGOLIA_API_KEY', 'dev_api_key'),
                         'html')
    app.add_config_value('algolia_indices',
                         get_indices(),
                         'html')
    app.add_config_value('algolia_index_prefix',
                         os.getenv('ALGOLIA_INDEX_PREFIX', 'red_'),
                         'html')

    def is_production_config(sphinx_app: Sphinx) -> bool:
        """Check for valid production credentials."""
        return all([
            sphinx_app.config.algolia_app_id,
            sphinx_app.config.algolia_app_id != 'dev_app_id',
            sphinx_app.config.algolia_api_key,
            sphinx_app.config.algolia_api_key != 'dev_api_key'
        ])

    def inject_config_script(sphinx_app: Sphinx) -> None:
        """Inject single Algolia config without using scripts attribute."""
        if is_production_config(sphinx_app):
            config = {
                "app_id": sphinx_app.config.algolia_app_id,
                "api_key": sphinx_app.config.algolia_api_key,
                "indices": sphinx_app.config.algolia_indices,
                "index_prefix": sphinx_app.config.algolia_index_prefix
            }
            # Add config without touching internal scripts attribute
            sphinx_app.add_js_file(
                "",  # Empty path instead of None
                body=json.dumps(config, indent=2),
                id="algolia-config",
                type="application/json",
                priority=200
            )

    def clean_search_context(sphinx_app: Sphinx, pagename: str,
                             templatename: str, context: Dict[str, Any],
                             doctree: Any) -> None:
        """Clean context using all parameters properly."""
        # Use all parameters to avoid warnings
        _ = pagename, templatename, doctree  # Explicitly mark as used

        if context and is_production_config(sphinx_app):
            context["generate_search_index"] = False

            # Clean asset lists
            for asset_type in ["css_files", "js_files", "script_files"]:  # Added script_files
                if asset_type in context:
                    seen_algolia = False
                    new_assets = []
                    for asset in context[asset_type]:
                        # Handle both string and tuple formats
                        asset_str = asset[0] if isinstance(asset, (tuple, list)) else asset
                        if 'algolia.js' in asset_str:
                            if not seen_algolia:
                                new_assets.append(asset)
                                seen_algolia = True
                        else:
                            new_assets.append(asset)
                    context[asset_type] = new_assets

    # Connect events
    app.connect('builder-inited', inject_config_script)
    app.connect('html-page-context', clean_search_context)

    # Add assets
    if is_production_config(app):
        app.add_js_file('js/algolia.js', priority=300)
        app.add_css_file('css/algolia.css')

    return {
        'version': '1.3',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
