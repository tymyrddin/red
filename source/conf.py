# Configuration file for the Sphinx documentation builder.

# -- Path setup --------------------------------------------------------------
import os
import sys

sys.path.insert(0, os.path.abspath('.'))

# -- Project information -----------------------------------------------------
project = 'Red team'
copyright = '2022, Ty Myrddin'
author = 'Ty Myrddin'
release = '0.1'

# -- General configuration ---------------------------------------------------
extensions = [
    'myst_parser',
    'sphinx_markdown_tables',
    'sphinx.ext.intersphinx',
    'extensions.algolia_search',
]

source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}
templates_path = ['_templates']
exclude_patterns = []
html_use_index = False  # Disable default search

# -- HTML Output -------------------------------------------------------------
html_theme = 'furo'
html_theme_options = {
    "sidebar_hide_name": True,
    "navigation_with_keys": True,
}
html_title = "Red team"
html_logo = "img/logo.png"
html_favicon = "img/favicon.ico"
html_static_path = ['_static']
html_css_files = ['css/custom.css']
html_js_files = [
    ('algolia.js', {'async': 'async', 'data-version': '1.0.0'}),]
html_show_sphinx = False
html_show_copyright = False

# -- Intersphinx ------------------------------------------------------------
myst_url_schemes = ["http", "https"]

# -- Pickle Prevention System -----------------------------------------------
import atexit

# 1. Disable Sphinx's native pickling
pickle = False

# 2. Active cleanup function
def _delete_pickle_files():
    """Remove any residual pickle files with verification."""
    pickle_path = os.path.join('build', 'doctrees', 'environment.pickle')
    try:
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[Security] Removed: {pickle_path}")
    except Exception as e:
        print(f"[Warning] Cleanup failed: {str(e)}")


# 3. Register cleanup hooks
atexit.register(_delete_pickle_files)  # Python-level cleanup
if os.getenv('NETLIFY'):
    os.environ['ALGOLIA_API_KEY'] = '[REDACTED]'  # Production obfuscation


# -- Setup Hook ------------------------------------------------------------
def setup(app):
    # Additional safety for modern Sphinx versions
    if hasattr(app, 'env') and hasattr(app.env, 'set_pickle'):
        app.env.set_pickle(False)

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
