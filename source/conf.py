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
    'extensions.algolia_search',  # This handles all Algolia setup
]

source_suffix = ['.rst', '.md']
templates_path = ['_templates']
exclude_patterns = []

# Disable default search index generation
html_use_index = False

# -- HTML Output -------------------------------------------------------------
html_theme = 'furo'

# Furo theme options
html_theme_options = {
    "sidebar_hide_name": True,
    "navigation_with_keys": True,
}

html_title = "Red team"
html_logo = "img/logo.png"
html_favicon = "img/favicon.ico"
html_static_path = ['_static']

# These are already added by the algolia_search extension
# html_js_files = ['js/algolia.js']  # Remove this
# html_css_files = ['css/algolia.css']  # Remove this

# Only include custom.css if you have other custom styles
html_css_files = ['css/custom.css']

html_show_sphinx = False
html_show_copyright = False

# -- Intersphinx ------------------------------------------------------------
myst_url_schemes = ["http", "https"]

# Disable environment caching
pickle = False
