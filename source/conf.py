# conf.py
import os
import sys

os.environ['SPHINX_IMMATERIAL_DISABLE_GOOGLE_FONTS'] = "1"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# -- Project information -----------------------------------------------------
project = 'Red team'
copyright = '2025, TyMyrddin'
author = 'TyMyrddin'
release = '0.1'

# -- General configuration ---------------------------------------------------

extensions = [
    'myst_parser',
    'sphinx_immaterial',
]

myst_enable_extensions = [
    "amsmath",
    "dollarmath",
    "tasklist",
    "colon_fence",
    "html_admonition",
    "html_image",
    "attrs_block",
    "attrs_inline",
]

# MyST parser configuration
# myst_enable_extensions = ["colon_fence"]
# myst_all_links_external = False  # Required for TOC resolution
# myst_suppress_warnings = ["myst.xref_missing"]  # More specific than suppress_warnings

# Path setup
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown'
}

# -- HTML output -------------------------------------------------------------
html_theme = 'sphinx_immaterial'

html_theme_options = {
    "palette": {
        "scheme": "slate",
        "primary": "red",
        "accent": "light-red"
    },
    "features": [
        "navigation.top",
        "content.tabs.link",
    ],
}

html_title = "Red team"
html_logo = "img/logo.png"
html_favicon = "img/favicon.ico"
html_static_path = ['_static']
html_css_files = ['css/custom.css']
html_last_updated_fmt = '%Y-%m-%d %H:%M'  # e.g., "May 05, 2025 at 14:30"
html_extra_path = ['_static/_headers']

# -- Build settings ----------------------------------------------------------
nitpicky = True  # Warn about broken references
# suppress_warnings = ["myst.xref_missing"]  # Backward compatibility

# Disable all automatic anchor generation
autosectionlabel_prefix_document = False
