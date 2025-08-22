# _ext/disable_fonts.py

def disable_google_fonts(app):
    """Disable Google Fonts fetch in sphinx_immaterial to prevent CI failures."""
    try:
        import sphinx_immaterial.google_fonts as gf
        # Patch the fetch_fonts function to a no-op
        gf.fetch_fonts = lambda *args, **kwargs: None
    except (ImportError, AttributeError):
        pass  # In case the module layout changes or missing

def setup(app):
    # Connect to builder-inited event; app parameter is required by Sphinx
    app.connect("builder-inited", disable_google_fonts)
