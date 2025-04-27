# Minimal makefile for Sphinx documentation
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

clean:
	@rm -rf build/
	@echo "Purged all build artifacts"

html:
	@echo "Building with pickle prevention..."
	@SPHINX_BUILD=1 sphinx-build -M html "$(SOURCEDIR)" "$(BUILDDIR)" -D pickle=False
	@rm -f build/doctrees/environment.pickle 2>/dev/null || true