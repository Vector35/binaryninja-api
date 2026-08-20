# Makefile for C++ documentation

PYTHON ?= poetry run python

.PHONY: help
help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "  html    to make standalone HTML files"
	@echo "  docset  to make a Dash docset"

.PHONY: clean
clean:
	rm -rf html
	rm -rf docset
	rm -rf xml

.PHONY: html
html:
	$(PYTHON) ./build_min_docs.py

.PHONY: docset
docset:
	$(PYTHON) ./build_min_docs.py --docset
