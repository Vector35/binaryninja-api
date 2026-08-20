PYTHON ?= python

.PHONY: help all manual reference python-reference cpp-reference clean

help:
	@echo "Documentation targets:"
	@echo "  manual             Build the user and developer manual"
	@echo "  python-reference   Build the Python API reference"
	@echo "  cpp-reference      Build the C++ API reference"
	@echo "  reference          Build both API references"
	@echo "  all                Build every documentation surface"
	@echo "  clean              Remove generated documentation output"

all: manual reference

manual:
	$(PYTHON) ../scripts/zensical_build.py

reference: python-reference cpp-reference

python-reference:
	$(MAKE) -C reference/python html

cpp-reference:
	$(MAKE) -C reference/cpp html PYTHON=$(PYTHON)

clean:
	$(PYTHON) ../scripts/zensical_build.py -c
	$(MAKE) -C reference/python clean
	$(MAKE) -C reference/cpp clean
