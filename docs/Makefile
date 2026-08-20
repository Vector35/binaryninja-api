POETRY ?= poetry

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
	cd .. && $(POETRY) run python scripts/zensical_build.py

reference: python-reference cpp-reference

python-reference:
	cd .. && $(POETRY) run $(MAKE) -C docs/reference/python html

cpp-reference:
	cd .. && $(POETRY) run $(MAKE) -C docs/reference/cpp html PYTHON=python

clean:
	cd .. && $(POETRY) run python scripts/zensical_build.py -c
	$(MAKE) -C reference/python clean
	$(MAKE) -C reference/cpp clean
