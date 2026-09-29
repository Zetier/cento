# cento -- standalone gates. `make help` lists the targets.
#
# Lint rulings live in pyproject.toml (the before.py exclusion carries its reason
# there). Runnable examples
# live in examples/exNN/ (repo root; not shipped in the wheel).
#
# Recipes run quietly by default; VERBOSE=1 re-enables command echo (CI sets
# it so the job logs show exactly what ran).

ifndef VERBOSE
.SILENT:
endif

.DEFAULT_GOAL := selftest

PY ?= python3

VENV := config/.venv
VENV_PY := $(VENV)/bin/python
VENV_STAMP := $(VENV)/.stamp

LINT_PATHS := src tests examples

# Every file class rides a gate: the lists come from git, so untracked scratch never gates.
SH_FILES := $(shell git ls-files '*.sh')
C_FILES := $(shell git ls-files '*.c' '*.h')
YAML_FILES := $(shell git ls-files '*.yml' '*.yaml')
MD_FILES := $(shell git ls-files '*.md')
JSON_FILES := $(shell git ls-files '*.json')

.PHONY: help setup selftest fix lint validate test transcripts dco dist dist-verify smoke-setup smoke-example \
	verify-setup verify-probe venv venv-verify check-python

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_%-]+:.*##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Install the pip-installable gate tools (pinned core in config/requirements.txt; shellcheck and cc come from the system)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r config/requirements.txt
	$(PY) -m pip install pytest-xdist yamllint pymarkdownlnt codespell pre-commit clang-tidy zizmor

fix: ## Auto-fix what the linters can (ruff format, ruff check --fix, codespell -w, pymarkdown fix)
	$(PY) -m ruff format $(LINT_PATHS)
	$(PY) -m ruff check --fix $(LINT_PATHS)
	$(PY) -m codespell_lib -w
	if [ -n "$(MD_FILES)" ]; then $(PY) -m pymarkdown fix $(MD_FILES); fi

lint: ## Lint every tracked file class: ruff (py), shellcheck (sh), yamllint (yml), pymarkdown (md), codespell (prose), zizmor (workflows)
	$(PY) -m ruff format --check $(LINT_PATHS)
	$(PY) -m ruff check $(LINT_PATHS)
	if [ -n "$(SH_FILES)" ]; then shellcheck $(SH_FILES); fi
	$(PY) -m yamllint --strict -c config/yamllint.yml $(YAML_FILES)
	$(PY) -m pymarkdown scan $(MD_FILES)
	$(PY) -m codespell_lib
	zizmor --quiet .github/workflows

# C rides full warnings. A deliberately insecure exhibit that trips a rule waives it IN the
# file (#pragma GCC diagnostic ignored, with the reason on the same comment) -- declared
# intent a reviewer reads, never a Makefile-wide -Wno-*. No exhibit needs one today.
validate: ## Static validation: mypy --strict (py), cc -Wall -Wextra -Werror + clang-tidy (c), bash -n (sh), json parse
	$(PY) -m mypy --strict src/cento tests examples
	for f in $(C_FILES); do cc -fsyntax-only -Wall -Wextra -Werror "$$f" || exit 1; done
	for f in $(C_FILES); do clang-tidy --quiet --config-file=config/clang-tidy.yml "$$f" -- -Wall || exit 1; done
	for f in $(SH_FILES); do bash -n "$$f" || exit 1; done
	for f in $(JSON_FILES); do $(PY) -c "import json,sys; json.load(open(sys.argv[1]))" "$$f" || exit 1; done

selftest: lint validate ## Run the authoritative gates: lint + validate + pytest + source-tree selftest
	$(PY) -m pytest tests -q -n auto
	PYTHONPATH=src $(PY) -m cento.selftest

test: ## Run pytest alone
	$(PY) -m pytest tests -q -n auto

transcripts: ## Regenerate examples/*/transcript.txt (checked-in verbatim runs; tests assert currency)
	$(PY) config/gen_transcripts.py

dco: ## Refuse unsigned commits in DCO_RANGE (default origin/main..HEAD)
	$(PY) config/dco_check.py "$${DCO_RANGE:-origin/main..HEAD}"

dist: ## Build the sdist and wheel into dist/ (installs build; fresh dist/ every run)
	rm -rf build dist  # a stale in-tree PEP 517 build/ merges into the wheel; stale dist/ ships old bytes
	$(PY) config/gen_pypi_readme.py
	$(PY) -m pip install build
	$(PY) -m build

dist-verify: ## Full wheel-install verification in a scratch venv
	$(PY) config/dist_verify.py

smoke-setup: ## Install cento (non-editable), then smoke test it from a tempdir
	rm -rf build  # a stale in-tree PEP 517 build/ merges into the wheel: never install over one
	$(PY) -m pip install .
	py="$$($(PY) -c 'import sys; print(sys.executable)')"; \
	tmp="$$(mktemp -d)"; cd "$$tmp" && \
	"$$py" -c "import cento; assert 'site-packages' in cento.__file__, cento.__file__; print('installed-at', cento.__file__, cento.__version__)" && \
	"$$py" -m cento.selftest

smoke-example: ## Run a repo example script against the installed package
	$(PY) examples/ex05/ex05_computed_cells.py

verify-setup: ## Install cento + pytest with the [verify] extra (GPL unicorn -- see License)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install '.[verify]' pytest pytest-xdist

verify-probe: ## Prove the [verify] extra resolved: unicorn importable
	$(PY) -c "import cento.verify; assert cento.verify.HAVE_UNICORN; print('unicorn importable; verify layer armed')"


check-python:
	@command -v $(PY) >/dev/null 2>&1 || { \
		echo "error: '$(PY)' not found -- install Python 3.10+ or set PY=/path/to/python"; exit 1; }
	@$(PY) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { \
		echo "error: $(PY) is $$($(PY) -V 2>&1) -- cento requires Python >= 3.10 (set PY=/path/to/python3.10+)"; exit 1; }

venv: $(VENV_STAMP) ## Create .venv/ with cento installed editable (core, stdlib-only)

$(VENV_STAMP): pyproject.toml | check-python
	@echo "setting up $(VENV)/ (one-time: venv + editable cento install)..."
	$(PY) -m venv $(VENV)
	$(VENV_PY) -m pip install --quiet --upgrade pip
	$(VENV_PY) -m pip install --quiet -e .
	touch $@

venv-verify: $(VENV_STAMP) ## venv plus the [verify] extra (GPL unicorn -- see License)
	$(VENV_PY) -m pip install --quiet -e '.[verify]'

ex%: venv ## Run example <NN> (a before/after pair runs check + refusal too; ARGS=... passes through)
	@if [ -e "examples/ex$*/after.py" ]; then \
		py="$$(pwd)/$(VENV_PY)"; ( cd examples/ex$* && \
		"$$py" before.py && "$$py" after.py && \
		{ [ ! -e enhanced.py ] || "$$py" enhanced.py; } && "$$py" check.py && \
		{ [ ! -e refusal.py ] || "$$py" refusal.py; } ); rc=$$?; \
		echo; \
		echo "hint: the output above is half the story -- the exhibit sources in examples/ex$*/ are the walkthrough"; \
		set -- examples/ex$*/ex$*_*.py; \
		if [ "$$rc" -ne 0 ] || [ ! -e "$$1" ]; then exit $$rc; fi; \
		echo; \
	fi; \
	set -- examples/ex$*/ex$*_*.py; \
	if [ ! -e "$$1" ]; then \
		echo "error: no example matching 'ex$*'; available:"; \
		ls examples | sed -n 's/^\(ex[0-9]*\)$$/  make \1/p'; exit 1; \
	fi; \
	[ -z "$(VERBOSE)" ] || echo "$(VENV_PY) $$1 $(ARGS)"; \
	$(VENV_PY) "$$1" $(ARGS); rc=$$?; \
	echo; \
	echo "hint: the output above is half the story -- open $$1 for the commented walkthrough"; \
	exit $$rc
