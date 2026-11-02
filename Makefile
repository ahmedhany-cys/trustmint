.PHONY: install test lint selfcheck demo reports

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check src tests
	ruff format --check src tests

test:
	pytest

selfcheck:
	trustmint selfcheck

demo:
	trustmint scan -s examples/acme/snapshot.json \
	  -w acme/payments-api=examples/acme/workflows/payments-api --fail-on never

reports:
	trustmint scan -s examples/acme/snapshot.json -w acme/payments-api=examples/acme/workflows/payments-api \
	  -f markdown -o examples/acme/report.md --fail-on never
	trustmint scan -s examples/acme/snapshot.json -w acme/payments-api=examples/acme/workflows/payments-api \
	  -f sarif -o examples/acme/report.sarif --fail-on never
