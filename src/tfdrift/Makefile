.PHONY: test lint typecheck install clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=tfdrift --cov-report=term-missing

lint:
	ruff check src/ tests/

typecheck:
	mypy src/tfdrift/ --ignore-missing-imports

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache .mypy_cache

all: lint typecheck test
