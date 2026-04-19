# Contributing to tfdrift

Thank you for your interest in contributing to tfdrift! This document provides guidelines and instructions for contributing.

## Development setup

```bash
# Clone the repo
git clone https://github.com/sudarshan8417/tfdrift.git
cd tfdrift

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Running tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=tfdrift --cov-report=term-missing

# Run a specific test file
pytest tests/test_models.py -v
```

## Code quality

```bash
# Lint
ruff check src/ tests/

# Auto-fix lint issues
ruff check --fix src/ tests/

# Type checking
mypy src/tfdrift/ --ignore-missing-imports
```

## Pull request process

1. Fork the repository and create a feature branch from `main`
2. Add tests for any new functionality
3. Ensure all tests pass and linting is clean
4. Update documentation if needed
5. Submit a pull request with a clear description of the change

## Commit messages

Use conventional commit format:

```
feat: add support for Azure drift detection
fix: handle empty terraform state gracefully
docs: update README with watch mode examples
test: add tests for severity classification
chore: update dependencies
```

## Adding new severity rules

To add new default severity rules, edit `src/tfdrift/severity.py` and add patterns to the appropriate list (`DEFAULT_CRITICAL_PATTERNS`, `DEFAULT_HIGH_PATTERNS`, or `DEFAULT_LOW_PATTERNS`). Include a test in `tests/test_models.py`.

## Adding new reporters

1. Create a new function in `src/tfdrift/reporters/output.py`
2. Wire it into the CLI in `src/tfdrift/cli.py`
3. Add tests

## Code of conduct

Be kind, be respectful, and help make this project welcoming for everyone.
