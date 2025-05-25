# Makefile for auth project

.PHONY: install test test-cov test-html test-xml clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  install     - Install dependencies"
	@echo "  test        - Run tests without coverage"
	@echo "  test-cov    - Run tests with coverage (default reports)"
	@echo "  test-html   - Run tests and generate HTML coverage report"
	@echo "  test-xml    - Run tests and generate XML coverage report"
	@echo "  clean       - Clean coverage files and cache"
	@echo "  help        - Show this help message"

# Install dependencies
install:
	pip install -r requirements.txt
	pip install -r requirements-pytest.txt

# Run tests without coverage
test:
	python -m pytest tests/ -v

# Run tests with coverage (all reports)
test-cov:
	python -m pytest tests/ --cov=app --cov-report=html:htmlcov --cov-report=xml:coverage.xml --cov-report=term-missing -v

# Run tests and generate HTML coverage report
test-html:
	python -m pytest tests/ --cov=app --cov-report=html:htmlcov -v

# Run tests and generate XML coverage report  
test-xml:
	python -m pytest tests/ --cov=app --cov-report=xml:coverage.xml -v

# Clean coverage files and cache
clean:
	rm -rf htmlcov/
	rm -f coverage.xml
	rm -f .coverage
	rm -rf .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete