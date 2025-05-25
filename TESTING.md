# Testing Guide

This document explains how to run tests and generate coverage reports for the authentication system.

## Prerequisites

Install testing dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-pytest.txt
```

## Running Tests

### Option 1: Using Make Commands (Recommended)

```bash
# Run tests with full coverage reporting
make test-cov

# Run tests without coverage
make test

# Generate only HTML coverage report
make test-html

# Generate only XML coverage report
make test-xml

# Clean coverage files
make clean

# Show all available commands
make help
```

### Option 2: Using Python Script

```bash
# Run tests with full coverage reporting
python run_tests.py

# Run tests without coverage
python run_tests.py --no-cov

# Generate only HTML coverage report
python run_tests.py --html

# Generate only XML coverage report
python run_tests.py --xml
```

### Option 3: Using pytest Directly

```bash
# Run tests with coverage (uses pytest.ini configuration)
pytest

# Run tests with specific coverage options
pytest --cov=app --cov-report=html --cov-report=term-missing

# Run tests without coverage
pytest tests/ --no-cov
```

## Coverage Reports

The testing setup generates multiple types of coverage reports:

### Terminal Report
Shows coverage summary in the terminal with missing line numbers.

### HTML Report
- **Location**: `htmlcov/index.html`
- **Usage**: Open in browser to see detailed coverage with highlighted source code
- **Features**: Line-by-line coverage visualization, sortable by coverage percentage

### XML Report
- **Location**: `coverage.xml`
- **Usage**: For CI/CD systems and tools that parse XML coverage reports
- **Format**: Cobertura-compatible XML

## Configuration Files

### pytest.ini
- Pytest configuration with coverage settings
- Sets coverage threshold to 80% (configurable)
- Defines test discovery patterns
- Excludes deprecation warnings

### .coveragerc
- Coverage.py configuration
- Defines source paths (`app/` directory)
- Excludes test files, migrations, templates from coverage
- Configures report output locations

### tests/conftest.py
- Flask app test fixtures
- Database setup for testing
- Application context management

## Writing Tests

### Test File Location
Place test files in the `tests/` directory with the naming pattern `test_*.py`.

### Basic Test Structure
```python
def test_something(client):
    """Test description."""
    response = client.get('/api/endpoint')
    assert response.status_code == 200
```

### Available Fixtures
- `app`: Flask application instance with testing configuration
- `client`: Test client for making HTTP requests
- `runner`: CLI runner for testing commands
- `app_context`: Application context for database operations

### Example Test
```python
def test_user_registration(client):
    """Test user registration endpoint."""
    response = client.post('/api/auth/register', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'securepassword123'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['message'] == 'User registered successfully'
```

## Coverage Goals

- **Minimum Coverage**: 80% (enforced by pytest configuration)
- **Target Coverage**: 90%+ for critical modules (auth, security, encryption)
- **Files to Focus On**: 
  - `app/auth/` - Authentication logic
  - `app/security/` - Security features
  - `app/utils/encryption.py` - Encryption functions
  - `app/models/` - Database models

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Database Errors**: Tests use in-memory SQLite; no setup required
3. **Coverage Too Low**: Add tests for uncovered code paths
4. **Missing Test Dependencies**: Run `pip install -r requirements-pytest.txt`

### Debug Mode
Run tests with verbose output:
```bash
pytest -v -s tests/
```

### Running Specific Tests
```bash
# Run specific test file
pytest tests/test_encryption.py

# Run specific test function
pytest tests/test_encryption.py::test_encrypt_decrypt_basic

# Run tests matching pattern
pytest -k "encryption"
```