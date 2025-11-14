# Contributing to Threat Intelligence Platform

Thank you for your interest in contributing to the Threat Intelligence Platform (TIP)! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Adding New Features](#adding-new-features)
- [Bug Reports](#bug-reports)
- [Security Issues](#security-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and harassment-free environment for everyone. We expect:

- **Respect**: Treat all contributors with respect and kindness
- **Constructive feedback**: Provide helpful, actionable feedback
- **Collaboration**: Work together to improve the platform
- **Professionalism**: Maintain professional communication

## Getting Started

### Prerequisites

Before you begin, ensure you have:

- **Git** installed
- **Python 3.11+** installed
- **Docker** and **Docker Compose** installed
- **Basic understanding** of:
  - Threat intelligence concepts
  - Python programming
  - RESTful APIs
  - Elasticsearch
  - Apache Airflow

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/threat-intelligence-platform.git
   cd threat-intelligence-platform
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/original/threat-intelligence-platform.git
   ```

### Stay Updated

Keep your fork synchronized:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Development Environment

### Quick Setup

1. **Run initialization**:
   ```bash
   bash scripts/init.sh
   ```

2. **Configure API keys**:
   ```bash
   cp config/api_keys.env.example config/api_keys.env
   # Edit config/api_keys.env with your keys
   ```

3. **Install Python dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Start services**:
   ```bash
   make start
   ```

5. **Initialize database**:
   ```bash
   make db-init
   ```

6. **Seed sample data** (optional):
   ```bash
   make db-seed
   ```

### Development Tools

Install recommended development tools:

```bash
pip install black flake8 pylint mypy pytest pytest-cov isort
```

### IDE Configuration

#### VS Code

Create `.vscode/settings.json`:

```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.formatting.blackArgs": ["--line-length=120"],
  "editor.formatOnSave": true,
  "python.testing.pytestEnabled": true
}
```

#### PyCharm

- Enable Black formatter in Settings → Tools → Black
- Configure Flake8 in Settings → Tools → External Tools
- Set line length to 120

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

1. **Bug fixes**: Fix issues and improve stability
2. **New features**: Add new collectors, enrichers, or functionality
3. **Documentation**: Improve docs, guides, and examples
4. **Tests**: Add or improve test coverage
5. **Performance**: Optimize code performance
6. **Security**: Identify and fix security vulnerabilities

### Contribution Workflow

1. **Create an issue** describing your contribution (if one doesn't exist)
2. **Create a branch** from `develop`:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Write tests** for your changes
5. **Run tests** locally:
   ```bash
   make test
   ```
6. **Commit your changes** with clear commit messages
7. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Create a Pull Request** to the `develop` branch

## Coding Standards

### Python Style Guide

We follow **PEP 8** with some modifications:

- **Line length**: Maximum 120 characters
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Prefer double quotes for strings
- **Imports**: Group and sort imports using `isort`

### Code Formatting

Format code with Black:

```bash
black collectors/ enrichment/ correlation/ --line-length=120
```

Sort imports:

```bash
isort collectors/ enrichment/ correlation/
```

### Linting

Run linters before committing:

```bash
# Flake8
flake8 collectors/ enrichment/ correlation/ --max-line-length=120

# Pylint
pylint collectors/ enrichment/ correlation/ --max-line-length=120
```

### Type Hints

Use type hints for function signatures:

```python
from typing import List, Dict, Optional

def collect_iocs(limit: int = 100) -> List[Dict]:
    """
    Collect IOCs from source

    Args:
        limit: Maximum number of IOCs to collect

    Returns:
        List of IOC dictionaries
    """
    pass
```

### Documentation

Write clear docstrings:

```python
def enrich_ioc(ioc: Dict) -> Dict:
    """
    Enrich an IOC with additional data

    This function adds geolocation, WHOIS, and reputation data
    to the provided IOC.

    Args:
        ioc: IOC dictionary with 'value' and 'type' fields

    Returns:
        Enriched IOC dictionary with additional fields

    Raises:
        ValueError: If IOC is missing required fields
        NetworkError: If external enrichment service fails

    Example:
        >>> ioc = {"value": "1.2.3.4", "type": "ip"}
        >>> enriched = enrich_ioc(ioc)
        >>> print(enriched["enrichment"]["geolocation"]["country"])
        "United States"
    """
    pass
```

## Testing Guidelines

### Test Structure

Organize tests by component:

```
tests/
├── collectors/
│   ├── test_alienvault_otx.py
│   ├── test_urlhaus_collector.py
│   └── test_abuseipdb_collector.py
├── enrichment/
│   ├── test_geoip_enricher.py
│   └── test_threat_score_engine.py
└── correlation/
    └── test_correlation_engine.py
```

### Writing Tests

Use **pytest** for testing:

```python
import pytest
from collectors.alienvault_otx import AlienVaultCollector

def test_collect_iocs_success(mocker):
    """Test successful IOC collection"""
    # Mock API response
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"results": [{"indicator": "1.2.3.4"}]}
    mocker.patch("requests.get", return_value=mock_response)

    # Test
    collector = AlienVaultCollector(api_key="test_key")
    iocs = collector.collect(limit=10)

    # Assertions
    assert len(iocs) > 0
    assert iocs[0].value == "1.2.3.4"

def test_collect_iocs_api_error(mocker):
    """Test API error handling"""
    mocker.patch("requests.get", side_effect=Exception("API Error"))

    collector = AlienVaultCollector(api_key="test_key")

    with pytest.raises(Exception):
        collector.collect(limit=10)
```

### Test Markers

Use markers to categorize tests:

```python
@pytest.mark.unit
def test_unit_function():
    pass

@pytest.mark.integration
def test_integration_with_elasticsearch():
    pass

@pytest.mark.slow
def test_slow_operation():
    pass
```

### Running Tests

```bash
# All tests
make test

# With coverage
make test-coverage

# Specific marker
pytest tests/ -m unit

# Specific file
pytest tests/collectors/test_alienvault_otx.py
```

### Test Coverage

Maintain **80%+ code coverage**:

```bash
pytest --cov=collectors --cov=enrichment --cov=correlation --cov-report=html
open htmlcov/index.html
```

## Commit Messages

### Format

Follow the **Conventional Commits** specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(collectors): add VirusTotal collector

Implement VirusTotal API v3 integration for collecting
file hash IOCs. Includes rate limiting and error handling.

Closes #123
```

```
fix(enrichment): handle missing GeoIP data gracefully

Previously crashed when GeoIP database returned None.
Now returns empty enrichment object with warning log.

Fixes #456
```

### Best Practices

- **Use imperative mood**: "Add feature" not "Added feature"
- **Keep subject line under 50 characters**
- **Capitalize subject line**
- **No period at end of subject**
- **Wrap body at 72 characters**
- **Reference issues**: Use "Closes #123" or "Fixes #456"

## Pull Request Process

### Before Submitting

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/develop
   ```

2. **Run all checks**:
   ```bash
   make lint
   make test
   make validate
   ```

3. **Update documentation** if needed

4. **Add changelog entry** (if significant change)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex code
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests pass locally

## Related Issues
Closes #123
```

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by at least one maintainer
3. **Address feedback** and update PR
4. **Approval** required before merge
5. **Merge** to `develop` branch

## Adding New Features

### Adding a New Collector

1. **Create collector class** in `collectors/`:

```python
from collectors.base_collector import BaseCollector, IOC

class NewSourceCollector(BaseCollector):
    """Collect IOCs from New Source"""

    def __init__(self, api_key: str):
        super().__init__(source_name="NewSource", api_key=api_key)
        self.base_url = "https://api.newsource.com/v1"

    def collect(self, limit: int = 100) -> List[IOC]:
        """Collect IOCs from New Source API"""
        # Implementation
        pass
```

2. **Add tests** in `tests/collectors/`:

```python
def test_new_source_collector():
    collector = NewSourceCollector(api_key="test")
    iocs = collector.collect(limit=10)
    assert len(iocs) > 0
```

3. **Update configuration** in `config/config.yaml`:

```yaml
collectors:
  new_source:
    enabled: true
    collection_limit: 1000
```

4. **Add to DAG** in `airflow_dags/`:

```python
def collect_new_source(**context):
    from new_source_collector import NewSourceCollector
    # Implementation
```

5. **Update documentation**

### Adding a New Enricher

Similar process as collectors, in `enrichment/` directory.

## Bug Reports

### Creating a Bug Report

Use the bug report template:

```markdown
## Bug Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: Ubuntu 22.04
- Python: 3.11.5
- Docker: 24.0.5

## Logs
```
Paste relevant logs here
```

## Additional Context
Screenshots, error messages, etc.
```

### Providing Information

Include:
- **Detailed steps** to reproduce
- **Error messages** and stack traces
- **Log files** from `logs/`
- **Configuration** (sanitized, no API keys)
- **Environment** details

## Security Issues

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Instead:

1. **Email**: security@tip-project.example.com
2. **Include**:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

3. **Wait** for response before disclosure

### Security Best Practices

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Sanitize user inputs
- Follow OWASP guidelines
- Keep dependencies updated

## Questions?

- **Documentation**: Check our [docs](docs/)
- **GitHub Discussions**: Ask questions
- **Slack/Discord**: Join our community
- **Email**: contact@tip-project.example.com

## License

By contributing, you agree that your contributions will be licensed under the project's license.

---

**Thank you for contributing to the Threat Intelligence Platform!** 🎉
