# Contributing to Senzil Django OIDC Provider

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/senzil/senzil-django-oidc-provider.git
cd senzil-django-oidc-provider
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
pip install -e ".[dev,all]"
```

### 4. Run Tests

```bash
pytest
# or
python manage.py test oidc_provider
```

## Code Quality

### Formatting

We use Black for code formatting:

```bash
black oidc_provider/
```

### Linting

We use Flake8 for linting:

```bash
flake8 oidc_provider/
```

### Type Checking

We use mypy for type checking:

```bash
mypy oidc_provider/
```

## Testing

### Run All Tests

```bash
pytest
```

### Run Specific Tests

```bash
pytest oidc_provider/tests/test_all_flows.py
pytest oidc_provider/tests/test_passkey.py
```

### Coverage Report

```bash
pytest --cov=oidc_provider --cov-report=html
```

## Pull Request Process

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the code style guidelines
3. **Add tests** for new features
4. **Update documentation** as needed
5. **Run tests** and ensure they pass
6. **Submit a pull request** with a clear description

### PR Guidelines

- Write clear, descriptive commit messages
- Keep PRs focused on a single feature/fix
- Update CHANGELOG.md with your changes
- Ensure all tests pass
- Follow PEP 8 and use Black formatting

## Reporting Issues

When reporting issues, please include:

- Django version
- Python version
- Package version
- Detailed description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs if applicable

## Feature Requests

We welcome feature requests! Please:

- Check if the feature already exists
- Provide a clear use case
- Explain why it would be valuable
- Consider submitting a PR

## Documentation

Help improve documentation:

- Fix typos and errors
- Add examples
- Improve clarity
- Add missing sections

Documentation is in the `docs/` folder using Markdown.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions

## Questions?

- Check the [documentation](docs/README.md)
- Open an issue for discussion
- Join community discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
