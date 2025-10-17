# Build and Release Instructions

## Building the Package

### Prerequisites

```bash
pip install build twine
```

### Build Distribution

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info

# Build source and wheel distributions
python -m build
```

This creates:
- `dist/senzil-django-oidc-provider-1.0.0.tar.gz` (source distribution)
- `dist/senzil_django_oidc_provider-1.0.0-py3-none-any.whl` (wheel)

### Verify Build

```bash
# Check package
twine check dist/*

# Test installation locally
pip install dist/senzil_django_oidc_provider-1.0.0-py3-none-any.whl
```

## Publishing to PyPI

### Test on TestPyPI First

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Test install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ senzil-django-oidc-provider
```

### Publish to PyPI

```bash
# Upload to PyPI
twine upload dist/*
```

### API Tokens

Configure PyPI API token in `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR-API-TOKEN

[testpypi]
username = __token__
password = pypi-YOUR-TESTPYPI-TOKEN
```

## Install Options

### Basic Installation

```bash
pip install senzil-django-oidc-provider
```

### With Passkey Support

```bash
pip install senzil-django-oidc-provider[passkey]
```

### With All Features

```bash
pip install senzil-django-oidc-provider[all]
```

### Development Install

```bash
# Clone repository
git clone https://github.com/senzil/senzil-django-oidc-provider.git
cd senzil-django-oidc-provider

# Install in editable mode with dev dependencies
pip install -e ".[dev,all]"
```

## Release Checklist

- [ ] Update version in `oidc_provider/version.py`
- [ ] Update CHANGELOG.md
- [ ] Run all tests: `pytest`
- [ ] Check code quality: `black .` and `flake8`
- [ ] Update documentation if needed
- [ ] Create git tag: `git tag v1.0.0`
- [ ] Build package: `python -m build`
- [ ] Check package: `twine check dist/*`
- [ ] Upload to TestPyPI and test
- [ ] Upload to PyPI
- [ ] Push tag: `git push origin v1.0.0`
- [ ] Create GitHub release

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: New functionality (backward compatible)
- **PATCH** version: Bug fixes (backward compatible)

Current version: **1.0.0** (major modernization release)

## Package Contents

```
senzil-django-oidc-provider/
├── oidc_provider/          # Main package
├── docs/                   # Documentation
├── tests/                  # Test suite
├── pyproject.toml         # Modern packaging config
├── setup.py               # Setup script
├── setup.cfg              # Additional config
├── MANIFEST.in            # Package manifest
├── README.md              # Main readme
├── CHANGELOG.md           # Change log
├── LICENSE                # MIT license
└── requirements.txt       # Dependencies
```

## Testing Package Locally

```bash
# Create test environment
python -m venv test-env
source test-env/bin/activate

# Install from wheel
pip install dist/senzil_django_oidc_provider-1.0.0-py3-none-any.whl

# Verify installation
python -c "import oidc_provider; print(oidc_provider.__version__)"

# Test in Django project
django-admin startproject testproject
cd testproject
# Add 'oidc_provider' to INSTALLED_APPS
python manage.py migrate oidc_provider
```

## Documentation

Documentation is available in the `docs/` folder and on GitHub:
https://github.com/senzil/senzil-django-oidc-provider/blob/main/docs/README.md

## Support

- Issues: https://github.com/senzil/senzil-django-oidc-provider/issues
- Discussions: https://github.com/senzil/senzil-django-oidc-provider/discussions
