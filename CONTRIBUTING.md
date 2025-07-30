# Contributing to Secret's Garden

Thank you for considering contributing to Secret's Garden! We welcome contributions from the community and are excited to see what you'll bring to the project.

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Development Environment Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/secrets-garden.git
   cd secrets-garden
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

5. **Verify installation**
   ```bash
   secrets-garden --version
   pytest
   ```

### Project Structure

```
secrets-garden/
├── secrets_garden/          # Main package
│   ├── cli/                # CLI interface
│   ├── vault/              # Core vault functionality
│   ├── config/             # Configuration management
│   └── exceptions.py       # Custom exceptions
├── tests/                  # Test suite
├── docs/                   # Documentation
├── .github/                # GitHub workflows and templates
├── pyproject.toml          # Project configuration
└── README.md              # Main documentation
```

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

- **Bug fixes** - Fix existing issues
- **Features** - Add new functionality
- **Documentation** - Improve docs, examples, or comments
- **Tests** - Add or improve test coverage
- **Security** - Security improvements or vulnerability fixes

### Before You Start

1. **Check existing issues** - Look for existing issues or discussions
2. **Create an issue** - For significant changes, create an issue first
3. **Discuss the approach** - Get feedback before starting work
4. **Check the roadmap** - Ensure your contribution aligns with project goals

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following our style guide
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and linting**
   ```bash
   # Run full test suite
   pytest

   # Run with coverage
   pytest --cov=secrets_garden

   # Run security tests
   pytest -m security

   # Lint code
   ruff check secrets_garden tests
   ruff format secrets_garden tests

   # Type checking
   mypy secrets_garden

   # Security scanning
   bandit -r secrets_garden
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style and Standards

### Python Code Style

We use automated tools to maintain code quality:

- **Black** for code formatting
- **Ruff** for linting and import sorting
- **MyPy** for type checking
- **Bandit** for security scanning

### Commit Message Convention

We follow conventional commit format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `security:` - Security improvements
- `chore:` - Maintenance tasks

Examples:
```
feat: add export command for secrets
fix: resolve memory leak in crypto module
docs: update installation instructions
test: add integration tests for vault manager
security: implement constant-time comparison
```

### Type Hints

All new code should include type hints:

```python
def encrypt_secret(plaintext: str, password: str) -> EncryptedData:
    """Encrypt a secret with the given password."""
    # Implementation here
```

### Documentation Strings

Use Google-style docstrings:

```python
def create_vault(path: Path, password: str) -> VaultManager:
    """Create a new vault at the specified path.
    
    Args:
        path: Directory path for the new vault
        password: Master password for the vault
        
    Returns:
        VaultManager instance for the new vault
        
    Raises:
        VaultAlreadyExistsError: If vault already exists at path
        VaultError: If vault creation fails
    """
```

## Testing Guidelines

### Test Structure

- **Unit tests** - Test individual components in isolation
- **Integration tests** - Test component interactions
- **Security tests** - Test security properties and edge cases
- **CLI tests** - Test command-line interface

### Writing Tests

1. **Test file naming**: `test_<module_name>.py`
2. **Test function naming**: `test_<functionality>_<scenario>`
3. **Use fixtures**: Leverage pytest fixtures for common setup
4. **Test edge cases**: Include boundary conditions and error cases
5. **Security focus**: Add security-specific test cases

Example test:

```python
def test_encrypt_decrypt_roundtrip(crypto_manager: CryptoManager):
    """Test that encryption and decryption work correctly."""
    password = "test-password"
    plaintext = "secret message"
    
    encrypted_data = crypto_manager.encrypt(plaintext, password)
    decrypted = crypto_manager.decrypt(encrypted_data, password)
    
    assert decrypted == plaintext
```

### Test Coverage

- Aim for >95% test coverage
- Focus on critical security code paths
- Include error handling tests
- Test CLI commands and user interactions

## Security Considerations

### Security-First Development

- **Review crypto code carefully** - All cryptographic code needs thorough review
- **No hardcoded secrets** - Never commit secrets or keys
- **Input validation** - Validate all user inputs
- **Error handling** - Don't leak sensitive information in errors
- **Memory safety** - Clear sensitive data from memory when possible

### Security Testing

- Add security-specific tests for new features
- Test error conditions and edge cases
- Verify that sensitive data is properly cleared
- Test against common attack vectors

### Cryptographic Changes

For changes to cryptographic code:

1. **Discuss first** - Security changes need community discussion
2. **Expert review** - Get review from cryptography experts
3. **Extensive testing** - Include comprehensive security tests
4. **Documentation** - Update security documentation

## Documentation

### Types of Documentation

- **Code comments** - Explain complex logic
- **Docstrings** - Document public APIs
- **README** - High-level project information
- **Security docs** - Security model and implementation
- **Examples** - Usage examples and tutorials

### Documentation Standards

- Keep documentation up to date with code changes
- Use clear, concise language
- Include practical examples
- Document security implications
- Update CHANGELOG.md for significant changes

## Pull Request Process

### Before Submitting

- [ ] Tests pass locally
- [ ] Code is properly formatted and linted
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (for significant changes)
- [ ] Commit messages follow convention
- [ ] No merge conflicts with main branch

### Pull Request Template

When creating a pull request, include:

1. **Description** - What does this PR do?
2. **Motivation** - Why is this change needed?
3. **Testing** - How was this tested?
4. **Breaking changes** - Any backward compatibility issues?
5. **Security impact** - Any security implications?

### Review Process

1. **Automated checks** - CI pipeline must pass
2. **Code review** - At least one maintainer review required
3. **Security review** - Security-sensitive changes need security review
4. **Testing** - Reviewers may test functionality manually
5. **Documentation review** - Check that docs are accurate and complete

### Merging

- PRs are merged using "Squash and merge" to maintain clean history
- Ensure commit message follows conventional format
- Delete feature branch after merging

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** - Breaking changes
- **MINOR** - New features (backward compatible)
- **PATCH** - Bug fixes (backward compatible)

### Release Steps

1. Update version in `secrets_garden/__init__.py`
2. Update CHANGELOG.md
3. Create release PR
4. Tag release after merging
5. Publish to PyPI (maintainers only)

## Community

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and discussions
- **Security Email** - security@secrets-garden.dev for security issues

### Getting Help

If you need help:

1. Check existing documentation and issues
2. Search GitHub discussions
3. Create a new discussion or issue
4. Be specific about your environment and problem

## Recognition

Contributors are recognized in several ways:

- **CONTRIBUTORS.md** - All contributors are listed
- **GitHub contributors page** - Automatic recognition
- **Release notes** - Significant contributions are highlighted
- **Special recognition** - Outstanding contributions may receive special thanks

## Legal

By contributing to Secret's Garden, you agree that your contributions will be licensed under the MIT License. You also confirm that you have the right to submit your contributions under this license.

---

Thank you for contributing to Secret's Garden! Your efforts help make secure secrets management accessible to everyone. 🌱