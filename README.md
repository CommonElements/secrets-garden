# 🌱 Secret's Garden

> A secure, local-first secrets management CLI tool with military-grade encryption

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-green.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

Secret's Garden is a command-line secrets manager that keeps your sensitive data secure with AES-256-GCM encryption. No cloud, no network calls, just secure local storage that you control.

## ✨ Features

- 🔒 **Military-grade encryption** - AES-256-GCM with PBKDF2 key derivation
- 🏠 **Local-first** - All data stays on your machine, no cloud dependencies
- 🚀 **Fast & lightweight** - SQLite backend with optimized performance
- 🎨 **Beautiful CLI** - Rich terminal interface with colors and tables
- 🔧 **Developer-friendly** - Export secrets as environment variables
- 🔄 **Backup & restore** - Easy vault backup and migration
- 🏷️ **Organized** - Tag and categorize your secrets
- 🔍 **Searchable** - Find secrets quickly with pattern matching

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (coming soon)
pip install secrets-garden

# Or install from source
git clone https://github.com/harryschoeller/secrets-garden.git
cd secrets-garden
pip install -e .
```

### Basic Usage

```bash
# Create your first vault
secrets-garden init my-vault

# Add a secret
secrets-garden add api-key --description "Production API key"

# Get a secret
secrets-garden get api-key --show

# List all secrets
secrets-garden list

# Run a command with secrets as environment variables
secrets-garden run -- python my-script.py
```

## 📖 Documentation

### Creating and Managing Vaults

```bash
# Create a new vault
secrets-garden init production --description "Production secrets"

# Get vault information
secrets-garden info production

# Unlock a vault (stays unlocked for 1 hour by default)
secrets-garden unlock production

# Lock a vault
secrets-garden lock production

# Change vault password
secrets-garden change-password
```

### Managing Secrets

```bash
# Add a secret with tags
secrets-garden add database-url \
  --description "Main database connection" \
  --tag database \
  --tag production

# Update a secret
secrets-garden update database-url --value "new-connection-string"

# Get a secret (copies to clipboard by default)
secrets-garden get database-url

# Show secret value in terminal
secrets-garden get database-url --show

# Delete a secret
secrets-garden delete old-api-key

# List secrets with filters
secrets-garden list --pattern "api*" --tag production
```

### Export and Integration

```bash
# Export secrets as JSON (metadata only)
secrets-garden export secrets.json

# Export with values (use with caution!)
secrets-garden export secrets.json --include-values

# Export as environment file
secrets-garden export .env --format env --include-values

# Run commands with secrets injected
secrets-garden run -- docker-compose up
secrets-garden run --prefix MYAPP_ -- python app.py
```

### Backup and Restore

```bash
# Create a backup
secrets-garden backup ~/backups/my-vault-backup

# Restore is as simple as copying the backup directory
cp -r ~/backups/my-vault-backup ~/.secrets-garden/vaults/restored-vault
```

## 🔐 Security

Secret's Garden uses industry-standard cryptography:

- **AES-256-GCM** for authenticated encryption
- **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation
- **Cryptographically secure random** salt and nonce generation
- **Memory-safe operations** with explicit cleanup
- **Local-only storage** - no network communication

### Security Best Practices

1. **Use strong master passwords** - Consider using a passphrase with multiple words
2. **Keep backups secure** - Store encrypted backups in safe locations
3. **Regular password rotation** - Change vault passwords periodically
4. **Secure your system** - Use full-disk encryption and screen locks
5. **Review exported data** - Be careful when exporting secrets with values

## 🛠️ Advanced Usage

### Configuration

Secret's Garden can be configured via environment variables or config files:

```bash
# Set custom vault directory
export SECRETS_GARDEN_VAULT_DIR="$HOME/my-secrets"

# Customize session timeout (in seconds)
export SECRETS_GARDEN_VAULT__SESSION_TIMEOUT=7200

# Disable colored output
export SECRETS_GARDEN_CLI__COLOR_OUTPUT=false
```

### Multiple Vaults

```bash
# Work with different vaults
secrets-garden --vault personal init
secrets-garden --vault work init

# Add secrets to specific vaults
secrets-garden --vault personal add github-token
secrets-garden --vault work add company-api-key

# List secrets from specific vault
secrets-garden --vault personal list
```

### Scripting and Automation

```bash
# Non-interactive secret addition
echo "my-secret-value" | secrets-garden add my-secret --value -

# Batch operations with JSON
secrets-garden export secrets.json
# Modify JSON as needed
secrets-garden import secrets.json

# Use in scripts
if secrets-garden get api-key --quiet; then
    echo "API key found"
else
    echo "API key missing"
    exit 1
fi
```

## 📋 Examples

### Web Development Workflow

```bash
# Create a project vault
secrets-garden init my-webapp --description "My Web App Secrets"

# Add development secrets
secrets-garden add database-url --value "postgresql://localhost/myapp_dev"
secrets-garden add jwt-secret --value "dev-secret-key"
secrets-garden add stripe-key --value "sk_test_..." --tag payment

# Add production secrets
secrets-garden add prod-database-url --value "postgresql://prod-server/myapp"
secrets-garden add prod-jwt-secret --value "prod-secret-key" --tag production
secrets-garden add prod-stripe-key --value "sk_live_..." --tag payment --tag production

# Run development server with secrets
secrets-garden run -- python manage.py runserver

# Export production secrets for deployment
secrets-garden export prod-secrets.env --format env --include-values --tag production
```

### DevOps Integration

```bash
# Store infrastructure secrets
secrets-garden add aws-access-key --description "AWS deployment key"
secrets-garden add docker-registry-token --description "Private registry access"
secrets-garden add k8s-secret --description "Kubernetes cluster secret"

# Use in deployment scripts
secrets-garden run -- terraform apply
secrets-garden run -- kubectl apply -f deployment.yaml

# Backup before infrastructure changes
secrets-garden backup ~/infra-backups/$(date +%Y%m%d)
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/harryschoeller/secrets-garden.git
cd secrets-garden

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run with coverage
pytest --cov=secrets_garden
```

### Security

If you discover a security vulnerability, please send an email to security@secrets-garden.dev. We take security seriously and will address issues promptly.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔮 Roadmap

- [ ] **Plugin system** for custom integrations
- [ ] **Web UI** for browser-based management
- [ ] **Team vaults** with shared access controls
- [ ] **Hardware security module** (HSM) support
- [ ] **Biometric authentication** integration
- [ ] **Mobile companion app** for secure access
- [ ] **Git hooks** for secret scanning
- [ ] **Cloud backup** with client-side encryption

## 💬 Support

- 📖 [Documentation](https://docs.secrets-garden.dev)
- 🐛 [Issue Tracker](https://github.com/harryschoeller/secrets-garden/issues)
- 💬 [Discussions](https://github.com/harryschoeller/secrets-garden/discussions)
- 📧 [Email Support](mailto:support@secrets-garden.dev)

## 🙏 Acknowledgments

- Built with [Typer](https://typer.tiangolo.com/) for the CLI framework
- Powered by [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- Secured by [cryptography](https://cryptography.io/) for encryption
- Inspired by [pass](https://www.passwordstore.org/) and other password managers

---

<div align="center">
  <strong>🌱 Keep your secrets safe with Secret's Garden 🌱</strong>
</div>