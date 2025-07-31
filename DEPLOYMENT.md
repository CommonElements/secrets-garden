# Production Deployment Guide

This guide covers best practices for deploying Secret's Garden in production environments, including security considerations, monitoring, and operational procedures.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Security Hardening](#security-hardening)
- [Configuration Management](#configuration-management)
- [Backup and Recovery](#backup-and-recovery)
- [Monitoring and Logging](#monitoring-and-logging)
- [Operational Procedures](#operational-procedures)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux (recommended), macOS, or Windows
- **Python**: 3.9 or higher
- **Memory**: Minimum 512MB RAM
- **Storage**: Minimum 100MB free space
- **Network**: No inbound network access required (local-first design)

### Security Requirements

- Secure file system with appropriate permissions
- Regular security updates for the operating system
- Access control for user accounts
- Encrypted storage (recommended)

## Installation Methods

### Method 1: PyPI Installation (Recommended)

```bash
# Create dedicated user (Linux/macOS)
sudo useradd -m -s /bin/bash secrets-garden
sudo passwd secrets-garden

# Switch to dedicated user
sudo su - secrets-garden

# Install in virtual environment
python3 -m venv ~/.secrets-garden-env
source ~/.secrets-garden-env/bin/activate
pip install secrets-garden

# Verify installation
secrets-garden --version
```

### Method 2: From Source

```bash
# Clone repository
git clone https://github.com/CommonElements/secrets-garden.git
cd secrets-garden

# Install in virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -e ".[all]"

# Run tests
pytest

# Verify installation
python -m secrets_garden --version
```

### Method 3: Docker Deployment

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -s /bin/bash secrets-garden

# Install secrets-garden
RUN pip install secrets-garden

# Switch to non-root user
USER secrets-garden
WORKDIR /home/secrets-garden

# Set up volume for data persistence
VOLUME ["/home/secrets-garden/.secrets-garden"]

# Default command
CMD ["secrets-garden", "--help"]
```

```bash
# Build and run
docker build -t secrets-garden .
docker run -it -v secrets-data:/home/secrets-garden/.secrets-garden secrets-garden
```

## Security Hardening

### File System Permissions

```bash
# Set restrictive permissions on config directory
chmod 700 ~/.secrets-garden
chmod 600 ~/.secrets-garden/config.json
chmod 600 ~/.secrets-garden/vaults/*/vault.json
chmod 600 ~/.secrets-garden/vaults/*/secrets.db
```

### Environment Security

```bash
# Disable core dumps
echo "* soft core 0" >> /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf

# Set secure umask
echo "umask 077" >> ~/.bashrc

# Clear sensitive environment variables
unset HISTFILE
export HISTSIZE=0
```

### User Account Security

```bash
# Lock password authentication (use SSH keys only)
sudo passwd -l secrets-garden

# Restrict sudo access (if needed)
echo "secrets-garden ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart secrets-garden" >> /etc/sudoers.d/secrets-garden
```

## Configuration Management

### Production Configuration

Create a production configuration file:

```json
{
  "vault": {
    "default_vault_name": "production",
    "data_dir": "/var/lib/secrets-garden/vaults",
    "session_timeout": 1800
  },
  "security": {
    "clear_clipboard_timeout": 30,
    "require_password_validation": true,
    "max_failed_attempts": 3,
    "lockout_duration": 300
  },
  "cli": {
    "verbose": false,
    "colored_output": false
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/secrets-garden/secrets-garden.log"
  }
}
```

### Environment Variables

```bash
# Set production environment
export SECRETS_GARDEN_ENV=production
export SECRETS_GARDEN_CONFIG_DIR=/etc/secrets-garden
export SECRETS_GARDEN_DATA_DIR=/var/lib/secrets-garden
export SECRETS_GARDEN_LOG_LEVEL=INFO
```

### Systemd Service (Linux)

Create `/etc/systemd/system/secrets-garden.service`:

```ini
[Unit]
Description=Secret's Garden Secrets Manager
After=network.target

[Service]
Type=oneshot
User=secrets-garden
Group=secrets-garden
WorkingDirectory=/home/secrets-garden
Environment=SECRETS_GARDEN_ENV=production
Environment=SECRETS_GARDEN_CONFIG_DIR=/etc/secrets-garden
ExecStart=/home/secrets-garden/.secrets-garden-env/bin/secrets-garden info
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable secrets-garden
sudo systemctl start secrets-garden
sudo systemctl status secrets-garden
```

## Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /usr/local/bin/secrets-garden-backup.sh

BACKUP_DIR="/var/backups/secrets-garden"
VAULT_DIR="/var/lib/secrets-garden/vaults"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup all vaults
for vault in "$VAULT_DIR"/*; do
    if [ -d "$vault" ]; then
        vault_name=$(basename "$vault")
        backup_file="$BACKUP_DIR/${vault_name}_${DATE}.tar.gz"
        
        # Create encrypted backup
        tar -czf - -C "$VAULT_DIR" "$vault_name" | \
        gpg --symmetric --cipher-algo AES256 --compress-algo 1 \
            --output "$backup_file.gpg"
        
        echo "Backup created: $backup_file.gpg"
    fi
done

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.gpg" -mtime +30 -delete
```

### Backup Cron Job

```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * /usr/local/bin/secrets-garden-backup.sh >> /var/log/secrets-garden/backup.log 2>&1
```

### Recovery Procedure

```bash
# Restore from backup
gpg --decrypt vault_backup_20240130_020001.tar.gz.gpg | \
tar -xzf - -C /var/lib/secrets-garden/vaults/

# Verify vault integrity
secrets-garden info vault_name

# Test secret retrieval
secrets-garden get test_secret --show
```

## Monitoring and Logging

### Log Configuration

```json
{
  "logging": {
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
      "detailed": {
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
      }
    },
    "handlers": {
      "file": {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": "/var/log/secrets-garden/secrets-garden.log",
        "maxBytes": 10485760,
        "backupCount": 5,
        "formatter": "detailed"
      },
      "syslog": {
        "class": "logging.handlers.SysLogHandler",
        "address": "/dev/log",
        "formatter": "detailed"
      }
    },
    "loggers": {
      "secrets_garden": {
        "handlers": ["file", "syslog"],
        "level": "INFO",
        "propagate": false
      }
    }
  }
}
```

### Monitoring Script

```bash
#!/bin/bash
# /usr/local/bin/secrets-garden-monitor.sh

VAULT_DIR="/var/lib/secrets-garden/vaults"
LOG_FILE="/var/log/secrets-garden/monitor.log"

check_vault_integrity() {
    local vault_name=$1
    local vault_path="$VAULT_DIR/$vault_name"
    
    if [ ! -f "$vault_path/vault.json" ]; then
        echo "$(date): ERROR - Vault config missing: $vault_name" >> "$LOG_FILE"
        return 1
    fi
    
    if [ ! -f "$vault_path/secrets.db" ]; then
        echo "$(date): ERROR - Vault database missing: $vault_name" >> "$LOG_FILE"
        return 1
    fi
    
    # Check file permissions
    local config_perms=$(stat -c %a "$vault_path/vault.json")
    local db_perms=$(stat -c %a "$vault_path/secrets.db")
    
    if [ "$config_perms" != "600" ] || [ "$db_perms" != "600" ]; then
        echo "$(date): WARNING - Incorrect permissions on vault: $vault_name" >> "$LOG_FILE"
    fi
    
    echo "$(date): INFO - Vault integrity check passed: $vault_name" >> "$LOG_FILE"
    return 0
}

# Check all vaults
for vault in "$VAULT_DIR"/*; do
    if [ -d "$vault" ]; then
        vault_name=$(basename "$vault")
        check_vault_integrity "$vault_name"
    fi
done
```

### Alerting

```bash
# Monitor for failed login attempts
tail -f /var/log/secrets-garden/secrets-garden.log | \
grep "Too many failed attempts" | \
while read line; do
    echo "$line" | mail -s "Security Alert: Failed login attempts" admin@example.com
done
```

## Operational Procedures

### Regular Maintenance

```bash
#!/bin/bash
# Weekly maintenance script

# Rotate encryption keys (recommended monthly)
secrets-garden rotate-key production --no-backup

# Clean up old session files
find ~/.secrets-garden/sessions -mtime +1 -delete

# Verify vault integrity
secrets-garden info production

# Update software (if managed via package manager)
pip install --upgrade secrets-garden
```

### Key Rotation Schedule

```bash
# Monthly key rotation via cron
0 3 1 * * /usr/local/bin/rotate-keys.sh >> /var/log/secrets-garden/rotation.log 2>&1
```

### Security Incident Response

1. **Suspected Compromise**:
   ```bash
   # Lock all vaults immediately
   secrets-garden lock --all
   
   # Change master passwords
   secrets-garden change-password production
   
   # Rotate encryption keys
   secrets-garden rotate-key production
   
   # Review audit logs
   grep "SECURITY" /var/log/secrets-garden/secrets-garden.log
   ```

2. **Data Recovery**:
   ```bash
   # Restore from backup
   restore-vault-backup production
   
   # Verify data integrity
   secrets-garden list production
   ```

## Performance Optimization

### Large Vaults

For vaults with 1000+ secrets:

```json
{
  "database": {
    "connection_pool_size": 10,
    "query_timeout": 30,
    "bulk_operations": true
  },
  "memory": {
    "cache_size": "100MB",
    "preload_frequently_used": true
  }
}
```

### Network Storage

When using network-attached storage:

```json
{
  "storage": {
    "sync_writes": true,
    "file_locking": true,
    "backup_on_network": false
  }
}
```

## Compliance and Auditing

### Audit Logging

Enable comprehensive audit logging:

```json
{
  "audit": {
    "enabled": true,
    "log_file": "/var/log/secrets-garden/audit.log",
    "log_level": "DEBUG",
    "include_metadata": true,
    "retention_days": 365
  }
}
```

### Compliance Checklist

- [ ] Encryption at rest (AES-256-GCM)
- [ ] Strong password policies enforced
- [ ] Regular key rotation (monthly)
- [ ] Comprehensive audit logging
- [ ] Secure backup procedures
- [ ] Access control and monitoring
- [ ] Incident response procedures
- [ ] Regular security updates

### GDPR Compliance

```bash
# Data export for GDPR requests
secrets-garden export production --format json --include-values

# Data deletion
secrets-garden delete secret_name --force
secrets-garden rotate-key production  # Ensures deleted data is cryptographically erased
```

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   # Fix file permissions
   chmod 700 ~/.secrets-garden
   chmod 600 ~/.secrets-garden/vaults/*/vault.json
   ```

2. **Database Corruption**:
   ```bash
   # Restore from backup
   restore-vault-backup vault_name
   
   # Or repair database
   sqlite3 vault.db ".recover" > vault_recovered.db
   ```

3. **Memory Issues**:
   ```bash
   # Monitor memory usage
   ps aux | grep secrets-garden
   
   # Optimize configuration
   export SECRETS_GARDEN_MEMORY_LIMIT=256MB
   ```

### Support and Updates

- Monitor [GitHub releases](https://github.com/CommonElements/secrets-garden/releases) for updates
- Subscribe to security advisories
- Join the [discussions](https://github.com/CommonElements/secrets-garden/discussions) for community support

---

For additional support or security concerns, please refer to our [Security Policy](SECURITY.md) or open an issue on GitHub.