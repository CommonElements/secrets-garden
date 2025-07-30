# Security Policy

## Overview

Secret's Garden takes security seriously. This document outlines our security model, implementation details, and how to report security vulnerabilities.

## Security Model

### Threat Model

Secret's Garden is designed to protect against:

- **Local file system access** by unauthorized users
- **Memory dumps** and swap file exposure
- **Weak encryption** and cryptographic vulnerabilities
- **Brute force attacks** against stored secrets
- **Side-channel attacks** through timing analysis

### Assumptions

Our security model assumes:

- The operating system and underlying hardware are trustworthy
- The user's system is not compromised by malware
- The user follows reasonable security practices (strong passwords, etc.)
- Physical access to the system is controlled

## Cryptographic Implementation

### Encryption Algorithm

- **Algorithm**: AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode)
- **Key size**: 256 bits
- **Mode**: Authenticated encryption with associated data (AEAD)
- **Benefits**: 
  - Provides both confidentiality and authenticity
  - Resistance against chosen-ciphertext attacks
  - Parallel encryption/decryption for performance

### Key Derivation

- **Function**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (OWASP recommended minimum for 2023)
- **Salt size**: 256 bits (32 bytes)
- **Output size**: 256 bits (32 bytes)
- **Benefits**:
  - Resistance against rainbow table attacks
  - Protection against brute force attacks
  - Unique keys even with identical passwords

### Random Number Generation

- **Source**: Cryptographically secure pseudorandom number generator (CSPRNG)
- **Implementation**: Python's `secrets` module
- **Usage**: Salt generation, nonce generation, key material
- **Entropy**: System-provided entropy sources

### Memory Safety

- **Key material**: Explicitly cleared from memory after use
- **Sensitive data**: Minimized time in memory
- **Password handling**: Secure input methods where possible
- **Limitations**: Python's memory management makes complete erasure difficult

## Implementation Details

### Data Storage

```
Vault Structure:
├── vault.json          # Configuration and password hash
└── secrets.db          # Encrypted secrets database

Configuration File (vault.json):
{
  "version": "1.0",
  "created_at": <timestamp>,
  "description": "<user description>",
  "password_salt": "<hex-encoded salt>",
  "password_hash": "<hex-encoded hash>",
  "encryption": {
    "algorithm": "AES-256-GCM",
    "kdf": "PBKDF2-HMAC-SHA256",
    "iterations": 600000
  }
}

Database Schema:
secrets (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  tags TEXT DEFAULT '',
  ciphertext BLOB NOT NULL,     # Encrypted secret value
  nonce BLOB NOT NULL,          # 96-bit GCM nonce
  tag BLOB NOT NULL,            # 128-bit authentication tag
  salt BLOB NOT NULL,           # 256-bit PBKDF2 salt
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
)
```

### Encryption Process

1. **Password derivation**: Master password + unique salt → encryption key
2. **Nonce generation**: Generate unique 96-bit nonce for GCM
3. **Encryption**: AES-256-GCM(plaintext, key, nonce) → ciphertext + auth_tag
4. **Storage**: Store ciphertext, nonce, auth_tag, and salt

### Decryption Process

1. **Password derivation**: Master password + stored salt → encryption key
2. **Decryption**: AES-256-GCM-decrypt(ciphertext, key, nonce, auth_tag) → plaintext
3. **Verification**: Authentication tag automatically verified during decryption
4. **Cleanup**: Clear sensitive data from memory

### Session Management

- **Timeout**: Configurable session timeout (default: 1 hour)
- **Auto-lock**: Automatic locking after inactivity
- **Memory clearing**: Session credentials cleared on lock
- **Re-authentication**: Required after session expiry

## Security Features

### Authentication

- **Master password**: Single factor authentication
- **Password verification**: Constant-time comparison to prevent timing attacks
- **Failed attempts**: No built-in attempt limiting (relies on OS protection)

### Authorization

- **File permissions**: Vault files created with restrictive permissions (600)
- **Directory permissions**: Vault directories use standard permissions
- **Process isolation**: No privilege escalation or special permissions required

### Data Integrity

- **Authentication tags**: GCM mode provides built-in integrity verification
- **Database integrity**: SQLite built-in integrity checking
- **Backup verification**: Backup integrity can be verified by attempting to unlock

### Protection Against Common Attacks

#### Brute Force Attacks
- High iteration count (600,000) makes password cracking expensive
- Unique salts prevent rainbow table attacks
- No network component eliminates remote brute force

#### Timing Attacks
- Constant-time password comparisons
- Consistent operation timing regardless of success/failure

#### Memory Analysis
- Explicit memory clearing for sensitive data
- Minimal time sensitive data spends in memory
- No persistent storage of plaintext secrets

## Security Best Practices

### For Users

1. **Strong passwords**: Use long, complex master passwords
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, and symbols
   - Consider using passphrases (multiple words)

2. **System security**: Protect your local system
   - Use full-disk encryption
   - Enable screen locks and automatic locking
   - Keep OS and software updated
   - Use reputable antivirus software

3. **Backup security**: Protect vault backups
   - Store backups in secure locations
   - Encrypt backup storage media
   - Regularly test backup restoration

4. **Access control**: Limit who can access your system
   - Use separate user accounts
   - Avoid sharing systems with untrusted users
   - Monitor system access logs

### For Developers

1. **Dependency management**: Keep cryptographic libraries updated
2. **Code review**: Security-focused code reviews for crypto code
3. **Testing**: Comprehensive security testing including edge cases
4. **Documentation**: Keep security documentation current

## Known Limitations

### Current Limitations

1. **Single factor auth**: Only password-based authentication
2. **Memory clearing**: Cannot guarantee complete memory erasure in Python
3. **Platform dependent**: Security properties depend on underlying OS
4. **No HSM support**: Cannot use hardware security modules
5. **No key rotation**: Encryption keys are not automatically rotated

### Planned Improvements

- Multi-factor authentication support
- Hardware security module integration
- Automatic key rotation
- Enhanced memory protection
- Biometric authentication

## Vulnerability Reporting

### Reporting Process

If you discover a security vulnerability in Secret's Garden:

1. **Do not** open a public issue
2. **Do not** disclose the vulnerability publicly
3. **Do** send details to: security@secrets-garden.dev
4. **Do** include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if known)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix development**: Depends on severity and complexity
- **Public disclosure**: After fix is available and deployed

### Scope

Security issues in scope:
- Cryptographic implementation flaws
- Authentication/authorization bypasses
- Data exposure vulnerabilities
- Code execution vulnerabilities
- Denial of service attacks

Out of scope:
- Social engineering attacks
- Physical access attacks
- Operating system vulnerabilities
- Third-party dependency issues (report to respective projects)

## Security Audits

### Internal Security Reviews

- Regular code reviews with security focus
- Automated security scanning with tools like bandit
- Dependency vulnerability scanning
- Cryptographic implementation reviews

### External Security Audits

- Professional security audits are planned
- Results will be published when available
- Community security reviews are welcome

## Compliance and Standards

### Standards Followed

- **OWASP**: Following OWASP guidelines for secure development
- **NIST**: Alignment with NIST cryptographic standards
- **RFC Standards**: Implementation follows relevant RFCs

### Certifications

- No formal certifications at this time
- Open to pursuing relevant certifications based on user needs

## Security Contact

For security-related questions or concerns:

- **Email**: security@secrets-garden.dev
- **PGP Key**: Available on request
- **Response time**: Best effort within 48 hours

---

*This security policy is a living document and will be updated as the project evolves.*