# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Active support  |

## Security Features

InfraCode implements defense-in-depth security:

- **Encryption at Rest**: AES-256-GCM for all state files and secrets
- **Encryption in Transit**: TLS 1.3 for API communications
- **Secret Management**: Integrated vault with support for HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- **RBAC**: Role-based access control with least-privilege defaults
- **Audit Logging**: Immutable JSON audit trail for all operations
- **Input Validation**: Strict schema validation on all templates and API inputs
- **Dependency Scanning**: Automated CVE scanning in CI pipeline
- **State File Protection**: Encrypted, locked, and integrity-verified state files
- **Compliance Engine**: CIS, NIST, PCI DSS policy enforcement

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Email**: Site@hotmail.com
2. **Subject**: `[SECURITY] InfraCode Vulnerability Report`
3. **Include**: Description, reproduction steps, impact assessment
4. **Do NOT** open a public GitHub issue for security vulnerabilities

We will respond within 48 hours and provide a fix timeline within 7 days.

## Security Hardening Checklist

- [ ] Change default `INFRACODE_SECRET_KEY` in `.env`
- [ ] Enable encryption for state backend
- [ ] Configure RBAC with least-privilege roles
- [ ] Enable audit logging
- [ ] Use remote state backend with access controls
- [ ] Rotate encryption keys periodically
- [ ] Enable TLS for API server in production
- [ ] Review compliance policies for your environment
