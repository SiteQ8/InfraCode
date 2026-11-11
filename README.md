# InfraCode: Infrastructure as Code Platform

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/security-hardened-red.svg" alt="Security">
</p>

**InfraCode** is a production-grade Infrastructure as Code (IaC) platform that enables declarative infrastructure provisioning, state management, drift detection, versioning, and compliance enforcement across multi-cloud environments.

## Key Features

- **Multi-Cloud Providers**: AWS, Azure, GCP, Kubernetes, unified template syntax
- **State Management**: Encrypted state files with locking, remote backends, and rollback
- **Version Control**: Full infrastructure versioning with diff, history, and rollback
- **Plan & Apply**: Preview changes before applying, never deploy blind
- **Drift Detection**: Continuous monitoring for configuration drift from desired state
- **Security Hardened**: AES-256-GCM encryption, secret vault, RBAC, audit logging
- **Compliance Engine**: CIS Benchmarks, NIST 800-53, PCI DSS v4.0, custom policies
- **Interactive GUI**: Browser-based visual infrastructure designer and manager
- **CLI & API**: Full CLI for automation + REST API for integration
- **Modular Architecture**: Reusable modules for networking, compute, storage, databases

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   InfraCode GUI                       │
│            (React SPA — Visual Designer)              │
├──────────────────────────────────────────────────────┤
│                    REST API Layer                      │
│              (FastAPI + Auth Middleware)               │
├──────────┬──────────┬───────────┬────────────────────┤
│ Planning │  State   │ Versioning│    Compliance       │
│  Engine  │ Manager  │  Control  │     Engine          │
├──────────┴──────────┴───────────┴────────────────────┤
│                  Core IaC Engine                       │
│         (Template Parser + Resource Graph)             │
├──────────┬──────────┬───────────┬────────────────────┤
│   AWS    │  Azure   │   GCP     │   Kubernetes        │
│ Provider │ Provider │ Provider  │    Provider         │
└──────────┴──────────┴───────────┴────────────────────┘
```

## Quick Start

```bash
# Clone
git clone https://github.com/SiteQ8/InfraCode.git
cd InfraCode

# Install
pip install -r requirements.txt

# Initialize a new project
python -m cli.main init my-infrastructure

# Validate templates
python -m cli.main validate templates/aws/vpc.yaml

# Plan changes
python -m cli.main plan --config infrastructure.yaml

# Apply changes
python -m cli.main apply --config infrastructure.yaml --auto-approve

# Check compliance
python -m cli.main compliance --policy policies/cis_benchmarks.yaml

# Launch GUI
python -m api.server
# Open http://localhost:8080
```

## Docker

```bash
docker-compose up -d
# GUI: http://localhost:8080
# API: http://localhost:8000
```

## Project Structure

```
InfraCode/
├── core/               # Core IaC engine
│   ├── engine.py       # Template parser & resource graph
│   ├── state.py        # Encrypted state management
│   ├── plan.py         # Plan/diff engine
│   ├── providers/      # Cloud provider implementations
│   ├── security/       # Encryption, vault, scanner, compliance
│   ├── versioning/     # Version control & history
│   └── modules/        # Reusable infrastructure modules
├── templates/          # IaC templates (AWS, Azure, GCP, K8s)
├── policies/           # Compliance policies
├── cli/                # Command-line interface
├── api/                # REST API server
├── gui/                # Interactive web GUI
├── tests/              # Test suite
└── docs/               # Documentation
```

## Author

**Ali AlEnezi**, [@SiteQ8](https://github.com/SiteQ8)

## License

MIT License, see [LICENSE](LICENSE) for details.
