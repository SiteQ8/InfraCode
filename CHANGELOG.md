# Changelog

## [1.0.0] - 2026-03-08

### Added
- **Core Engine**: Template parser with YAML/JSON support, variable interpolation, dependency graph
- **State Management**: Encrypted state files (AES-256-GCM), locking, versioning, rollback
- **Plan Engine**: Diff-based execution plans with field-level change detection
- **AWS Provider**: VPC, EC2, S3, RDS, EKS, Lambda, IAM, ALB, Security Groups
- **Azure Provider**: Resource Group, VNet, Subnet, NSG, VM, Storage, AKS, SQL, Key Vault
- **GCP Provider**: VPC, Subnet, Compute, GCS, Cloud SQL, GKE, Firewall, Cloud Functions
- **Kubernetes Provider**: Namespace, Deployment, Service, Ingress, ConfigMap, Secret, PVC, NetworkPolicy, ServiceAccount, RBAC
- **Security Scanner**: 12 built-in rules detecting misconfigurations (public access, encryption, SSH exposure, hardcoded secrets)
- **Compliance Engine**: CIS AWS Benchmarks, NIST 800-53, PCI DSS v4.0 policy enforcement
- **Secret Vault**: AES-256-GCM encrypted local vault with audit logging
- **Version Control**: Full change history with plan snapshots, rollback chain, Git integration
- **REST API**: FastAPI-based with CORS, audit middleware, full CRUD endpoints
- **Interactive GUI**: React SPA with dashboard, template editor, resource viewer, security scanner, compliance reports
- **CLI**: Full command-line interface (init, validate, plan, apply, scan, compliance, state, history)
- **Reusable Modules**: Networking, Compute, Storage, Database patterns
- **Templates**: Production-ready templates for AWS, Azure, GCP, Kubernetes
- **Docker Support**: Dockerfile + docker-compose for containerized deployment
- **Test Suite**: Comprehensive tests for engine, state, security, and encryption
