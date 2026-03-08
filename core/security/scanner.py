"""
InfraCode Security Scanner
Static analysis of IaC templates for security misconfigurations.
"""

import re
import logging
from typing import Any
from dataclasses import dataclass, field

logger = logging.getLogger("infracode.security.scanner")


@dataclass
class Finding:
    """A security finding from template scanning."""
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    resource_id: str
    resource_type: str
    title: str
    description: str
    remediation: str = ""
    cwe: str = ""
    framework_refs: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "framework_refs": self.framework_refs,
        }


# Security rules database
SECURITY_RULES = [
    {
        "id": "SEC001",
        "title": "S3 Bucket Public Access",
        "severity": "CRITICAL",
        "types": ["aws_s3_bucket"],
        "check": lambda cfg: cfg.get("acl") in ("public-read", "public-read-write"),
        "description": "S3 bucket allows public access which may expose sensitive data",
        "remediation": "Set acl to 'private' and enable public_access_block",
        "cwe": "CWE-284",
        "frameworks": ["CIS AWS 2.1.5", "NIST AC-3", "PCI DSS 7.1"],
    },
    {
        "id": "SEC002",
        "title": "Unencrypted S3 Bucket",
        "severity": "HIGH",
        "types": ["aws_s3_bucket"],
        "check": lambda cfg: not cfg.get("encryption"),
        "description": "S3 bucket does not have server-side encryption enabled",
        "remediation": "Enable SSE-S3 or SSE-KMS encryption",
        "cwe": "CWE-311",
        "frameworks": ["CIS AWS 2.1.1", "NIST SC-28", "PCI DSS 3.4"],
    },
    {
        "id": "SEC003",
        "title": "Security Group Allows All Inbound",
        "severity": "CRITICAL",
        "types": ["aws_security_group", "azure_nsg"],
        "check": lambda cfg: any(
            r.get("cidr_blocks", r.get("source", "")) in ("0.0.0.0/0", "*")
            and r.get("from_port", r.get("port", 0)) == 0
            for r in cfg.get("ingress", cfg.get("rules", []))
            if isinstance(r, dict)
        ),
        "description": "Security group allows unrestricted inbound traffic on all ports",
        "remediation": "Restrict inbound rules to specific ports and source CIDRs",
        "cwe": "CWE-284",
        "frameworks": ["CIS AWS 5.2", "NIST AC-4", "PCI DSS 1.2"],
    },
    {
        "id": "SEC004",
        "title": "SSH Port Open to Internet",
        "severity": "HIGH",
        "types": ["aws_security_group", "azure_nsg", "gcp_firewall_rule"],
        "check": lambda cfg: any(
            r.get("cidr_blocks", r.get("source_ranges", [""])) in (["0.0.0.0/0"], "0.0.0.0/0")
            and (r.get("from_port", r.get("port", 0)) <= 22 <= r.get("to_port", r.get("port", 0))
                 or 22 in r.get("ports", []))
            for r in cfg.get("ingress", cfg.get("rules", cfg.get("allowed", [])))
            if isinstance(r, dict)
        ),
        "description": "SSH port (22) is open to the entire internet",
        "remediation": "Restrict SSH access to specific trusted IP ranges or use a bastion host",
        "cwe": "CWE-284",
        "frameworks": ["CIS AWS 5.2", "NIST AC-17"],
    },
    {
        "id": "SEC005",
        "title": "RDS Not Encrypted",
        "severity": "HIGH",
        "types": ["aws_rds_instance", "azure_sql_database", "gcp_cloud_sql"],
        "check": lambda cfg: not cfg.get("storage_encrypted", cfg.get("encryption", False)),
        "description": "Database instance storage is not encrypted",
        "remediation": "Enable storage encryption with a KMS key",
        "cwe": "CWE-311",
        "frameworks": ["CIS AWS 2.3.1", "NIST SC-28", "PCI DSS 3.4"],
    },
    {
        "id": "SEC006",
        "title": "RDS Publicly Accessible",
        "severity": "CRITICAL",
        "types": ["aws_rds_instance"],
        "check": lambda cfg: cfg.get("publicly_accessible", False),
        "description": "Database instance is publicly accessible from the internet",
        "remediation": "Set publicly_accessible to false and use VPC security groups",
        "cwe": "CWE-284",
        "frameworks": ["CIS AWS 2.3.2", "NIST AC-3"],
    },
    {
        "id": "SEC007",
        "title": "No Multi-AZ for Database",
        "severity": "MEDIUM",
        "types": ["aws_rds_instance"],
        "check": lambda cfg: not cfg.get("multi_az", False),
        "description": "Database does not have Multi-AZ deployment for high availability",
        "remediation": "Enable multi_az for production databases",
        "cwe": "",
        "frameworks": ["NIST CP-10"],
    },
    {
        "id": "SEC008",
        "title": "EKS/AKS/GKE Public API Server",
        "severity": "HIGH",
        "types": ["aws_eks_cluster", "azure_aks_cluster", "gcp_gke_cluster"],
        "check": lambda cfg: cfg.get("endpoint_public_access", cfg.get("public_cluster", True)),
        "description": "Kubernetes cluster API server is publicly accessible",
        "remediation": "Disable public access and use VPN or private endpoints",
        "cwe": "CWE-284",
        "frameworks": ["CIS K8s 3.1.1", "NIST AC-3"],
    },
    {
        "id": "SEC009",
        "title": "Container Running as Root",
        "severity": "HIGH",
        "types": ["k8s_deployment"],
        "check": lambda cfg: any(
            c.get("security_context", {}).get("run_as_root", False)
            or c.get("security_context", {}).get("run_as_user", 1) == 0
            for c in cfg.get("containers", [])
            if isinstance(c, dict)
        ),
        "description": "Container is configured to run as root user",
        "remediation": "Set runAsNonRoot: true and specify a non-root runAsUser",
        "cwe": "CWE-250",
        "frameworks": ["CIS K8s 5.2.6", "NIST AC-6"],
    },
    {
        "id": "SEC010",
        "title": "Missing Network Policy",
        "severity": "MEDIUM",
        "types": ["k8s_namespace"],
        "check": lambda cfg: not cfg.get("network_policies", False),
        "description": "Namespace has no network policies — all pod-to-pod traffic is allowed",
        "remediation": "Define NetworkPolicy resources to restrict pod communication",
        "cwe": "CWE-284",
        "frameworks": ["CIS K8s 5.3.2", "NIST AC-4"],
    },
    {
        "id": "SEC011",
        "title": "HTTPS Not Enforced on Storage",
        "severity": "MEDIUM",
        "types": ["azure_storage_account"],
        "check": lambda cfg: not cfg.get("https_only", True),
        "description": "Storage account does not enforce HTTPS-only access",
        "remediation": "Set https_only to true",
        "cwe": "CWE-319",
        "frameworks": ["CIS Azure 3.1", "NIST SC-8"],
    },
    {
        "id": "SEC012",
        "title": "Hardcoded Credentials Detected",
        "severity": "CRITICAL",
        "types": ["*"],
        "check": lambda cfg: _check_hardcoded_secrets(cfg),
        "description": "Template contains potential hardcoded credentials or API keys",
        "remediation": "Use vault references ${vault.secret_name} instead of hardcoded values",
        "cwe": "CWE-798",
        "frameworks": ["CIS General", "NIST IA-5", "PCI DSS 6.5.3"],
    },
]


def _check_hardcoded_secrets(config: dict) -> bool:
    """Detect potential hardcoded secrets in configuration."""
    secret_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),              # AWS Access Key
        re.compile(r"[a-zA-Z0-9/+]{40}"),              # AWS Secret Key
        re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY"), # Private keys
        re.compile(r"password\s*[:=]\s*['\"][^'\"]+"),    # Passwords
        re.compile(r"api[_-]?key\s*[:=]\s*['\"][^'\"]+"), # API keys
        re.compile(r"secret\s*[:=]\s*['\"][^'\"]{8,}"),   # Generic secrets
    ]

    config_str = str(config)
    for pattern in secret_patterns:
        if pattern.search(config_str):
            return True
    return False


class SecurityScanner:
    """Scan IaC templates for security misconfigurations."""

    def __init__(self, custom_rules: list = None):
        self.rules = SECURITY_RULES + (custom_rules or [])

    def scan_template(self, template) -> list[Finding]:
        """Scan all resources in a template."""
        findings = []
        for resource in template.resources:
            resource_findings = self.scan_resource(resource)
            findings.extend(resource_findings)
        return findings

    def scan_resource(self, resource) -> list[Finding]:
        """Scan a single resource against all applicable rules."""
        findings = []
        for rule in self.rules:
            applicable_types = rule.get("types", [])
            if "*" in applicable_types or resource.type in applicable_types:
                try:
                    if rule["check"](resource.config):
                        findings.append(Finding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            resource_id=resource.id,
                            resource_type=resource.type,
                            title=rule["title"],
                            description=rule["description"],
                            remediation=rule.get("remediation", ""),
                            cwe=rule.get("cwe", ""),
                            framework_refs=rule.get("frameworks", []),
                        ))
                except Exception as e:
                    logger.debug(f"Rule {rule['id']} check failed for {resource.id}: {e}")
        return findings

    def scan_config(self, resource_id: str, resource_type: str, config: dict) -> list[Finding]:
        """Scan a raw config dict (without Resource object)."""
        from core.engine import Resource
        resource = Resource(id=resource_id, type=resource_type, provider="", name=resource_id, config=config)
        return self.scan_resource(resource)

    def generate_report(self, findings: list[Finding]) -> dict:
        """Generate a summary report from findings."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "findings": [f.to_dict() for f in findings],
            "pass": severity_counts["CRITICAL"] == 0 and severity_counts["HIGH"] == 0,
            "score": max(0, 100 - (severity_counts["CRITICAL"] * 25 + severity_counts["HIGH"] * 10 + severity_counts["MEDIUM"] * 5 + severity_counts["LOW"] * 1)),
        }
