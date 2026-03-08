"""
InfraCode Compliance Engine
Policy-as-code enforcement for CIS Benchmarks, NIST 800-53, PCI DSS v4.0.
"""

import yaml
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("infracode.security.compliance")


@dataclass
class PolicyViolation:
    """A compliance policy violation."""
    policy_id: str
    framework: str
    control: str
    severity: str
    resource_id: str
    resource_type: str
    description: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "framework": self.framework,
            "control": self.control,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class ComplianceReport:
    """Full compliance assessment report."""
    framework: str
    assessed_at: str = ""
    total_controls: int = 0
    passing: int = 0
    failing: int = 0
    not_applicable: int = 0
    violations: list = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "assessed_at": self.assessed_at,
            "total_controls": self.total_controls,
            "passing": self.passing,
            "failing": self.failing,
            "not_applicable": self.not_applicable,
            "score": self.score,
            "violations": [v.to_dict() for v in self.violations],
        }


# Built-in compliance policies
BUILTIN_POLICIES = {
    "cis_aws": [
        {"id": "CIS-2.1.1", "control": "Ensure S3 bucket encryption", "framework": "CIS AWS",
         "types": ["aws_s3_bucket"], "severity": "HIGH",
         "check": lambda cfg: bool(cfg.get("encryption")),
         "remediation": "Enable SSE-S3 or SSE-KMS encryption on all S3 buckets"},
        {"id": "CIS-2.1.5", "control": "Ensure S3 bucket is not publicly accessible", "framework": "CIS AWS",
         "types": ["aws_s3_bucket"], "severity": "CRITICAL",
         "check": lambda cfg: cfg.get("acl", "private") == "private" and cfg.get("public_access_block", False),
         "remediation": "Set ACL to private and enable public access block"},
        {"id": "CIS-4.1", "control": "Ensure no security groups allow ingress 0.0.0.0/0 to port 22", "framework": "CIS AWS",
         "types": ["aws_security_group"], "severity": "HIGH",
         "check": lambda cfg: not any(
             "0.0.0.0/0" in str(r.get("cidr_blocks", "")) and 22 in range(r.get("from_port", 0), r.get("to_port", 0) + 1)
             for r in cfg.get("ingress", []) if isinstance(r, dict)),
         "remediation": "Restrict SSH access to specific trusted CIDRs"},
        {"id": "CIS-2.3.1", "control": "Ensure RDS encryption at rest", "framework": "CIS AWS",
         "types": ["aws_rds_instance"], "severity": "HIGH",
         "check": lambda cfg: cfg.get("storage_encrypted", False),
         "remediation": "Enable storage_encrypted with KMS key"},
    ],
    "nist_800_53": [
        {"id": "NIST-AC-3", "control": "Access Enforcement", "framework": "NIST 800-53",
         "types": ["aws_s3_bucket", "azure_storage_account", "gcp_gcs_bucket"], "severity": "HIGH",
         "check": lambda cfg: cfg.get("acl", "private") == "private",
         "remediation": "Enforce least-privilege access controls on storage resources"},
        {"id": "NIST-AC-4", "control": "Information Flow Enforcement", "framework": "NIST 800-53",
         "types": ["aws_security_group", "azure_nsg", "gcp_firewall_rule", "k8s_network_policy"], "severity": "HIGH",
         "check": lambda cfg: bool(cfg.get("ingress") or cfg.get("rules") or cfg.get("pod_selector")),
         "remediation": "Define explicit network flow rules"},
        {"id": "NIST-SC-28", "control": "Protection of Information at Rest", "framework": "NIST 800-53",
         "types": ["aws_s3_bucket", "aws_rds_instance", "azure_storage_account"], "severity": "HIGH",
         "check": lambda cfg: cfg.get("encryption", cfg.get("storage_encrypted", cfg.get("https_only", False))),
         "remediation": "Enable encryption at rest for all data stores"},
        {"id": "NIST-AU-2", "control": "Audit Events", "framework": "NIST 800-53",
         "types": ["aws_s3_bucket"], "severity": "MEDIUM",
         "check": lambda cfg: bool(cfg.get("logging")),
         "remediation": "Enable access logging on S3 buckets"},
    ],
    "pci_dss_v4": [
        {"id": "PCI-1.2", "control": "Restrict connections to untrusted networks", "framework": "PCI DSS v4.0",
         "types": ["aws_security_group", "azure_nsg"], "severity": "CRITICAL",
         "check": lambda cfg: not any(
             "0.0.0.0/0" in str(r) for r in cfg.get("ingress", cfg.get("rules", []))),
         "remediation": "Restrict all inbound rules to trusted network ranges"},
        {"id": "PCI-3.4", "control": "Render PAN unreadable anywhere it is stored", "framework": "PCI DSS v4.0",
         "types": ["aws_s3_bucket", "aws_rds_instance", "azure_storage_account", "azure_sql_database"],
         "severity": "CRITICAL",
         "check": lambda cfg: cfg.get("encryption", cfg.get("storage_encrypted", False)),
         "remediation": "Enable strong encryption (AES-256) for all data stores"},
        {"id": "PCI-6.5.3", "control": "Insecure cryptographic storage", "framework": "PCI DSS v4.0",
         "types": ["*"], "severity": "CRITICAL",
         "check": lambda cfg: not any(
             k in str(cfg).lower() for k in ["password=", "secret=", "api_key="]),
         "remediation": "Use vault references for all secrets — never hardcode credentials"},
        {"id": "PCI-7.1", "control": "Limit access to system components", "framework": "PCI DSS v4.0",
         "types": ["aws_iam_role", "k8s_rbac_role"], "severity": "HIGH",
         "check": lambda cfg: "*" not in str(cfg.get("policies", cfg.get("rules", []))),
         "remediation": "Implement least-privilege access — avoid wildcard permissions"},
    ],
}


class ComplianceEngine:
    """Evaluate infrastructure templates against compliance frameworks."""

    def __init__(self):
        self.policies = dict(BUILTIN_POLICIES)
        self.custom_policies: list = []

    def load_custom_policy(self, path: str):
        """Load a custom policy file (YAML)."""
        content = Path(path).read_text(encoding="utf-8")
        policy_data = yaml.safe_load(content)

        if isinstance(policy_data, dict) and "policies" in policy_data:
            for p in policy_data["policies"]:
                self.custom_policies.append(p)
            logger.info(f"Loaded {len(policy_data['policies'])} custom policies from {path}")

    def assess(self, template, frameworks: Optional[list] = None) -> list[ComplianceReport]:
        """Assess a template against one or more compliance frameworks."""
        from datetime import datetime, timezone

        if frameworks is None:
            frameworks = list(self.policies.keys())

        reports = []
        for framework in frameworks:
            policies = self.policies.get(framework, [])
            if not policies:
                continue

            report = ComplianceReport(
                framework=framework,
                assessed_at=datetime.now(timezone.utc).isoformat(),
                total_controls=len(policies),
            )

            for policy in policies:
                applicable_resources = [
                    r for r in template.resources
                    if "*" in policy.get("types", []) or r.type in policy.get("types", [])
                ]

                if not applicable_resources:
                    report.not_applicable += 1
                    continue

                policy_passed = True
                for resource in applicable_resources:
                    try:
                        if not policy["check"](resource.config):
                            policy_passed = False
                            report.violations.append(PolicyViolation(
                                policy_id=policy["id"],
                                framework=policy["framework"],
                                control=policy["control"],
                                severity=policy["severity"],
                                resource_id=resource.id,
                                resource_type=resource.type,
                                description=f"Failed: {policy['control']}",
                                remediation=policy.get("remediation", ""),
                            ))
                    except Exception as e:
                        logger.debug(f"Policy {policy['id']} check error on {resource.id}: {e}")

                if policy_passed:
                    report.passing += 1
                else:
                    report.failing += 1

            assessable = report.total_controls - report.not_applicable
            report.score = (report.passing / assessable * 100) if assessable > 0 else 100.0
            reports.append(report)

        return reports
