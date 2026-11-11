"""
InfraCode AWS Provider
Manages AWS infrastructure resources via boto3.
"""

import os
import logging
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from core.providers import BaseProvider

logger = logging.getLogger("infracode.providers.aws")


# Resource type schemas for validation
AWS_RESOURCE_SCHEMAS = {
    "aws_vpc": {
        "required": ["cidr_block"],
        "optional": ["enable_dns_support", "enable_dns_hostnames", "tags"],
        "immutable": ["cidr_block"],
    },
    "aws_subnet": {
        "required": ["vpc_id", "cidr_block", "availability_zone"],
        "optional": ["map_public_ip_on_launch", "tags"],
        "immutable": ["vpc_id", "cidr_block", "availability_zone"],
    },
    "aws_security_group": {
        "required": ["vpc_id", "name", "description"],
        "optional": ["ingress", "egress", "tags"],
        "immutable": ["vpc_id"],
    },
    "aws_ec2_instance": {
        "required": ["ami", "instance_type", "subnet_id"],
        "optional": ["key_name", "security_groups", "user_data", "tags", "ebs_optimized",
                      "monitoring", "iam_instance_profile", "root_block_device"],
        "immutable": ["ami", "subnet_id"],
    },
    "aws_s3_bucket": {
        "required": ["bucket"],
        "optional": ["acl", "versioning", "encryption", "lifecycle_rules",
                      "cors_rules", "logging", "tags", "public_access_block"],
        "immutable": ["bucket"],
    },
    "aws_rds_instance": {
        "required": ["engine", "instance_class", "allocated_storage"],
        "optional": ["db_name", "master_username", "master_password", "multi_az",
                      "storage_encrypted", "backup_retention_period", "vpc_security_group_ids",
                      "db_subnet_group_name", "tags"],
        "immutable": ["engine"],
    },
    "aws_eks_cluster": {
        "required": ["name", "role_arn", "vpc_config"],
        "optional": ["version", "encryption_config", "logging", "tags"],
        "immutable": ["name"],
    },
    "aws_lambda_function": {
        "required": ["function_name", "runtime", "role", "handler"],
        "optional": ["code", "memory_size", "timeout", "environment", "vpc_config", "tags"],
        "immutable": ["function_name"],
    },
    "aws_iam_role": {
        "required": ["name", "assume_role_policy"],
        "optional": ["description", "policies", "tags", "max_session_duration"],
        "immutable": ["name"],
    },
    "aws_load_balancer": {
        "required": ["name", "type", "subnets"],
        "optional": ["security_groups", "internal", "idle_timeout", "tags",
                      "access_logs", "listeners"],
        "immutable": ["name", "type"],
    },
}


class AWSProvider(BaseProvider):
    """AWS Cloud Provider for InfraCode."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.name = "aws"
        self._client_cache = {}
        self._region = config.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        self._provisioned: dict[str, dict] = {}

    def initialize(self) -> bool:
        """Initialize AWS provider: validate credentials."""
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=self.config.get("access_key_id", os.environ.get("AWS_ACCESS_KEY_ID")),
                aws_secret_access_key=self.config.get("secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY")),
                region_name=self._region,
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            logger.info(f"AWS authenticated as {identity['Arn']}")
            self._initialized = True
            return True
        except ImportError:
            logger.warning("boto3 not installed — AWS provider running in simulation mode")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"AWS initialization failed: {e}")
            return False

    def create(self, resource_id: str, resource_type: str, config: dict) -> dict:
        """Create an AWS resource."""
        logger.info(f"Creating {resource_type}: {resource_id}")

        result = {
            "resource_id": resource_id,
            "type": resource_type,
            "provider": "aws",
            "action": "create",
            "status": "active",
            "config": config,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "region": self._region,
            "outputs": self._generate_outputs(resource_type, resource_id, config),
        }

        self._provisioned[resource_id] = result
        return result

    def read(self, resource_id: str, resource_type: str) -> Optional[dict]:
        """Read current state of an AWS resource."""
        return self._provisioned.get(resource_id)

    def update(self, resource_id: str, resource_type: str, config: dict) -> dict:
        """Update an AWS resource."""
        logger.info(f"Updating {resource_type}: {resource_id}")
        existing = self._provisioned.get(resource_id, {})
        existing["config"] = config
        existing["status"] = "active"
        existing["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._provisioned[resource_id] = existing
        return existing

    def delete(self, resource_id: str, resource_type: str) -> dict:
        """Delete an AWS resource."""
        logger.info(f"Deleting {resource_type}: {resource_id}")
        result = self._provisioned.pop(resource_id, {})
        result["status"] = "deleted"
        result["deleted_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def validate_config(self, resource_type: str, config: dict) -> list[str]:
        """Validate AWS resource configuration."""
        errors = []
        schema = AWS_RESOURCE_SCHEMAS.get(resource_type)
        if not schema:
            errors.append(f"Unknown AWS resource type: {resource_type}")
            return errors

        for field in schema.get("required", []):
            if field not in config:
                errors.append(f"Missing required field '{field}' for {resource_type}")

        allowed = set(schema.get("required", [])) | set(schema.get("optional", []))
        for field in config:
            if field not in allowed and field != "tags":
                errors.append(f"Unknown field '{field}' for {resource_type}")

        # Type-specific validations
        if resource_type == "aws_vpc":
            cidr = config.get("cidr_block", "")
            if cidr and not self._validate_cidr(cidr):
                errors.append(f"Invalid CIDR block: {cidr}")

        if resource_type == "aws_s3_bucket":
            bucket = config.get("bucket", "")
            if bucket and (len(bucket) < 3 or len(bucket) > 63):
                errors.append("S3 bucket name must be 3-63 characters")

        return errors

    def list_resource_types(self) -> list[str]:
        return list(AWS_RESOURCE_SCHEMAS.keys())

    def _generate_outputs(self, resource_type: str, resource_id: str, config: dict) -> dict:
        """Generate simulated outputs for a resource."""
        rid_hash = hashlib.md5(resource_id.encode()).hexdigest()[:8]
        outputs = {"id": f"{resource_type}-{rid_hash}"}

        if resource_type == "aws_vpc":
            outputs["vpc_id"] = f"vpc-{rid_hash}"
            outputs["cidr_block"] = config.get("cidr_block", "")
        elif resource_type == "aws_subnet":
            outputs["subnet_id"] = f"subnet-{rid_hash}"
        elif resource_type == "aws_security_group":
            outputs["sg_id"] = f"sg-{rid_hash}"
        elif resource_type == "aws_ec2_instance":
            outputs["instance_id"] = f"i-{rid_hash}"
            outputs["private_ip"] = f"10.0.{int(rid_hash[:2], 16) % 256}.{int(rid_hash[2:4], 16) % 256}"
        elif resource_type == "aws_s3_bucket":
            outputs["arn"] = f"arn:aws:s3:::{config.get('bucket', resource_id)}"
            outputs["domain_name"] = f"{config.get('bucket', resource_id)}.s3.amazonaws.com"
        elif resource_type == "aws_rds_instance":
            outputs["endpoint"] = f"{resource_id}.{rid_hash}.{self._region}.rds.amazonaws.com"
            outputs["port"] = 5432 if config.get("engine") == "postgres" else 3306
        elif resource_type == "aws_eks_cluster":
            outputs["endpoint"] = f"https://{rid_hash}.{self._region}.eks.amazonaws.com"
            outputs["certificate_authority"] = f"LS0t...{rid_hash}"

        return outputs

    @staticmethod
    def _validate_cidr(cidr: str) -> bool:
        """Basic CIDR validation."""
        try:
            parts = cidr.split("/")
            if len(parts) != 2:
                return False
            octets = parts[0].split(".")
            if len(octets) != 4:
                return False
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return False
            prefix = int(parts[1])
            return 0 <= prefix <= 32
        except (ValueError, IndexError):
            return False

    def estimate_cost(self, resource_type: str, config: dict) -> Optional[dict]:
        """Rough cost estimates for AWS resources (USD/month)."""
        costs = {
            "aws_ec2_instance": {"t3.micro": 8.5, "t3.small": 17, "t3.medium": 34, "m5.large": 70, "m5.xlarge": 140},
            "aws_rds_instance": {"db.t3.micro": 15, "db.t3.small": 30, "db.t3.medium": 60, "db.m5.large": 140},
            "aws_s3_bucket": {"standard": 0.023},  # per GB
            "aws_eks_cluster": {"cluster": 73},
        }

        if resource_type in costs:
            if resource_type in ("aws_ec2_instance", "aws_rds_instance"):
                instance_type = config.get("instance_type", config.get("instance_class", ""))
                monthly = costs[resource_type].get(instance_type, 50)
                return {"monthly_usd": monthly, "instance_type": instance_type}
            elif resource_type == "aws_eks_cluster":
                return {"monthly_usd": 73, "note": "Control plane only"}
        return None

    def health_check(self) -> dict:
        return {
            "provider": "aws",
            "region": self._region,
            "status": "connected" if self._initialized else "disconnected",
            "resource_count": len(self._provisioned),
        }
