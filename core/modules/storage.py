"""
InfraCode Storage Module
Reusable storage infrastructure patterns.
"""


def secure_s3_bucket(name: str, versioning: bool = True, encryption: str = "AES256", tags: dict = None) -> dict:
    """Generate a security-hardened S3 bucket."""
    return {
        f"{name}-bucket": {
            "type": "aws_s3_bucket",
            "provider": "aws",
            "name": name,
            "bucket": name,
            "acl": "private",
            "versioning": {"enabled": versioning},
            "encryption": {"sse_algorithm": encryption},
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            "logging": {"target_bucket": f"{name}-logs"},
            "lifecycle_rules": [
                {"id": "transition-to-ia", "status": "Enabled", "transition": {"days": 90, "storage_class": "STANDARD_IA"}},
                {"id": "transition-to-glacier", "status": "Enabled", "transition": {"days": 365, "storage_class": "GLACIER"}},
            ],
            "tags": {"Name": name, "Module": "storage", "Encryption": encryption, **(tags or {})},
        }
    }


def azure_storage_hardened(name: str, location: str = "eastus", tags: dict = None) -> dict:
    """Generate a hardened Azure Storage Account."""
    return {
        f"{name}-storage": {
            "type": "azure_storage_account",
            "provider": "azure",
            "name": name,
            "resource_group": "${var.resource_group}",
            "location": location,
            "sku": "Standard_GRS",
            "kind": "StorageV2",
            "access_tier": "Hot",
            "https_only": True,
            "encryption": {"services": {"blob": True, "file": True}, "key_source": "Microsoft.Storage"},
            "network_rules": {"default_action": "Deny", "bypass": ["AzureServices"]},
            "tags": {"Name": name, "Module": "storage", **(tags or {})},
        }
    }
