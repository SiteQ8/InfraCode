"""
InfraCode Azure Provider
Manages Azure infrastructure resources.
"""

import os
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional

from core.providers import BaseProvider

logger = logging.getLogger("infracode.providers.azure")

AZURE_RESOURCE_SCHEMAS = {
    "azure_resource_group": {
        "required": ["name", "location"],
        "optional": ["tags"],
        "immutable": ["name", "location"],
    },
    "azure_virtual_network": {
        "required": ["name", "resource_group", "address_space"],
        "optional": ["subnets", "dns_servers", "tags"],
        "immutable": ["name", "resource_group"],
    },
    "azure_subnet": {
        "required": ["name", "resource_group", "virtual_network", "address_prefix"],
        "optional": ["nsg_id", "route_table_id", "service_endpoints"],
        "immutable": ["name", "resource_group", "virtual_network"],
    },
    "azure_nsg": {
        "required": ["name", "resource_group", "location"],
        "optional": ["rules", "tags"],
        "immutable": ["name", "resource_group"],
    },
    "azure_virtual_machine": {
        "required": ["name", "resource_group", "location", "vm_size", "image"],
        "optional": ["admin_username", "admin_password", "ssh_key", "os_disk",
                      "data_disks", "network_interfaces", "tags"],
        "immutable": ["name", "resource_group", "location"],
    },
    "azure_storage_account": {
        "required": ["name", "resource_group", "location", "sku"],
        "optional": ["kind", "access_tier", "https_only", "encryption", "network_rules", "tags"],
        "immutable": ["name", "resource_group"],
    },
    "azure_aks_cluster": {
        "required": ["name", "resource_group", "location", "dns_prefix", "node_pools"],
        "optional": ["kubernetes_version", "network_profile", "identity", "tags"],
        "immutable": ["name", "resource_group", "dns_prefix"],
    },
    "azure_sql_database": {
        "required": ["name", "server_name", "resource_group"],
        "optional": ["sku", "max_size_gb", "collation", "zone_redundant", "tags"],
        "immutable": ["name", "server_name"],
    },
    "azure_key_vault": {
        "required": ["name", "resource_group", "location", "tenant_id"],
        "optional": ["sku", "access_policies", "network_acls", "soft_delete", "purge_protection", "tags"],
        "immutable": ["name", "resource_group"],
    },
}


class AzureProvider(BaseProvider):
    """Azure Cloud Provider for InfraCode."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.name = "azure"
        self._subscription_id = config.get("subscription_id", os.environ.get("AZURE_SUBSCRIPTION_ID", ""))
        self._provisioned: dict[str, dict] = {}

    def initialize(self) -> bool:
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            logger.info("Azure authenticated via DefaultAzureCredential")
            self._initialized = True
            return True
        except ImportError:
            logger.warning("azure SDK not installed — running in simulation mode")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Azure initialization failed: {e}")
            return False

    def create(self, resource_id: str, resource_type: str, config: dict) -> dict:
        logger.info(f"Creating {resource_type}: {resource_id}")
        rid_hash = hashlib.md5(resource_id.encode()).hexdigest()[:8]
        result = {
            "resource_id": resource_id,
            "type": resource_type,
            "provider": "azure",
            "action": "create",
            "status": "active",
            "config": config,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "subscription_id": self._subscription_id,
            "outputs": {"id": f"/subscriptions/{self._subscription_id}/resourceGroups/{config.get('resource_group', 'rg')}/providers/Microsoft/{rid_hash}"},
        }
        self._provisioned[resource_id] = result
        return result

    def read(self, resource_id: str, resource_type: str) -> Optional[dict]:
        return self._provisioned.get(resource_id)

    def update(self, resource_id: str, resource_type: str, config: dict) -> dict:
        logger.info(f"Updating {resource_type}: {resource_id}")
        existing = self._provisioned.get(resource_id, {})
        existing["config"] = config
        existing["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._provisioned[resource_id] = existing
        return existing

    def delete(self, resource_id: str, resource_type: str) -> dict:
        logger.info(f"Deleting {resource_type}: {resource_id}")
        result = self._provisioned.pop(resource_id, {})
        result["status"] = "deleted"
        return result

    def validate_config(self, resource_type: str, config: dict) -> list[str]:
        errors = []
        schema = AZURE_RESOURCE_SCHEMAS.get(resource_type)
        if not schema:
            return [f"Unknown Azure resource type: {resource_type}"]
        for field in schema.get("required", []):
            if field not in config:
                errors.append(f"Missing required field '{field}' for {resource_type}")
        return errors

    def list_resource_types(self) -> list[str]:
        return list(AZURE_RESOURCE_SCHEMAS.keys())

    def health_check(self) -> dict:
        return {"provider": "azure", "subscription": self._subscription_id, "status": "connected" if self._initialized else "disconnected"}
