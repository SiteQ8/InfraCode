"""
InfraCode GCP Provider
Manages Google Cloud Platform infrastructure resources.
"""

import os
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional

from core.providers import BaseProvider

logger = logging.getLogger("infracode.providers.gcp")

GCP_RESOURCE_SCHEMAS = {
    "gcp_vpc_network": {
        "required": ["name"],
        "optional": ["auto_create_subnetworks", "routing_mode", "description"],
        "immutable": ["name"],
    },
    "gcp_subnet": {
        "required": ["name", "network", "region", "ip_cidr_range"],
        "optional": ["private_ip_google_access", "secondary_ip_ranges"],
        "immutable": ["name", "network", "region"],
    },
    "gcp_compute_instance": {
        "required": ["name", "machine_type", "zone", "boot_disk"],
        "optional": ["network_interfaces", "service_account", "metadata", "tags", "labels"],
        "immutable": ["name", "zone"],
    },
    "gcp_gcs_bucket": {
        "required": ["name", "location"],
        "optional": ["storage_class", "versioning", "lifecycle_rules", "encryption", "cors", "labels"],
        "immutable": ["name", "location"],
    },
    "gcp_cloud_sql": {
        "required": ["name", "database_version", "region", "tier"],
        "optional": ["disk_size", "disk_type", "backup_configuration", "ip_configuration", "labels"],
        "immutable": ["name", "database_version", "region"],
    },
    "gcp_gke_cluster": {
        "required": ["name", "location", "node_pools"],
        "optional": ["network", "subnetwork", "cluster_ipv4_cidr", "master_auth", "labels"],
        "immutable": ["name", "location"],
    },
    "gcp_firewall_rule": {
        "required": ["name", "network", "direction"],
        "optional": ["allowed", "denied", "source_ranges", "target_tags", "priority"],
        "immutable": ["name", "network"],
    },
    "gcp_cloud_function": {
        "required": ["name", "runtime", "entry_point", "source"],
        "optional": ["memory", "timeout", "environment_variables", "trigger", "labels"],
        "immutable": ["name"],
    },
}


class GCPProvider(BaseProvider):
    """Google Cloud Platform Provider for InfraCode."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.name = "gcp"
        self._project_id = config.get("project_id", os.environ.get("GCP_PROJECT_ID", ""))
        self._provisioned: dict[str, dict] = {}

    def initialize(self) -> bool:
        try:
            from google.auth import default
            credentials, project = default()
            self._project_id = self._project_id or project
            logger.info(f"GCP authenticated for project {self._project_id}")
            self._initialized = True
            return True
        except ImportError:
            logger.warning("google-auth not installed — running in simulation mode")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"GCP initialization failed: {e}")
            return False

    def create(self, resource_id: str, resource_type: str, config: dict) -> dict:
        logger.info(f"Creating {resource_type}: {resource_id}")
        rid_hash = hashlib.md5(resource_id.encode()).hexdigest()[:8]
        result = {
            "resource_id": resource_id,
            "type": resource_type,
            "provider": "gcp",
            "action": "create",
            "status": "active",
            "config": config,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "project_id": self._project_id,
            "outputs": {"self_link": f"projects/{self._project_id}/{resource_type}/{rid_hash}"},
        }
        self._provisioned[resource_id] = result
        return result

    def read(self, resource_id: str, resource_type: str) -> Optional[dict]:
        return self._provisioned.get(resource_id)

    def update(self, resource_id: str, resource_type: str, config: dict) -> dict:
        existing = self._provisioned.get(resource_id, {})
        existing["config"] = config
        existing["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._provisioned[resource_id] = existing
        return existing

    def delete(self, resource_id: str, resource_type: str) -> dict:
        result = self._provisioned.pop(resource_id, {})
        result["status"] = "deleted"
        return result

    def validate_config(self, resource_type: str, config: dict) -> list[str]:
        errors = []
        schema = GCP_RESOURCE_SCHEMAS.get(resource_type)
        if not schema:
            return [f"Unknown GCP resource type: {resource_type}"]
        for field in schema.get("required", []):
            if field not in config:
                errors.append(f"Missing required field '{field}' for {resource_type}")
        return errors

    def list_resource_types(self) -> list[str]:
        return list(GCP_RESOURCE_SCHEMAS.keys())

    def health_check(self) -> dict:
        return {"provider": "gcp", "project": self._project_id, "status": "connected" if self._initialized else "disconnected"}
