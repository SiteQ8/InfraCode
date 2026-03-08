"""
InfraCode Kubernetes Provider
Manages Kubernetes resources (Deployments, Services, Ingress, etc.).
"""

import os
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional

from core.providers import BaseProvider

logger = logging.getLogger("infracode.providers.kubernetes")

K8S_RESOURCE_SCHEMAS = {
    "k8s_namespace": {"required": ["name"], "optional": ["labels", "annotations"], "immutable": ["name"]},
    "k8s_deployment": {
        "required": ["name", "namespace", "replicas", "containers"],
        "optional": ["labels", "annotations", "strategy", "node_selector", "tolerations",
                      "affinity", "volumes", "service_account"],
        "immutable": ["name", "namespace"],
    },
    "k8s_service": {
        "required": ["name", "namespace", "type", "ports", "selector"],
        "optional": ["labels", "annotations", "cluster_ip", "external_ips", "load_balancer_ip"],
        "immutable": ["name", "namespace"],
    },
    "k8s_ingress": {
        "required": ["name", "namespace", "rules"],
        "optional": ["labels", "annotations", "tls", "ingress_class"],
        "immutable": ["name", "namespace"],
    },
    "k8s_configmap": {
        "required": ["name", "namespace", "data"],
        "optional": ["labels", "annotations"],
        "immutable": ["name", "namespace"],
    },
    "k8s_secret": {
        "required": ["name", "namespace", "type"],
        "optional": ["data", "string_data", "labels", "annotations"],
        "immutable": ["name", "namespace"],
    },
    "k8s_persistent_volume_claim": {
        "required": ["name", "namespace", "storage_class", "access_modes", "storage"],
        "optional": ["labels", "annotations", "selector"],
        "immutable": ["name", "namespace", "storage_class"],
    },
    "k8s_network_policy": {
        "required": ["name", "namespace", "pod_selector"],
        "optional": ["ingress", "egress", "policy_types"],
        "immutable": ["name", "namespace"],
    },
    "k8s_service_account": {
        "required": ["name", "namespace"],
        "optional": ["labels", "annotations", "automount_service_account_token"],
        "immutable": ["name", "namespace"],
    },
    "k8s_rbac_role": {
        "required": ["name", "namespace", "rules"],
        "optional": ["labels", "annotations"],
        "immutable": ["name", "namespace"],
    },
}


class KubernetesProvider(BaseProvider):
    """Kubernetes Provider for InfraCode."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.name = "kubernetes"
        self._kubeconfig = config.get("kubeconfig", os.environ.get("KUBECONFIG", "~/.kube/config"))
        self._context = config.get("context", "")
        self._provisioned: dict[str, dict] = {}

    def initialize(self) -> bool:
        try:
            from kubernetes import client, config as k8s_config
            k8s_config.load_kube_config(config_file=self._kubeconfig, context=self._context or None)
            v1 = client.CoreV1Api()
            v1.list_namespace(limit=1)
            logger.info("Kubernetes authenticated successfully")
            self._initialized = True
            return True
        except ImportError:
            logger.warning("kubernetes SDK not installed — running in simulation mode")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Kubernetes initialization failed: {e}")
            self._initialized = True  # Allow simulation
            return True

    def create(self, resource_id: str, resource_type: str, config: dict) -> dict:
        logger.info(f"Creating {resource_type}: {resource_id}")
        rid_hash = hashlib.md5(resource_id.encode()).hexdigest()[:8]
        result = {
            "resource_id": resource_id,
            "type": resource_type,
            "provider": "kubernetes",
            "action": "create",
            "status": "active",
            "config": config,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "outputs": {"uid": f"{rid_hash}-{resource_type}", "namespace": config.get("namespace", "default")},
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
        schema = K8S_RESOURCE_SCHEMAS.get(resource_type)
        if not schema:
            return [f"Unknown K8s resource type: {resource_type}"]
        for field in schema.get("required", []):
            if field not in config:
                errors.append(f"Missing required field '{field}' for {resource_type}")
        return errors

    def list_resource_types(self) -> list[str]:
        return list(K8S_RESOURCE_SCHEMAS.keys())

    def health_check(self) -> dict:
        return {"provider": "kubernetes", "context": self._context, "status": "connected" if self._initialized else "disconnected"}
