"""
InfraCode Compute Module
Reusable compute infrastructure patterns.
"""


def web_server_cluster(
    name: str,
    instance_type: str = "t3.medium",
    ami: str = "ami-0c55b159cbfafe1f0",
    min_size: int = 2,
    max_size: int = 6,
    subnet_refs: list = None,
    sg_refs: list = None,
    provider: str = "aws",
    tags: dict = None,
) -> dict:
    """Generate a web server auto-scaling cluster pattern."""
    resources = {}
    tags = tags or {}
    subnet_refs = subnet_refs or []
    sg_refs = sg_refs or []

    for i in range(min_size):
        resources[f"{name}-web-{i+1}"] = {
            "type": f"{provider}_ec2_instance" if provider == "aws" else f"{provider}_virtual_machine",
            "provider": provider,
            "name": f"{name}-web-{i+1}",
            "ami": ami,
            "instance_type": instance_type,
            "subnet_id": subnet_refs[i % len(subnet_refs)] if subnet_refs else "",
            "security_groups": sg_refs,
            "monitoring": True,
            "ebs_optimized": True,
            "root_block_device": {"volume_size": 20, "volume_type": "gp3", "encrypted": True},
            "tags": {"Name": f"{name}-web-{i+1}", "Role": "web", "Module": "compute", **tags},
            "metadata": {"immutable_fields": ["ami", "subnet_id"]},
        }

    return resources


def kubernetes_deployment(
    name: str,
    image: str,
    replicas: int = 3,
    port: int = 8080,
    cpu_limit: str = "500m",
    memory_limit: str = "512Mi",
    namespace: str = "default",
) -> dict:
    """Generate a Kubernetes deployment pattern."""
    return {
        f"{name}-deployment": {
            "type": "k8s_deployment",
            "provider": "kubernetes",
            "name": name,
            "namespace": namespace,
            "replicas": replicas,
            "containers": [{
                "name": name,
                "image": image,
                "ports": [{"container_port": port}],
                "resources": {
                    "limits": {"cpu": cpu_limit, "memory": memory_limit},
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                },
                "security_context": {
                    "run_as_non_root": True,
                    "read_only_root_filesystem": True,
                    "allow_privilege_escalation": False,
                },
                "liveness_probe": {"http_get": {"path": "/health", "port": port}, "initial_delay_seconds": 15},
                "readiness_probe": {"http_get": {"path": "/ready", "port": port}, "initial_delay_seconds": 5},
            }],
            "strategy": {"type": "RollingUpdate", "max_unavailable": 1, "max_surge": 1},
            "tags": {"app": name, "module": "compute"},
        },
        f"{name}-service": {
            "type": "k8s_service",
            "provider": "kubernetes",
            "name": f"{name}-svc",
            "namespace": namespace,
            "type": "ClusterIP",
            "ports": [{"port": 80, "target_port": port, "protocol": "TCP"}],
            "selector": {"app": name},
            "depends_on": [f"{name}-deployment"],
        },
    }
