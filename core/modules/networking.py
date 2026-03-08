"""
InfraCode Networking Module
Reusable networking infrastructure patterns for multi-cloud.
"""


def vpc_with_subnets(
    name: str,
    cidr: str = "10.0.0.0/16",
    availability_zones: list = None,
    public_subnets: int = 2,
    private_subnets: int = 2,
    enable_nat: bool = True,
    provider: str = "aws",
    tags: dict = None,
) -> dict:
    """
    Generate a VPC with public and private subnets pattern.
    Returns a template-ready resource dict.
    """
    az_list = availability_zones or ["us-east-1a", "us-east-1b"]
    tags = tags or {}
    resources = {}

    # VPC
    resources[f"{name}-vpc"] = {
        "type": f"{provider}_vpc" if provider == "aws" else f"{provider}_virtual_network",
        "provider": provider,
        "name": f"{name}-vpc",
        "cidr_block": cidr if provider == "aws" else None,
        "address_space": [cidr] if provider == "azure" else None,
        "enable_dns_support": True,
        "enable_dns_hostnames": True,
        "tags": {"Name": f"{name}-vpc", "Module": "networking", **tags},
    }

    # Public Subnets
    for i in range(min(public_subnets, len(az_list))):
        subnet_cidr = f"10.0.{i}.0/24"
        resources[f"{name}-public-{i+1}"] = {
            "type": f"{provider}_subnet",
            "provider": provider,
            "name": f"{name}-public-{i+1}",
            "vpc_id": f"${{{name}-vpc.vpc_id}}",
            "cidr_block": subnet_cidr,
            "availability_zone": az_list[i % len(az_list)],
            "map_public_ip_on_launch": True,
            "depends_on": [f"{name}-vpc"],
            "tags": {"Name": f"{name}-public-{i+1}", "Tier": "public", **tags},
        }

    # Private Subnets
    for i in range(min(private_subnets, len(az_list))):
        subnet_cidr = f"10.0.{10 + i}.0/24"
        resources[f"{name}-private-{i+1}"] = {
            "type": f"{provider}_subnet",
            "provider": provider,
            "name": f"{name}-private-{i+1}",
            "vpc_id": f"${{{name}-vpc.vpc_id}}",
            "cidr_block": subnet_cidr,
            "availability_zone": az_list[i % len(az_list)],
            "map_public_ip_on_launch": False,
            "depends_on": [f"{name}-vpc"],
            "tags": {"Name": f"{name}-private-{i+1}", "Tier": "private", **tags},
        }

    return resources


def security_group_web(name: str, vpc_ref: str, provider: str = "aws", tags: dict = None) -> dict:
    """Generate a web-tier security group (HTTP/HTTPS + restricted SSH)."""
    return {
        f"{name}-web-sg": {
            "type": f"{provider}_security_group",
            "provider": provider,
            "name": f"{name}-web-sg",
            "description": "Web tier security group — HTTP/HTTPS inbound",
            "vpc_id": vpc_ref,
            "ingress": [
                {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "HTTPS"},
                {"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "HTTP"},
            ],
            "egress": [
                {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"], "description": "All outbound"},
            ],
            "tags": {"Name": f"{name}-web-sg", "Module": "networking", **(tags or {})},
        }
    }


def security_group_database(name: str, vpc_ref: str, app_sg_ref: str, provider: str = "aws") -> dict:
    """Generate a database-tier security group (app tier only)."""
    return {
        f"{name}-db-sg": {
            "type": f"{provider}_security_group",
            "provider": provider,
            "name": f"{name}-db-sg",
            "description": "Database tier — only accessible from app tier",
            "vpc_id": vpc_ref,
            "ingress": [
                {"from_port": 5432, "to_port": 5432, "protocol": "tcp", "source_security_group": app_sg_ref, "description": "PostgreSQL from app"},
                {"from_port": 3306, "to_port": 3306, "protocol": "tcp", "source_security_group": app_sg_ref, "description": "MySQL from app"},
            ],
            "egress": [],
            "tags": {"Name": f"{name}-db-sg", "Module": "networking"},
        }
    }
