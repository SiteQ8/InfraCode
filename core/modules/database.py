"""
InfraCode Database Module
Reusable database infrastructure patterns.
"""


def rds_postgres(
    name: str,
    instance_class: str = "db.t3.medium",
    allocated_storage: int = 100,
    multi_az: bool = True,
    subnet_group: str = "",
    sg_refs: list = None,
    tags: dict = None,
) -> dict:
    """Generate a production-ready RDS PostgreSQL instance."""
    return {
        f"{name}-rds": {
            "type": "aws_rds_instance",
            "provider": "aws",
            "name": name,
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": instance_class,
            "allocated_storage": allocated_storage,
            "storage_encrypted": True,
            "multi_az": multi_az,
            "db_name": name.replace("-", "_"),
            "master_username": "${vault.db_username}",
            "master_password": "${vault.db_password}",
            "backup_retention_period": 30,
            "deletion_protection": True,
            "performance_insights_enabled": True,
            "monitoring_interval": 60,
            "db_subnet_group_name": subnet_group,
            "vpc_security_group_ids": sg_refs or [],
            "publicly_accessible": False,
            "tags": {"Name": name, "Module": "database", "Engine": "PostgreSQL", **(tags or {})},
            "metadata": {"immutable_fields": ["engine"]},
        }
    }


def aurora_cluster(
    name: str,
    engine: str = "aurora-postgresql",
    instance_count: int = 2,
    instance_class: str = "db.r6g.large",
    tags: dict = None,
) -> dict:
    """Generate an Aurora cluster with reader replicas."""
    resources = {
        f"{name}-aurora-cluster": {
            "type": "aws_rds_instance",
            "provider": "aws",
            "name": f"{name}-cluster",
            "engine": engine,
            "master_username": "${vault.db_username}",
            "master_password": "${vault.db_password}",
            "storage_encrypted": True,
            "backup_retention_period": 35,
            "deletion_protection": True,
            "tags": {"Name": f"{name}-cluster", "Module": "database", **(tags or {})},
        }
    }

    for i in range(instance_count):
        role = "writer" if i == 0 else "reader"
        resources[f"{name}-aurora-{role}-{i+1}"] = {
            "type": "aws_rds_instance",
            "provider": "aws",
            "name": f"{name}-{role}-{i+1}",
            "engine": engine,
            "instance_class": instance_class,
            "depends_on": [f"{name}-aurora-cluster"],
            "tags": {"Name": f"{name}-{role}-{i+1}", "Role": role},
        }

    return resources
