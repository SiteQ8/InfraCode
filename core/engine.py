"""
InfraCode Core Engine
Template parser, resource graph builder, and dependency resolver.

Supports declarative YAML/JSON infrastructure definitions with:
- Dependency graph resolution (topological sort)
- Variable interpolation and expressions
- Resource lifecycle management (create, update, delete)
- Parallel execution with dependency-aware scheduling
"""

import yaml
import json
import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger("infracode.engine")


class ResourceAction(Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NOOP = "no-op"
    REPLACE = "replace"


class ResourceStatus(Enum):
    PENDING = "pending"
    CREATING = "creating"
    ACTIVE = "active"
    UPDATING = "updating"
    DELETING = "deleting"
    DELETED = "deleted"
    FAILED = "failed"
    DRIFTED = "drifted"


@dataclass
class Resource:
    """Represents a single infrastructure resource."""
    id: str
    type: str
    provider: str
    name: str
    config: dict = field(default_factory=dict)
    dependencies: list = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    status: ResourceStatus = ResourceStatus.PENDING
    action: ResourceAction = ResourceAction.NOOP
    outputs: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Generate a deterministic fingerprint of the resource config."""
        config_str = json.dumps(self.config, sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "provider": self.provider,
            "name": self.name,
            "config": self.config,
            "dependencies": self.dependencies,
            "tags": self.tags,
            "status": self.status.value,
            "action": self.action.value,
            "outputs": self.outputs,
            "metadata": self.metadata,
            "fingerprint": self.fingerprint,
        }


@dataclass
class InfraTemplate:
    """Parsed infrastructure template."""
    version: str
    name: str
    description: str = ""
    provider: str = ""
    variables: dict = field(default_factory=dict)
    resources: list = field(default_factory=list)
    outputs: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    policies: list = field(default_factory=list)


class TemplateParser:
    """
    Parse YAML/JSON infrastructure templates into InfraTemplate objects.
    Supports variable interpolation, expressions, and cross-references.
    """

    # Pattern for variable interpolation: ${var.name} or ${resource.id.output}
    VAR_PATTERN = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_.]*)\}")

    def __init__(self):
        self._templates_cache: dict[str, InfraTemplate] = {}

    def parse_file(self, path: str) -> InfraTemplate:
        """Parse a template file (YAML or JSON)."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Template not found: {path}")

        content = file_path.read_text(encoding="utf-8")

        if file_path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        elif file_path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported template format: {file_path.suffix}")

        return self._parse_data(data, source=str(file_path))

    def parse_string(self, content: str, fmt: str = "yaml") -> InfraTemplate:
        """Parse template from string."""
        if fmt == "yaml":
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)
        return self._parse_data(data, source="<string>")

    def _parse_data(self, data: dict, source: str = "") -> InfraTemplate:
        """Parse raw dict into InfraTemplate."""
        if not isinstance(data, dict):
            raise ValueError("Template must be a YAML/JSON object")

        # Validate required fields
        infracode_block = data.get("infracode", {})
        version = infracode_block.get("version", data.get("version", "1.0"))

        template = InfraTemplate(
            version=str(version),
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            provider=data.get("provider", ""),
            variables=self._parse_variables(data.get("variables", {})),
            outputs=data.get("outputs", {}),
            metadata={
                "source": source,
                **data.get("metadata", {}),
            },
            policies=data.get("policies", []),
        )

        # Parse resources
        raw_resources = data.get("resources", {})
        if isinstance(raw_resources, dict):
            for res_id, res_config in raw_resources.items():
                resource = self._parse_resource(res_id, res_config, template.provider)
                template.resources.append(resource)
        elif isinstance(raw_resources, list):
            for item in raw_resources:
                res_id = item.get("id", item.get("name", "unnamed"))
                resource = self._parse_resource(res_id, item, template.provider)
                template.resources.append(resource)

        logger.info(f"Parsed template '{template.name}' with {len(template.resources)} resources")
        return template

    def _parse_variables(self, variables: dict) -> dict:
        """Parse variable definitions with defaults and validation."""
        parsed = {}
        for name, config in variables.items():
            if isinstance(config, dict):
                parsed[name] = {
                    "type": config.get("type", "string"),
                    "default": config.get("default"),
                    "description": config.get("description", ""),
                    "required": config.get("required", False),
                    "sensitive": config.get("sensitive", False),
                    "validation": config.get("validation"),
                }
            else:
                parsed[name] = {
                    "type": "string",
                    "default": config,
                    "description": "",
                    "required": False,
                    "sensitive": False,
                    "validation": None,
                }
        return parsed

    def _parse_resource(self, res_id: str, config: dict, default_provider: str) -> Resource:
        """Parse a single resource definition."""
        resource_type = config.get("type", "unknown")
        provider = config.get("provider", default_provider)

        # Extract special fields
        dependencies = config.get("depends_on", [])
        tags = config.get("tags", {})
        metadata = config.get("metadata", {})

        # Everything else is resource config
        resource_config = {
            k: v for k, v in config.items()
            if k not in ("type", "provider", "depends_on", "tags", "metadata", "id", "name")
        }

        return Resource(
            id=res_id,
            type=resource_type,
            provider=provider,
            name=config.get("name", res_id),
            config=resource_config,
            dependencies=dependencies,
            tags=tags,
            metadata=metadata,
        )

    def interpolate_variables(self, template: InfraTemplate, values: dict) -> InfraTemplate:
        """Resolve variable references in template with provided values."""
        merged = {}
        for name, var_def in template.variables.items():
            if name in values:
                merged[name] = values[name]
            elif var_def.get("default") is not None:
                merged[name] = var_def["default"]
            elif var_def.get("required"):
                raise ValueError(f"Required variable '{name}' not provided")

        # Deep interpolate all resource configs
        for resource in template.resources:
            resource.config = self._deep_interpolate(resource.config, merged)
            resource.tags = self._deep_interpolate(resource.tags, merged)

        return template

    def _deep_interpolate(self, obj: Any, variables: dict) -> Any:
        """Recursively interpolate variables in nested structures."""
        if isinstance(obj, str):
            return self.VAR_PATTERN.sub(
                lambda m: str(self._resolve_ref(m.group(1), variables)),
                obj
            )
        elif isinstance(obj, dict):
            return {k: self._deep_interpolate(v, variables) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_interpolate(item, variables) for item in obj]
        return obj

    def _resolve_ref(self, ref: str, variables: dict) -> Any:
        """Resolve a variable reference like 'var.name' or 'env.KEY'."""
        parts = ref.split(".")
        if parts[0] == "var" and len(parts) == 2:
            return variables.get(parts[1], f"${{{ref}}}")
        elif parts[0] == "env" and len(parts) == 2:
            import os
            return os.environ.get(parts[1], "")
        return f"${{{ref}}}"


class DependencyGraph:
    """
    Build and resolve a dependency graph for infrastructure resources.
    Uses topological sort to determine execution order.
    Detects circular dependencies.
    """

    def __init__(self):
        self._graph: dict[str, set[str]] = defaultdict(set)
        self._reverse: dict[str, set[str]] = defaultdict(set)
        self._resources: dict[str, Resource] = {}

    def add_resource(self, resource: Resource):
        """Add a resource to the dependency graph."""
        self._resources[resource.id] = resource
        self._graph[resource.id]  # Ensure node exists
        for dep in resource.dependencies:
            self._graph[resource.id].add(dep)
            self._reverse[dep].add(resource.id)

    def topological_sort(self) -> list[list[str]]:
        """
        Topological sort with parallelism detection.
        Returns list of "layers": resources in same layer can be provisioned in parallel.
        """
        in_degree = {node: 0 for node in self._graph}
        for node in self._graph:
            for dep in self._graph[node]:
                if dep in in_degree:
                    in_degree[node] = in_degree.get(node, 0)

        # Recalculate properly
        in_degree = {node: 0 for node in self._graph}
        for node in self._graph:
            for dep in self._graph[node]:
                pass
        for node, deps in self._graph.items():
            for dep in deps:
                if dep not in self._graph:
                    raise ValueError(f"Resource '{node}' depends on unknown resource '{dep}'")

        # Kahn's algorithm with layers
        in_deg = defaultdict(int)
        for node in self._graph:
            for dep in self._graph[node]:
                in_deg[node] += 1
            if node not in in_deg:
                in_deg[node] = 0

        layers = []
        queue = [n for n in self._graph if in_deg[n] == 0]
        visited = set()

        while queue:
            layers.append(sorted(queue))
            visited.update(queue)
            next_queue = []
            for node in queue:
                for dependent in self._reverse.get(node, []):
                    in_deg[dependent] -= 1
                    if in_deg[dependent] == 0 and dependent not in visited:
                        next_queue.append(dependent)
            queue = next_queue

        if len(visited) != len(self._graph):
            unvisited = set(self._graph.keys()) - visited
            raise ValueError(f"Circular dependency detected involving: {unvisited}")

        return layers

    def get_execution_order(self) -> list[str]:
        """Flat execution order respecting dependencies."""
        layers = self.topological_sort()
        return [rid for layer in layers for rid in layer]

    def get_dependents(self, resource_id: str) -> set[str]:
        """Get all resources that depend on the given resource."""
        return self._reverse.get(resource_id, set())

    def get_dependencies(self, resource_id: str) -> set[str]:
        """Get all dependencies of the given resource."""
        return self._graph.get(resource_id, set())


class InfraEngine:
    """
    Main IaC engine orchestrating template parsing, planning, and execution.
    """

    def __init__(self, state_manager=None, provider_registry=None):
        self.parser = TemplateParser()
        self.state_manager = state_manager
        self.provider_registry = provider_registry or {}
        self._current_template: Optional[InfraTemplate] = None
        self._graph: Optional[DependencyGraph] = None

    def load_template(self, path: str, variables: Optional[dict] = None) -> InfraTemplate:
        """Load and parse a template, resolving variables."""
        template = self.parser.parse_file(path)
        if variables:
            template = self.parser.interpolate_variables(template, variables)
        self._current_template = template
        self._build_graph(template)
        return template

    def _build_graph(self, template: InfraTemplate):
        """Build dependency graph from template resources."""
        self._graph = DependencyGraph()
        for resource in template.resources:
            self._graph.add_resource(resource)

    def plan(self, template: Optional[InfraTemplate] = None) -> dict:
        """
        Generate an execution plan by comparing desired state (template)
        with current state (state manager).
        """
        template = template or self._current_template
        if not template:
            raise ValueError("No template loaded")

        current_state = {}
        if self.state_manager:
            current_state = self.state_manager.get_resources()

        plan = {
            "template": template.name,
            "version": template.version,
            "actions": [],
            "summary": {"create": 0, "update": 0, "delete": 0, "noop": 0, "replace": 0},
        }

        desired_ids = {r.id for r in template.resources}
        current_ids = set(current_state.keys())

        # Determine actions for each resource
        for resource in template.resources:
            if resource.id not in current_state:
                resource.action = ResourceAction.CREATE
                plan["summary"]["create"] += 1
            else:
                current = current_state[resource.id]
                if resource.fingerprint != current.get("fingerprint"):
                    # Check if update is possible or replacement needed
                    if self._requires_replacement(resource, current):
                        resource.action = ResourceAction.REPLACE
                        plan["summary"]["replace"] += 1
                    else:
                        resource.action = ResourceAction.UPDATE
                        plan["summary"]["update"] += 1
                else:
                    resource.action = ResourceAction.NOOP
                    plan["summary"]["noop"] += 1

            plan["actions"].append({
                "resource_id": resource.id,
                "resource_type": resource.type,
                "action": resource.action.value,
                "provider": resource.provider,
                "config": resource.config,
            })

        # Resources to delete (in current state but not in template)
        for res_id in current_ids - desired_ids:
            plan["actions"].append({
                "resource_id": res_id,
                "resource_type": current_state[res_id].get("type", "unknown"),
                "action": ResourceAction.DELETE.value,
                "provider": current_state[res_id].get("provider", ""),
            })
            plan["summary"]["delete"] += 1

        return plan

    def _requires_replacement(self, resource: Resource, current: dict) -> bool:
        """Check if a resource change requires full replacement (immutable fields changed)."""
        immutable_fields = resource.metadata.get("immutable_fields", [])
        current_config = current.get("config", {})
        for field_name in immutable_fields:
            if (field_name in resource.config and field_name in current_config
                    and resource.config[field_name] != current_config[field_name]):
                return True
        return False

    def apply(self, plan: dict, auto_approve: bool = False) -> dict:
        """
        Execute a plan, provisioning/updating/deleting resources.
        Returns execution results.
        """
        if not auto_approve:
            raise PermissionError("Plan must be approved before applying. Use --auto-approve or confirm interactively.")

        results = {
            "status": "success",
            "resources": [],
            "errors": [],
        }

        # Build execution order
        if self._graph:
            try:
                layers = self._graph.topological_sort()
            except ValueError as e:
                return {"status": "failed", "error": str(e)}
        else:
            layers = [[a["resource_id"] for a in plan["actions"]]]

        action_map = {a["resource_id"]: a for a in plan["actions"]}

        for layer in layers:
            for res_id in layer:
                if res_id not in action_map:
                    continue
                action = action_map[res_id]
                try:
                    result = self._execute_action(action)
                    results["resources"].append(result)

                    # Update state
                    if self.state_manager and action["action"] != ResourceAction.DELETE.value:
                        self.state_manager.set_resource(res_id, result)
                    elif self.state_manager and action["action"] == ResourceAction.DELETE.value:
                        self.state_manager.remove_resource(res_id)

                except Exception as e:
                    logger.error(f"Failed to execute {action['action']} on {res_id}: {e}")
                    results["errors"].append({
                        "resource_id": res_id,
                        "action": action["action"],
                        "error": str(e),
                    })
                    results["status"] = "partial_failure"

        # Save state
        if self.state_manager:
            self.state_manager.save()

        return results

    def _execute_action(self, action: dict) -> dict:
        """Execute a single resource action via the appropriate provider."""
        provider_name = action.get("provider", "")
        provider = self.provider_registry.get(provider_name)

        if not provider:
            logger.warning(f"No provider '{provider_name}' registered — simulating action")
            return {
                "resource_id": action["resource_id"],
                "type": action["resource_type"],
                "action": action["action"],
                "status": "simulated",
                "provider": provider_name,
                "config": action.get("config", {}),
            }

        action_type = action["action"]
        if action_type == ResourceAction.CREATE.value:
            return provider.create(action["resource_id"], action["resource_type"], action.get("config", {}))
        elif action_type == ResourceAction.UPDATE.value:
            return provider.update(action["resource_id"], action["resource_type"], action.get("config", {}))
        elif action_type == ResourceAction.DELETE.value:
            return provider.delete(action["resource_id"], action["resource_type"])
        elif action_type == ResourceAction.REPLACE.value:
            provider.delete(action["resource_id"], action["resource_type"])
            return provider.create(action["resource_id"], action["resource_type"], action.get("config", {}))
        else:
            return {"resource_id": action["resource_id"], "action": "noop", "status": "unchanged"}

    def validate_template(self, template: Optional[InfraTemplate] = None) -> list[dict]:
        """Validate a template for correctness."""
        template = template or self._current_template
        errors = []

        if not template:
            return [{"level": "error", "message": "No template to validate"}]

        if not template.resources:
            errors.append({"level": "warning", "message": "Template has no resources defined"})

        # Check for duplicate resource IDs
        seen_ids = set()
        for resource in template.resources:
            if resource.id in seen_ids:
                errors.append({"level": "error", "message": f"Duplicate resource ID: {resource.id}"})
            seen_ids.add(resource.id)

        # Validate dependencies exist
        resource_ids = {r.id for r in template.resources}
        for resource in template.resources:
            for dep in resource.dependencies:
                if dep not in resource_ids:
                    errors.append({
                        "level": "error",
                        "message": f"Resource '{resource.id}' depends on unknown resource '{dep}'",
                    })

        # Check for circular dependencies
        if self._graph:
            try:
                self._graph.topological_sort()
            except ValueError as e:
                errors.append({"level": "error", "message": str(e)})

        # Validate required variable references
        for resource in template.resources:
            unresolved = self.parser.VAR_PATTERN.findall(json.dumps(resource.config))
            for ref in unresolved:
                if ref.startswith("var."):
                    var_name = ref.split(".")[1]
                    if var_name not in template.variables:
                        errors.append({
                            "level": "error",
                            "message": f"Resource '{resource.id}' references undefined variable '{var_name}'",
                        })

        if not errors:
            errors.append({"level": "info", "message": "Template validation passed"})

        return errors

    def detect_drift(self, template: Optional[InfraTemplate] = None) -> list[dict]:
        """Detect configuration drift between desired and actual state."""
        template = template or self._current_template
        if not template or not self.state_manager:
            return []

        drifts = []
        current_state = self.state_manager.get_resources()

        for resource in template.resources:
            if resource.id in current_state:
                current = current_state[resource.id]
                if resource.fingerprint != current.get("fingerprint"):
                    drifts.append({
                        "resource_id": resource.id,
                        "type": resource.type,
                        "expected_fingerprint": resource.fingerprint,
                        "actual_fingerprint": current.get("fingerprint"),
                        "status": "drifted",
                    })
            else:
                drifts.append({
                    "resource_id": resource.id,
                    "type": resource.type,
                    "status": "missing",
                })

        for res_id in set(current_state.keys()) - {r.id for r in template.resources}:
            drifts.append({
                "resource_id": res_id,
                "type": current_state[res_id].get("type", "unknown"),
                "status": "orphaned",
            })

        return drifts
