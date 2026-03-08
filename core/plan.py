"""
InfraCode Plan Engine
Generates detailed execution plans with diff visualization.
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("infracode.plan")


@dataclass
class ResourceChange:
    """Represents a single resource change in a plan."""
    resource_id: str
    resource_type: str
    provider: str
    action: str  # create, update, delete, replace, no-op
    before: Optional[dict] = None
    after: Optional[dict] = None
    diff: list = field(default_factory=list)
    requires_replacement: bool = False

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "provider": self.provider,
            "action": self.action,
            "before": self.before,
            "after": self.after,
            "diff": self.diff,
            "requires_replacement": self.requires_replacement,
        }


@dataclass
class ExecutionPlan:
    """Complete execution plan with all resource changes."""
    plan_id: str
    created_at: str
    template_name: str
    changes: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    estimated_time: int = 0  # seconds

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "template_name": self.template_name,
            "changes": [c.to_dict() for c in self.changes],
            "summary": self.summary,
            "warnings": self.warnings,
            "estimated_time": self.estimated_time,
        }

    def format_text(self) -> str:
        """Human-readable plan output."""
        lines = [
            f"╔══════════════════════════════════════════════════╗",
            f"║         InfraCode Execution Plan                 ║",
            f"╠══════════════════════════════════════════════════╣",
            f"║  Plan ID:  {self.plan_id[:20]:<38}║",
            f"║  Template: {self.template_name:<38}║",
            f"║  Created:  {self.created_at[:19]:<38}║",
            f"╠══════════════════════════════════════════════════╣",
        ]

        action_symbols = {
            "create": "+",
            "update": "~",
            "delete": "-",
            "replace": "±",
            "no-op": " ",
        }

        for change in self.changes:
            symbol = action_symbols.get(change.action, "?")
            action_str = change.action.upper()
            lines.append(f"║  [{symbol}] {change.resource_id:<25} {action_str:<12}║")

            if change.diff:
                for diff_item in change.diff:
                    field_name = diff_item.get("field", "")
                    old_val = diff_item.get("old", "")
                    new_val = diff_item.get("new", "")
                    lines.append(f"║      {field_name}: {str(old_val)[:15]} → {str(new_val)[:15]:<10}║")

        lines.extend([
            f"╠══════════════════════════════════════════════════╣",
            f"║  Summary:                                        ║",
            f"║    + Create: {self.summary.get('create', 0):<36}║",
            f"║    ~ Update: {self.summary.get('update', 0):<36}║",
            f"║    - Delete: {self.summary.get('delete', 0):<36}║",
            f"║    ± Replace: {self.summary.get('replace', 0):<35}║",
            f"║    = No-op:  {self.summary.get('noop', 0):<36}║",
            f"╚══════════════════════════════════════════════════╝",
        ])

        if self.warnings:
            lines.append("\n⚠ Warnings:")
            for w in self.warnings:
                lines.append(f"  - {w}")

        return "\n".join(lines)


class PlanEngine:
    """
    Generate execution plans by comparing desired state against current state.
    Produces detailed diffs with field-level change detection.
    """

    # Estimated provisioning times per resource type (seconds)
    ESTIMATED_TIMES = {
        "vpc": 30,
        "subnet": 15,
        "security_group": 10,
        "ec2_instance": 60,
        "rds_instance": 300,
        "s3_bucket": 10,
        "load_balancer": 45,
        "kubernetes_cluster": 600,
        "virtual_network": 30,
        "virtual_machine": 90,
        "storage_account": 15,
        "default": 30,
    }

    def __init__(self):
        self._plan_counter = 0

    def generate_plan(
        self,
        desired_resources: list,
        current_state: dict,
        template_name: str = "unnamed",
    ) -> ExecutionPlan:
        """Generate a plan comparing desired resources against current state."""
        self._plan_counter += 1
        now = datetime.now(timezone.utc)

        plan = ExecutionPlan(
            plan_id=hashlib.sha256(f"{now.isoformat()}{self._plan_counter}".encode()).hexdigest()[:16],
            created_at=now.isoformat(),
            template_name=template_name,
            summary={"create": 0, "update": 0, "delete": 0, "replace": 0, "noop": 0},
        )

        desired_map = {r.id: r for r in desired_resources}
        desired_ids = set(desired_map.keys())
        current_ids = set(current_state.keys())

        # Process desired resources
        for res_id, resource in desired_map.items():
            if res_id not in current_state:
                change = ResourceChange(
                    resource_id=res_id,
                    resource_type=resource.type,
                    provider=resource.provider,
                    action="create",
                    after=resource.config,
                )
                plan.changes.append(change)
                plan.summary["create"] += 1
            else:
                current = current_state[res_id]
                diff = self._compute_diff(current.get("config", {}), resource.config)
                if diff:
                    immutable = resource.metadata.get("immutable_fields", [])
                    needs_replace = any(d["field"] in immutable for d in diff)
                    action = "replace" if needs_replace else "update"

                    change = ResourceChange(
                        resource_id=res_id,
                        resource_type=resource.type,
                        provider=resource.provider,
                        action=action,
                        before=current.get("config", {}),
                        after=resource.config,
                        diff=diff,
                        requires_replacement=needs_replace,
                    )
                    plan.changes.append(change)
                    plan.summary[action] += 1

                    if needs_replace:
                        plan.warnings.append(
                            f"Resource '{res_id}' requires replacement due to immutable field change"
                        )
                else:
                    change = ResourceChange(
                        resource_id=res_id,
                        resource_type=resource.type,
                        provider=resource.provider,
                        action="no-op",
                    )
                    plan.changes.append(change)
                    plan.summary["noop"] += 1

        # Resources to delete
        for res_id in current_ids - desired_ids:
            current = current_state[res_id]
            change = ResourceChange(
                resource_id=res_id,
                resource_type=current.get("type", "unknown"),
                provider=current.get("provider", ""),
                action="delete",
                before=current.get("config", {}),
            )
            plan.changes.append(change)
            plan.summary["delete"] += 1

        # Estimate total time
        plan.estimated_time = sum(
            self.ESTIMATED_TIMES.get(c.resource_type, self.ESTIMATED_TIMES["default"])
            for c in plan.changes if c.action != "no-op"
        )

        return plan

    def _compute_diff(self, before: dict, after: dict) -> list[dict]:
        """Compute field-level diff between two configurations."""
        diff = []
        all_keys = set(list(before.keys()) + list(after.keys()))

        for key in sorted(all_keys):
            old_val = before.get(key)
            new_val = after.get(key)

            if old_val != new_val:
                if old_val is None:
                    diff.append({"field": key, "change": "added", "new": new_val})
                elif new_val is None:
                    diff.append({"field": key, "change": "removed", "old": old_val})
                elif isinstance(old_val, dict) and isinstance(new_val, dict):
                    nested = self._compute_diff(old_val, new_val)
                    for item in nested:
                        item["field"] = f"{key}.{item['field']}"
                        diff.append(item)
                else:
                    diff.append({"field": key, "change": "modified", "old": old_val, "new": new_val})

        return diff

    def compare_plans(self, plan_a: ExecutionPlan, plan_b: ExecutionPlan) -> dict:
        """Compare two execution plans to show differences."""
        a_changes = {c.resource_id: c for c in plan_a.changes}
        b_changes = {c.resource_id: c for c in plan_b.changes}

        comparison = {"added": [], "removed": [], "changed": []}

        for rid in set(list(a_changes.keys()) + list(b_changes.keys())):
            if rid in a_changes and rid not in b_changes:
                comparison["removed"].append(rid)
            elif rid not in a_changes and rid in b_changes:
                comparison["added"].append(rid)
            elif a_changes[rid].action != b_changes[rid].action:
                comparison["changed"].append({
                    "resource_id": rid,
                    "plan_a_action": a_changes[rid].action,
                    "plan_b_action": b_changes[rid].action,
                })

        return comparison
