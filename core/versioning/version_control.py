"""
InfraCode Version Control
Track infrastructure changes with full history, diff, and rollback.
Integrates with Git for template versioning and provides independent
state versioning for infrastructure lifecycle management.
"""

import json
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("infracode.versioning")


@dataclass
class ChangeRecord:
    """A record of an infrastructure change."""
    change_id: str
    timestamp: str
    author: str
    action: str  # plan, apply, rollback, import, destroy
    template: str
    resources_affected: list = field(default_factory=list)
    plan_summary: dict = field(default_factory=dict)
    status: str = "pending"  # pending, success, failed, rolled_back
    message: str = ""
    parent_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "change_id": self.change_id,
            "timestamp": self.timestamp,
            "author": self.author,
            "action": self.action,
            "template": self.template,
            "resources_affected": self.resources_affected,
            "plan_summary": self.plan_summary,
            "status": self.status,
            "message": self.message,
            "parent_id": self.parent_id,
        }


class VersionControl:
    """
    Infrastructure version control system.
    Maintains a changelog of all infrastructure operations with:
    - Change history with author attribution
    - Plan snapshots before each apply
    - Rollback chain tracking
    - Git integration for template versioning
    """

    def __init__(self, history_dir: str = ".infracode/history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._changelog_file = self.history_dir / "changelog.json"
        self._changes: list[dict] = []
        self._load()

    def _load(self):
        """Load changelog from disk."""
        if self._changelog_file.exists():
            try:
                self._changes = json.loads(self._changelog_file.read_text(encoding="utf-8"))
            except Exception:
                self._changes = []

    def _save(self):
        """Persist changelog to disk."""
        self._changelog_file.write_text(
            json.dumps(self._changes, indent=2, default=str),
            encoding="utf-8"
        )

    def record_change(
        self,
        action: str,
        template: str,
        author: str = "system",
        resources: list = None,
        plan_summary: dict = None,
        message: str = "",
    ) -> ChangeRecord:
        """Record a new infrastructure change."""
        now = datetime.now(timezone.utc)
        parent_id = self._changes[-1]["change_id"] if self._changes else None

        change = ChangeRecord(
            change_id=hashlib.sha256(f"{now.isoformat()}{action}{template}".encode()).hexdigest()[:16],
            timestamp=now.isoformat(),
            author=author,
            action=action,
            template=template,
            resources_affected=resources or [],
            plan_summary=plan_summary or {},
            status="pending",
            message=message,
            parent_id=parent_id,
        )

        self._changes.append(change.to_dict())
        self._save()

        # Save plan snapshot
        if plan_summary:
            snapshot_file = self.history_dir / f"plan-{change.change_id}.json"
            snapshot_file.write_text(json.dumps(plan_summary, indent=2, default=str), encoding="utf-8")

        logger.info(f"Recorded change {change.change_id}: {action} on {template}")
        return change

    def update_status(self, change_id: str, status: str, message: str = ""):
        """Update the status of a recorded change."""
        for change in self._changes:
            if change["change_id"] == change_id:
                change["status"] = status
                if message:
                    change["message"] = message
                break
        self._save()

    def get_history(self, limit: int = 50, action_filter: str = None) -> list[dict]:
        """Get change history, most recent first."""
        changes = list(reversed(self._changes))
        if action_filter:
            changes = [c for c in changes if c["action"] == action_filter]
        return changes[:limit]

    def get_change(self, change_id: str) -> Optional[dict]:
        """Get a specific change record."""
        for change in self._changes:
            if change["change_id"] == change_id:
                return change
        return None

    def get_plan_snapshot(self, change_id: str) -> Optional[dict]:
        """Retrieve the plan snapshot for a specific change."""
        snapshot_file = self.history_dir / f"plan-{change_id}.json"
        if snapshot_file.exists():
            return json.loads(snapshot_file.read_text(encoding="utf-8"))
        return None

    def diff_changes(self, change_id_a: str, change_id_b: str) -> dict:
        """Compare two change records."""
        a = self.get_change(change_id_a)
        b = self.get_change(change_id_b)
        if not a or not b:
            return {"error": "Change not found"}

        plan_a = self.get_plan_snapshot(change_id_a) or {}
        plan_b = self.get_plan_snapshot(change_id_b) or {}

        return {
            "change_a": a,
            "change_b": b,
            "resource_diff": {
                "only_in_a": list(set(a.get("resources_affected", [])) - set(b.get("resources_affected", []))),
                "only_in_b": list(set(b.get("resources_affected", [])) - set(a.get("resources_affected", []))),
                "in_both": list(set(a.get("resources_affected", [])) & set(b.get("resources_affected", []))),
            },
        }

    def get_rollback_chain(self, change_id: str) -> list[dict]:
        """Get the chain of changes leading to a specific change."""
        chain = []
        current_id = change_id
        visited = set()

        while current_id and current_id not in visited:
            visited.add(current_id)
            change = self.get_change(current_id)
            if change:
                chain.append(change)
                current_id = change.get("parent_id")
            else:
                break

        return list(reversed(chain))


class GitIntegration:
    """Git integration for template version control."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)

    def init_repo(self) -> bool:
        """Initialize a git repository."""
        try:
            subprocess.run(["git", "init"], cwd=self.repo_path, capture_output=True, check=True)
            return True
        except Exception as e:
            logger.error(f"Git init failed: {e}")
            return False

    def commit_changes(self, message: str, files: list = None) -> Optional[str]:
        """Stage and commit changes."""
        try:
            if files:
                for f in files:
                    subprocess.run(["git", "add", f], cwd=self.repo_path, capture_output=True, check=True)
            else:
                subprocess.run(["git", "add", "-A"], cwd=self.repo_path, capture_output=True, check=True)

            result = subprocess.run(
                ["git", "commit", "-m", message],
                cwd=self.repo_path, capture_output=True, text=True
            )

            if result.returncode == 0:
                # Get commit hash
                hash_result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=self.repo_path, capture_output=True, text=True, check=True
                )
                return hash_result.stdout.strip()
            return None
        except Exception as e:
            logger.error(f"Git commit failed: {e}")
            return None

    def get_log(self, limit: int = 20) -> list[dict]:
        """Get git log entries."""
        try:
            result = subprocess.run(
                ["git", "log", f"-{limit}", "--format=%H|%an|%ae|%ai|%s"],
                cwd=self.repo_path, capture_output=True, text=True, check=True
            )
            entries = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|", 4)
                    if len(parts) == 5:
                        entries.append({
                            "hash": parts[0],
                            "author": parts[1],
                            "email": parts[2],
                            "date": parts[3],
                            "message": parts[4],
                        })
            return entries
        except Exception:
            return []

    def get_diff(self, ref_a: str = "HEAD~1", ref_b: str = "HEAD") -> str:
        """Get diff between two refs."""
        try:
            result = subprocess.run(
                ["git", "diff", ref_a, ref_b],
                cwd=self.repo_path, capture_output=True, text=True
            )
            return result.stdout
        except Exception:
            return ""

    def tag_version(self, tag: str, message: str = "") -> bool:
        """Create a git tag."""
        try:
            cmd = ["git", "tag", "-a", tag, "-m", message or tag]
            subprocess.run(cmd, cwd=self.repo_path, capture_output=True, check=True)
            return True
        except Exception:
            return False
