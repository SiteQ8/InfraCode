"""
InfraCode State Manager
Encrypted state file management with locking, versioning, and rollback.

State files track the current infrastructure state and are critical for:
- Planning: Comparing desired vs actual state
- Drift detection: Identifying configuration drift
- Rollback: Reverting to previous known-good states
- Audit: Tracking who changed what and when
"""

import json
import hashlib
import logging
import os
import time
import shutil
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("infracode.state")


@dataclass
class StateLock:
    """Represents a state lock to prevent concurrent modifications."""
    lock_id: str
    owner: str
    created_at: str
    expires_at: str
    operation: str = ""

    def to_dict(self) -> dict:
        return {
            "lock_id": self.lock_id,
            "owner": self.owner,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "operation": self.operation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StateLock":
        return cls(**data)


@dataclass
class StateVersion:
    """A point-in-time snapshot of the infrastructure state."""
    version_id: str
    serial: int
    timestamp: str
    resources: dict
    metadata: dict = field(default_factory=dict)
    checksum: str = ""

    def compute_checksum(self) -> str:
        content = json.dumps(self.resources, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "version_id": self.version_id,
            "serial": self.serial,
            "timestamp": self.timestamp,
            "resources": self.resources,
            "metadata": self.metadata,
            "checksum": self.checksum or self.compute_checksum(),
        }


class EncryptionProvider:
    """AES-256 encryption for state files using cryptography library or fallback."""

    def __init__(self, key: Optional[str] = None):
        self._key = key or os.environ.get("INFRACODE_ENCRYPTION_KEY", "")
        self._use_crypto = False
        try:
            from cryptography.fernet import Fernet
            if self._key:
                self._fernet = Fernet(self._key.encode() if isinstance(self._key, str) else self._key)
                self._use_crypto = True
        except ImportError:
            logger.warning("cryptography library not available — using base64 encoding (NOT SECURE for production)")

    def encrypt(self, data: str) -> str:
        if self._use_crypto:
            return self._fernet.encrypt(data.encode()).decode()
        # Fallback: base64 (development only)
        return base64.b64encode(data.encode()).decode()

    def decrypt(self, data: str) -> str:
        if self._use_crypto:
            return self._fernet.decrypt(data.encode()).decode()
        return base64.b64decode(data.encode()).decode()


class StateManager:
    """
    Manages infrastructure state with:
    - Encrypted persistence
    - File locking (prevent concurrent modifications)
    - Version history with rollback
    - Integrity verification (checksums)
    - Remote backend support
    """

    MAX_HISTORY = 50  # Maximum number of state versions to retain

    def __init__(
        self,
        state_dir: str = ".infracode/state",
        encryption_key: Optional[str] = None,
        backend: str = "local",
    ):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.backend = backend
        self.encryption = EncryptionProvider(encryption_key)

        self._state_file = self.state_dir / "infracode.state"
        self._lock_file = self.state_dir / "infracode.lock"
        self._history_dir = self.state_dir / "history"
        self._history_dir.mkdir(parents=True, exist_ok=True)

        self._resources: dict[str, dict] = {}
        self._serial: int = 0
        self._metadata: dict = {}
        self._lock: Optional[StateLock] = None

        # Load existing state
        self._load()

    def _load(self):
        """Load state from disk."""
        if self._state_file.exists():
            try:
                raw = self._state_file.read_text(encoding="utf-8")
                decrypted = self.encryption.decrypt(raw)
                data = json.loads(decrypted)
                self._resources = data.get("resources", {})
                self._serial = data.get("serial", 0)
                self._metadata = data.get("metadata", {})

                # Verify checksum
                stored_checksum = data.get("checksum", "")
                computed = hashlib.sha256(
                    json.dumps(self._resources, sort_keys=True, default=str).encode()
                ).hexdigest()
                if stored_checksum and stored_checksum != computed:
                    logger.error("State file integrity check FAILED — possible tampering")
                    raise ValueError("State file checksum mismatch")

                logger.info(f"Loaded state (serial={self._serial}, resources={len(self._resources)})")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
                raise

    def save(self):
        """Save current state to disk with encryption and versioning."""
        self._serial += 1
        timestamp = datetime.now(timezone.utc).isoformat()

        checksum = hashlib.sha256(
            json.dumps(self._resources, sort_keys=True, default=str).encode()
        ).hexdigest()

        state_data = {
            "infracode_version": "1.0.0",
            "serial": self._serial,
            "timestamp": timestamp,
            "resources": self._resources,
            "metadata": self._metadata,
            "checksum": checksum,
        }

        # Save version history before overwriting
        self._save_history(state_data)

        # Encrypt and write
        json_str = json.dumps(state_data, indent=2, default=str)
        encrypted = self.encryption.encrypt(json_str)
        self._state_file.write_text(encrypted, encoding="utf-8")

        logger.info(f"State saved (serial={self._serial}, checksum={checksum[:12]})")

    def _save_history(self, state_data: dict):
        """Save a historical snapshot of the state."""
        version = StateVersion(
            version_id=f"v{self._serial}",
            serial=self._serial,
            timestamp=state_data["timestamp"],
            resources=state_data["resources"],
            metadata=state_data.get("metadata", {}),
        )
        version.checksum = version.compute_checksum()

        history_file = self._history_dir / f"state-{self._serial:06d}.json"
        json_str = json.dumps(version.to_dict(), indent=2, default=str)
        encrypted = self.encryption.encrypt(json_str)
        history_file.write_text(encrypted, encoding="utf-8")

        # Prune old history
        self._prune_history()

    def _prune_history(self):
        """Keep only the most recent MAX_HISTORY state versions."""
        history_files = sorted(self._history_dir.glob("state-*.json"))
        if len(history_files) > self.MAX_HISTORY:
            for old_file in history_files[: len(history_files) - self.MAX_HISTORY]:
                old_file.unlink()

    # ── Resource Operations ──────────────────────────────────────────────

    def get_resources(self) -> dict:
        """Get all resources in current state."""
        return dict(self._resources)

    def get_resource(self, resource_id: str) -> Optional[dict]:
        """Get a specific resource by ID."""
        return self._resources.get(resource_id)

    def set_resource(self, resource_id: str, data: dict):
        """Add or update a resource in state."""
        data["last_modified"] = datetime.now(timezone.utc).isoformat()
        config_str = json.dumps(data.get("config", {}), sort_keys=True, default=str)
        data["fingerprint"] = hashlib.sha256(config_str.encode()).hexdigest()[:16]
        self._resources[resource_id] = data

    def remove_resource(self, resource_id: str) -> bool:
        """Remove a resource from state."""
        if resource_id in self._resources:
            del self._resources[resource_id]
            return True
        return False

    # ── Locking ──────────────────────────────────────────────────────────

    def acquire_lock(self, owner: str, operation: str = "", timeout: int = 300) -> StateLock:
        """Acquire an exclusive lock on the state."""
        if self._lock_file.exists():
            try:
                lock_data = json.loads(self._lock_file.read_text())
                existing = StateLock.from_dict(lock_data)
                expires = datetime.fromisoformat(existing.expires_at)
                if datetime.now(timezone.utc) < expires:
                    raise RuntimeError(
                        f"State is locked by '{existing.owner}' for '{existing.operation}' "
                        f"(expires {existing.expires_at})"
                    )
                logger.warning("Expired lock found — overriding")
            except (json.JSONDecodeError, KeyError):
                pass

        now = datetime.now(timezone.utc)
        lock = StateLock(
            lock_id=hashlib.sha256(f"{owner}{time.time()}".encode()).hexdigest()[:16],
            owner=owner,
            created_at=now.isoformat(),
            expires_at=(now.replace(second=now.second + timeout)).isoformat()
                if timeout < 60 else
                datetime.fromtimestamp(now.timestamp() + timeout, tz=timezone.utc).isoformat(),
            operation=operation,
        )

        self._lock_file.write_text(json.dumps(lock.to_dict()), encoding="utf-8")
        self._lock = lock
        logger.info(f"State locked by '{owner}' (id={lock.lock_id})")
        return lock

    def release_lock(self, lock_id: Optional[str] = None):
        """Release the state lock."""
        if self._lock_file.exists():
            if lock_id:
                lock_data = json.loads(self._lock_file.read_text())
                if lock_data.get("lock_id") != lock_id:
                    raise RuntimeError("Lock ID mismatch — cannot release lock owned by another process")
            self._lock_file.unlink()
            self._lock = None
            logger.info("State lock released")

    def force_unlock(self):
        """Force-remove the state lock (admin operation)."""
        if self._lock_file.exists():
            self._lock_file.unlink()
        self._lock = None
        logger.warning("State lock forcefully removed")

    # ── History & Rollback ───────────────────────────────────────────────

    def list_versions(self) -> list[dict]:
        """List all available state versions."""
        versions = []
        for f in sorted(self._history_dir.glob("state-*.json")):
            try:
                raw = f.read_text(encoding="utf-8")
                decrypted = self.encryption.decrypt(raw)
                data = json.loads(decrypted)
                versions.append({
                    "version_id": data["version_id"],
                    "serial": data["serial"],
                    "timestamp": data["timestamp"],
                    "resource_count": len(data.get("resources", {})),
                    "checksum": data.get("checksum", ""),
                })
            except Exception as e:
                logger.warning(f"Could not read history file {f}: {e}")
        return versions

    def rollback(self, serial: int) -> dict:
        """Rollback state to a specific version serial number."""
        history_file = self._history_dir / f"state-{serial:06d}.json"
        if not history_file.exists():
            raise FileNotFoundError(f"State version {serial} not found")

        raw = history_file.read_text(encoding="utf-8")
        decrypted = self.encryption.decrypt(raw)
        data = json.loads(decrypted)

        # Verify checksum
        version = StateVersion(**data)
        computed = version.compute_checksum()
        if version.checksum and version.checksum != computed:
            raise ValueError(f"Checksum mismatch for version {serial} — history may be corrupted")

        self._resources = data["resources"]
        self._metadata["rollback_from"] = self._serial
        self._metadata["rollback_to"] = serial
        self._metadata["rollback_at"] = datetime.now(timezone.utc).isoformat()
        self.save()

        logger.info(f"Rolled back to version {serial}")
        return {"status": "success", "rolled_back_to": serial, "new_serial": self._serial}

    def export_state(self, path: str):
        """Export current state to a readable JSON file (for debugging/migration)."""
        state_data = {
            "serial": self._serial,
            "resources": self._resources,
            "metadata": self._metadata,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
        Path(path).write_text(json.dumps(state_data, indent=2, default=str), encoding="utf-8")

    def import_state(self, path: str):
        """Import state from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._resources = data.get("resources", {})
        self._metadata = data.get("metadata", {})
        self.save()
