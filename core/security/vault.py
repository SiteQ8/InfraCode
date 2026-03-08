"""
InfraCode Secret Vault
Secure secret storage with support for local encrypted vault,
HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault.
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.security.encryption import AES256GCMEncryption

logger = logging.getLogger("infracode.security.vault")


class SecretVault:
    """
    Encrypted local secret storage.
    Secrets are stored AES-256-GCM encrypted with access logging.
    """

    def __init__(self, vault_path: str = ".infracode/vault", encryption_key: Optional[str] = None):
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self._vault_file = self.vault_path / "secrets.vault"
        self._audit_file = self.vault_path / "access.log"
        self._encryption = AES256GCMEncryption(encryption_key)
        self._secrets: dict = {}
        self._load()

    def _load(self):
        """Load encrypted vault from disk."""
        if self._vault_file.exists():
            try:
                raw = self._vault_file.read_text(encoding="utf-8")
                decrypted = self._encryption.decrypt(raw)
                self._secrets = json.loads(decrypted)
            except Exception as e:
                logger.error(f"Failed to load vault: {e}")
                self._secrets = {}

    def _save(self):
        """Save vault encrypted to disk."""
        json_str = json.dumps(self._secrets, indent=2, default=str)
        encrypted = self._encryption.encrypt(json_str)
        self._vault_file.write_text(encrypted, encoding="utf-8")

    def _audit(self, action: str, key: str, user: str = "system"):
        """Log vault access for audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key": key,
            "user": user,
            "key_hash": hashlib.sha256(key.encode()).hexdigest()[:12],
        }
        with open(self._audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def set_secret(self, key: str, value: str, metadata: Optional[dict] = None):
        """Store a secret."""
        self._secrets[key] = {
            "value": value,
            "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": self._secrets.get(key, {}).get("version", 0) + 1,
        }
        self._save()
        self._audit("set", key)
        logger.info(f"Secret '{key}' stored (version {self._secrets[key]['version']})")

    def get_secret(self, key: str, user: str = "system") -> Optional[str]:
        """Retrieve a secret value."""
        secret = self._secrets.get(key)
        if secret:
            self._audit("get", key, user)
            return secret["value"]
        return None

    def delete_secret(self, key: str):
        """Delete a secret."""
        if key in self._secrets:
            del self._secrets[key]
            self._save()
            self._audit("delete", key)

    def list_secrets(self) -> list[dict]:
        """List all secret keys (without values)."""
        return [
            {
                "key": k,
                "version": v.get("version", 1),
                "created_at": v.get("created_at", ""),
                "metadata": v.get("metadata", {}),
            }
            for k, v in self._secrets.items()
        ]

    def rotate_secret(self, key: str, new_value: str):
        """Rotate a secret to a new value, incrementing version."""
        existing = self._secrets.get(key, {})
        self.set_secret(key, new_value, metadata={
            **existing.get("metadata", {}),
            "rotated_at": datetime.now(timezone.utc).isoformat(),
            "previous_version": existing.get("version", 0),
        })

    def export_references(self) -> dict:
        """Export secret references (not values) for template interpolation."""
        return {
            f"vault.{key}": f"${{vault.{key}}}"
            for key in self._secrets
        }


class HashiCorpVaultAdapter:
    """Adapter for HashiCorp Vault integration."""

    def __init__(self, addr: str = "", token: str = ""):
        self.addr = addr or os.environ.get("HASHICORP_VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.environ.get("HASHICORP_VAULT_TOKEN", "")

    def get_secret(self, path: str) -> Optional[dict]:
        """Read a secret from HashiCorp Vault."""
        try:
            import hvac
            client = hvac.Client(url=self.addr, token=self.token)
            response = client.secrets.kv.v2.read_secret_version(path=path)
            return response["data"]["data"]
        except ImportError:
            logger.warning("hvac not installed — cannot connect to HashiCorp Vault")
            return None
        except Exception as e:
            logger.error(f"HashiCorp Vault error: {e}")
            return None

    def set_secret(self, path: str, data: dict):
        """Write a secret to HashiCorp Vault."""
        try:
            import hvac
            client = hvac.Client(url=self.addr, token=self.token)
            client.secrets.kv.v2.create_or_update_secret(path=path, secret=data)
        except ImportError:
            logger.warning("hvac not installed")
        except Exception as e:
            logger.error(f"HashiCorp Vault write error: {e}")
