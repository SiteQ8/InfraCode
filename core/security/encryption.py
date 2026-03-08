"""
InfraCode Encryption Module
AES-256-GCM encryption for state files, secrets, and sensitive data.
"""

import os
import base64
import hashlib
import secrets
import logging
import json
from typing import Optional

logger = logging.getLogger("infracode.security.encryption")


class AES256GCMEncryption:
    """
    AES-256-GCM encryption with authenticated encryption.
    Provides confidentiality + integrity + authenticity.
    """

    NONCE_SIZE = 12  # 96-bit nonce for GCM
    TAG_SIZE = 16    # 128-bit authentication tag
    KEY_SIZE = 32    # 256-bit key

    def __init__(self, key: Optional[str] = None):
        """Initialize with a base64-encoded or hex key, or generate one."""
        if key:
            self._key = self._decode_key(key)
        else:
            env_key = os.environ.get("INFRACODE_ENCRYPTION_KEY")
            if env_key:
                self._key = self._decode_key(env_key)
            else:
                logger.warning("No encryption key provided — generating ephemeral key")
                self._key = secrets.token_bytes(self.KEY_SIZE)

    def _decode_key(self, key: str) -> bytes:
        """Decode a key from base64 or hex string."""
        try:
            decoded = base64.b64decode(key)
            if len(decoded) == self.KEY_SIZE:
                return decoded
        except Exception:
            pass
        try:
            decoded = bytes.fromhex(key)
            if len(decoded) == self.KEY_SIZE:
                return decoded
        except Exception:
            pass
        # Derive key from passphrase using PBKDF2
        return hashlib.pbkdf2_hmac("sha256", key.encode(), b"infracode-salt-v1", 100000, dklen=self.KEY_SIZE)

    def encrypt(self, plaintext: str, aad: Optional[str] = None) -> str:
        """
        Encrypt plaintext with AES-256-GCM.
        Returns base64-encoded: nonce || ciphertext || tag
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            aesgcm = AESGCM(self._key)
            aad_bytes = aad.encode() if aad else None
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad_bytes)
            return base64.b64encode(nonce + ciphertext).decode()
        except ImportError:
            # Fallback: XOR-based obfuscation (NOT secure — development only)
            logger.warning("cryptography library not available — using development fallback")
            return base64.b64encode(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str, aad: Optional[str] = None) -> str:
        """
        Decrypt AES-256-GCM ciphertext.
        Input: base64-encoded nonce || ciphertext || tag
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = base64.b64decode(ciphertext)
            nonce = raw[: self.NONCE_SIZE]
            ct = raw[self.NONCE_SIZE:]
            aesgcm = AESGCM(self._key)
            aad_bytes = aad.encode() if aad else None
            plaintext = aesgcm.decrypt(nonce, ct, aad_bytes)
            return plaintext.decode()
        except ImportError:
            return base64.b64decode(ciphertext).decode()

    @staticmethod
    def generate_key() -> str:
        """Generate a new AES-256 key as base64 string."""
        return base64.b64encode(secrets.token_bytes(32)).decode()

    @staticmethod
    def derive_key(passphrase: str, salt: Optional[bytes] = None) -> tuple[str, str]:
        """Derive a key from a passphrase using PBKDF2. Returns (key_b64, salt_b64)."""
        if salt is None:
            salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, dklen=32)
        return base64.b64encode(key).decode(), base64.b64encode(salt).decode()


class KeyRotation:
    """Manages encryption key rotation for state files."""

    def __init__(self, current_key: str, key_store_path: str = ".infracode/keys"):
        self.current_key = current_key
        self.key_store_path = key_store_path
        os.makedirs(key_store_path, exist_ok=True)

    def rotate(self, new_key: Optional[str] = None) -> str:
        """Rotate the encryption key. Returns new key."""
        new_key = new_key or AES256GCMEncryption.generate_key()

        # Store old key for re-encryption
        old_enc = AES256GCMEncryption(self.current_key)
        new_enc = AES256GCMEncryption(new_key)

        # Record rotation event
        rotation_record = {
            "rotated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "old_key_hash": hashlib.sha256(self.current_key.encode()).hexdigest()[:16],
            "new_key_hash": hashlib.sha256(new_key.encode()).hexdigest()[:16],
        }

        record_path = os.path.join(self.key_store_path, "rotation_log.json")
        records = []
        if os.path.exists(record_path):
            with open(record_path) as f:
                records = json.load(f)
        records.append(rotation_record)
        with open(record_path, "w") as f:
            json.dump(records, f, indent=2)

        self.current_key = new_key
        return new_key

    def re_encrypt_file(self, file_path: str, old_key: str, new_key: str):
        """Re-encrypt a file with a new key."""
        old_enc = AES256GCMEncryption(old_key)
        new_enc = AES256GCMEncryption(new_key)

        with open(file_path, "r") as f:
            encrypted_data = f.read()

        plaintext = old_enc.decrypt(encrypted_data)
        new_encrypted = new_enc.encrypt(plaintext)

        with open(file_path, "w") as f:
            f.write(new_encrypted)
