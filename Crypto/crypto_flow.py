import base64
import os
import time
import threading
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


AAD_DEFAULT = b"waf-v1"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


@dataclass
class _CachedKey:
    plaintext_key: bytes
    encrypted_key_b64: str
    expires_at: float
    uses: int = 0


class DataKeyCache:
    def __init__(self, ttl_seconds: int = 120, max_uses: int = 1000) -> None:
        self._ttl = ttl_seconds
        self._max_uses = max_uses
        self._lock = threading.Lock()
        self._current: Optional[_CachedKey] = None

    def get(self) -> Optional[_CachedKey]:
        now = time.time()
        with self._lock:
            if not self._current:
                return None
            if now >= self._current.expires_at:
                self._current = None
                return None
            if self._current.uses >= self._max_uses:
                self._current = None
                return None
            self._current.uses += 1
            return self._current

    def set(self, plaintext_key: bytes, encrypted_key_b64: str) -> _CachedKey:
        with self._lock:
            cached = _CachedKey(
                plaintext_key=plaintext_key,
                encrypted_key_b64=encrypted_key_b64,
                expires_at=time.time() + self._ttl,
                uses=1,
            )
            self._current = cached
            return cached


class KMSClient:
    """Interface for KMS.

    Implement generate_data_key() and decrypt_data_key() using AWS/Azure/GCP KMS.
    """

    def generate_data_key(self, key_id: str) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def decrypt_data_key(self, encrypted_key: bytes, key_id: str) -> bytes:
        raise NotImplementedError


class InsecureLocalKMS(KMSClient):
    """Dev-only stand-in for KMS (do NOT use in production).

    This wraps data keys using a local master key stored in an env var.
    """

    def __init__(self, master_key_b64_env: str = "MASTER_KEY_B64") -> None:
        raw = os.environ.get(master_key_b64_env)
        if not raw:
            raise ValueError(f"Missing env var: {master_key_b64_env}")
        self._master_key = base64.b64decode(raw)

    def generate_data_key(self, key_id: str) -> Tuple[bytes, bytes]:
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        wrapped = AESGCM(self._master_key).encrypt(nonce, data_key, key_id.encode("ascii"))
        return data_key, nonce + wrapped

    def decrypt_data_key(self, encrypted_key: bytes, key_id: str) -> bytes:
        nonce = encrypted_key[:12]
        wrapped = encrypted_key[12:]
        return AESGCM(self._master_key).decrypt(nonce, wrapped, key_id.encode("ascii"))


class EnvelopeCrypto:
    def __init__(self, kms: KMSClient, key_id: str, cache: Optional[DataKeyCache] = None) -> None:
        self._kms = kms
        self._key_id = key_id
        self._cache = cache or DataKeyCache()

    def encrypt_payload(self, plaintext: bytes, aad: bytes = AAD_DEFAULT) -> dict:
        cached = self._cache.get()
        if cached:
            data_key = cached.plaintext_key
            encrypted_key_b64 = cached.encrypted_key_b64
        else:
            data_key, encrypted_key = self._kms.generate_data_key(self._key_id)
            encrypted_key_b64 = _b64e(encrypted_key)
            self._cache.set(data_key, encrypted_key_b64)

        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        return {
            "nonce_b64": _b64e(nonce),
            "ciphertext_b64": _b64e(ciphertext),
            "aad_b64": _b64e(aad),
            "encrypted_data_key_b64": encrypted_key_b64,
            "key_id": self._key_id,
        }

    def decrypt_payload(self, blob: dict) -> bytes:
        encrypted_key_b64 = blob["encrypted_data_key_b64"]
        cached = self._cache.get()
        if cached and cached.encrypted_key_b64 == encrypted_key_b64:
            data_key = cached.plaintext_key
        else:
            encrypted_key = _b64d(encrypted_key_b64)
            data_key = self._kms.decrypt_data_key(encrypted_key, blob["key_id"])
            # Warm up cache for subsequent decrypt-only operations
            self._cache.set(data_key, encrypted_key_b64)

        nonce = _b64d(blob["nonce_b64"])
        ciphertext = _b64d(blob["ciphertext_b64"])
        aad = _b64d(blob["aad_b64"])
        return AESGCM(data_key).decrypt(nonce, ciphertext, aad)

    def safe_decrypt_payload(self, blob: dict) -> bytes:
        """Decrypt with strict error handling for WAF boundary use.
        
        Raises:
            ValueError: If payload is invalid, malformed, or tampered.
        """
        try:
            return self.decrypt_payload(blob)
        except (KeyError, ValueError, InvalidTag):
            raise ValueError("Invalid or tampered payload")


# Example usage (dev only):
# 1) export MASTER_KEY_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode('ascii'))")
# 2) Use InsecureLocalKMS to mimic a KMS provider.
if __name__ == "__main__":
    kms = InsecureLocalKMS()
    crypto = EnvelopeCrypto(kms=kms, key_id="waf-master-key")

    payload = b"{\"user_input\":\"hello\"}"
    encrypted = crypto.encrypt_payload(payload)
    
    # Use safe_decrypt_payload at WAF boundary for strict validation
    try:
        decrypted = crypto.safe_decrypt_payload(encrypted)
        print(decrypted.decode("utf-8"))
    except ValueError as e:
        print(f"Blocked: {e}")
