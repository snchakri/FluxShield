import base64
import json
import os
import random
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from locust import HttpUser, between, task
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning


AAD = os.environ.get("APP_LAYER_AAD", "waf-v1")
TLS_VERIFY = os.environ.get("TLS_VERIFY", "false").lower() == "true"

MASTER_KEY_B64 = os.environ.get(
    "APP_LAYER_MASTER_KEY_B64",
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",  # 0123456789abcdef0123456789abcdef
)
MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
if len(MASTER_KEY) != 32:
    raise ValueError("APP_LAYER_MASTER_KEY_B64 must decode to exactly 32 bytes")

MALICIOUS_PAYLOADS = [
    "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
    "GET /../../../../etc/passwd HTTP/1.1",
    "POST /api/run HTTP/1.1 ; cat /etc/passwd",
    "GET /api/user?name=${7*7} HTTP/1.1",
    "GET /api/item?id={$ne:null} HTTP/1.1",
]

BENIGN_PAYLOADS = [
    "GET /api/products?page=1&sort=asc HTTP/1.1",
    "POST /api/login HTTP/1.1",
    "GET /api/user/profile HTTP/1.1",
    "GET /api/search?q=laptop HTTP/1.1",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ENDPOINTS = [
    "/api/login",
    "/api/products",
    "/api/search",
    "/api/orders",
    "/api/admin/settings",
    "/api/upload",
]
COUNTRIES = ["US", "IN", "DE", "GB", "BR", "SG"]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt_utf8(plaintext: str, aad: str = AAD) -> dict:
    nonce = os.urandom(12)
    aesgcm = AESGCM(MASTER_KEY)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return {
        "nonce_b64": b64(nonce),
        "ciphertext_b64": b64(ciphertext),
        "aad_b64": b64(aad.encode("utf-8")),
        "algo": "aes-256-gcm-app-layer",
    }


def random_ip() -> str:
    return ".".join(
        [
            str(random.randint(1, 255)),
            str(random.randint(0, 255)),
            str(random.randint(0, 255)),
            str(random.randint(1, 255)),
        ]
    )


def build_http_request_payload() -> dict:
    attack_roll = random.random()
    payload = random.choice(MALICIOUS_PAYLOADS if attack_roll < 0.65 else BENIGN_PAYLOADS)

    return {
        "payload": payload,
        "method": random.choice(METHODS),
        "endpoint": random.choice(ENDPOINTS),
        "ipAddress": random_ip(),
        "country": random.choice(COUNTRIES),
        "receivedAt": datetime.now(timezone.utc).isoformat(),
    }


class WafTrafficUser(HttpUser):
    wait_time = between(0.1, 1.2)

    def on_start(self):
        if not TLS_VERIFY:
            disable_warnings(InsecureRequestWarning)

    @task(8)
    def send_ingest_traffic(self):
        request_payload = build_http_request_payload()
        plaintext = json.dumps(request_payload, separators=(",", ":"))

        body = {
            "correlationId": str(uuid.uuid4()),
            "encryptedRequest": encrypt_utf8(plaintext),
        }

        self.client.post(
            "/api/traffic/ingest",
            json=body,
            name="POST /api/traffic/ingest",
            verify=TLS_VERIFY,
            timeout=10,
        )

    @task(2)
    def poll_live_feed(self):
        self.client.get(
            "/api/traffic/live",
            name="GET /api/traffic/live",
            verify=TLS_VERIFY,
            timeout=10,
        )
