import argparse
import base64
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

MALICIOUS_PAYLOADS = [
    "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
    "GET /../../../../etc/passwd HTTP/1.1",
    "POST /api/run HTTP/1.1 ; cat /etc/passwd",
]

BENIGN_PAYLOADS = [
    "GET /api/products?page=1 HTTP/1.1",
    "POST /api/login HTTP/1.1",
    "GET /api/search?q=laptop HTTP/1.1",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ENDPOINTS = ["/api/login", "/api/products", "/api/search", "/api/orders", "/api/upload"]
COUNTRIES = ["US", "IN", "DE", "GB", "BR"]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def random_ip() -> str:
    return ".".join(
        [
            str(random.randint(1, 255)),
            str(random.randint(0, 255)),
            str(random.randint(0, 255)),
            str(random.randint(1, 255)),
        ]
    )


def encrypt_utf8(plaintext: str, key_b64: str, aad: str = "waf-v1") -> dict:
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("APP_LAYER_MASTER_KEY_B64 must decode to exactly 32 bytes")

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return {
        "nonce_b64": b64(nonce),
        "ciphertext_b64": b64(ciphertext),
        "aad_b64": b64(aad.encode("utf-8")),
        "algo": "aes-256-gcm-app-layer",
    }


def build_payload() -> dict:
    is_malicious = random.random() < 0.7
    raw_payload = random.choice(MALICIOUS_PAYLOADS if is_malicious else BENIGN_PAYLOADS)
    return {
        "payload": raw_payload,
        "method": random.choice(METHODS),
        "endpoint": random.choice(ENDPOINTS),
        "ipAddress": random_ip(),
        "country": random.choice(COUNTRIES),
        "receivedAt": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed encrypted traffic into WAF ingest endpoint")
    parser.add_argument("--target", default="http://localhost:5000", help="Base URL, e.g. http://localhost:5000 or https://10.0.0.10:8443")
    parser.add_argument("--count", type=int, default=200, help="Number of requests")
    parser.add_argument("--sleep-ms", type=int, default=50, help="Delay between requests in milliseconds")
    parser.add_argument("--tls-verify", action="store_true", help="Enable TLS certificate verification")
    args = parser.parse_args()

    key_b64 = os.environ.get(
        "APP_LAYER_MASTER_KEY_B64",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    )

    if not args.tls_verify:
        disable_warnings(InsecureRequestWarning)

    ok = 0
    fail = 0

    for _ in range(args.count):
        payload = build_payload()
        encrypted = encrypt_utf8(json.dumps(payload, separators=(",", ":")), key_b64)
        body = {"correlationId": str(uuid.uuid4()), "encryptedRequest": encrypted}

        try:
            response = requests.post(
                f"{args.target}/api/traffic/ingest",
                json=body,
                timeout=10,
                verify=args.tls_verify,
            )
            if response.status_code < 300:
                ok += 1
            else:
                fail += 1
        except requests.RequestException:
            fail += 1

        time.sleep(max(args.sleep_ms, 0) / 1000.0)

    print(json.dumps({"ok": ok, "failed": fail, "target": args.target}, indent=2))


if __name__ == "__main__":
    main()
