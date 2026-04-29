# Twilight Docker Runbook

## Services
- `frontend` (nginx static app) on `http://localhost:8081`
- `backend` (single API orchestrator) on `http://localhost:5000`
- `ai-waf` (v1 inference service) on `http://localhost:8000`
- `file-db` (file-writing database service) on `http://localhost:7000`

## Start
```bash
docker compose up --build
```

## Stop
```bash
docker compose down
```

## Pipeline test (decrypt -> infer -> encrypt -> persist)
Send an app-layer encrypted payload to backend `POST /api/traffic/ingest`.

### Sample plaintext payload
```json
{
  "payload": "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
  "method": "GET",
  "endpoint": "/admin.php",
  "ipAddress": "203.0.113.10",
  "country": "US"
}
```

Encrypt the payload using the same AES-GCM app-layer scheme expected by backend and submit as:
```json
{
  "encryptedRequest": {
    "nonce_b64": "...",
    "ciphertext_b64": "...",
    "aad_b64": "..."
  }
}
```

Then verify live stream output:
- `GET http://localhost:5000/api/traffic/live`
- `GET http://localhost:8081`

## Robustness controls (current implementation)
- `ai-waf` includes robust runtime path with teacher/student arbitration and async learner process.
- Feedback ingestion endpoint: `POST http://localhost:8000/feedback`.
- Runtime stats endpoint: `GET http://localhost:8000/stats`.
- Queue, trust, and drift thresholds are configurable via container environment variables in compose.

### Demo-realistic adaptive settings (current compose)
- `TRUST_WARMUP_SECONDS=0` so accepted feedback can be observed during a short live demo.
- `TRUST_MIN_SCORE=0.35` keeps trust gating meaningful (requires repeated high-quality feedback).
- `LEARNER_BATCH_SIZE=8` allows small visible training increments instead of large jumps.
- `DRIFT_TRIGGER=0.12` keeps teacher-forced mode possible but not too easy to trigger.
- `PRE_GATE_THRESHOLD=0.99` pushes more requests through student/teacher comparison for realistic drift/fallback telemetry.

## Binary bridge (Node -> Python)
- Default internal transport is ZeroMQ + MessagePack (`WAF_ZMQ_ENABLED=true`).
- Backend endpoint config: `WAF_ZMQ_ENDPOINT=tcp://ai-waf:5557`.
- AI-WAF bind config: `AI_WAF_ZMQ_BIND=tcp://0.0.0.0:5557`.
- If bridge call fails or times out, backend falls back to HTTP classify endpoint automatically.

## Stored files
- `file-db` writes channel files to host path `file-db/data/` (mounted to `/data` in container).
  - `file-db/data/security_audit.jsonl`
  - `file-db/data/traffic_records.jsonl`
- `ai-waf` writes security audit JSONL logs to `backup_model/v1/logs/security_audit.jsonl` (bind-mounted to `/app/logs`).

Quick checks:
- `GET http://localhost:7000/health`
- `GET http://localhost:7000/records?channel=security_audit&limit=5`
- `GET http://localhost:5000/api/traffic/audit/security?limit=10`
- `GET http://localhost:5000/api/traffic/metrics`

## Load testing and traffic seeding

### Locust (mixed benign + malicious encrypted traffic)
1. Install tools:
```bash
pip install -r loadtest/requirements.txt
```
2. Run Locust against backend API (HTTP):
```bash
locust -f loadtest/locustfile.py --host http://localhost:5000
```
3. For TLS target by IP/port (example):
```bash
TLS_VERIFY=false locust -f loadtest/locustfile.py --host https://10.0.0.12:8443
```

### Direct traffic seeding (no Locust UI)
```bash
python loadtest/seed_traffic.py --target http://localhost:5000 --count 500 --sleep-ms 20
```

TLS target example:
```bash
python loadtest/seed_traffic.py --target https://10.0.0.12:8443 --count 200 --sleep-ms 50
```

If your TLS cert is valid and trusted, add `--tls-verify`.
