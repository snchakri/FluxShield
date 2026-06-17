# Encrypted Traffic Demo

This note shows how to craft deterministic encrypted traffic samples for the `/traffic/ingest` endpoint and explains how the encryption/ingest path works.

## Architecture (high-level)
- Live ingest: [livepage/backend/routes/traffic.js](../routes/traffic.js) decrypts `encryptedRequest`, normalizes the request shape, calls AI-WAF, and persists both the display record and the encrypted output.
- Crypto: [livepage/backend/utils/envelope-crypto.js](../utils/envelope-crypto.js) implements AES-256-GCM with AAD. The master key comes from `APP_LAYER_MASTER_KEY_B64`; if unset, it falls back to `SHA256("twilight-dev-master-key")`.
- AI-WAF path: the route prefers the ZeroMQ bridge ([livepage/backend/utils/waf-bridge.js](../utils/waf-bridge.js)) when `WAF_ZMQ_ENABLED=true`; otherwise it posts to `AI_WAF_URL`.
- Persistence: results and audit events are appended to File-DB (`FILE_DB_URL`), channel `traffic_records` (and `security_audit`).

## Large deterministic sample (uses fallback master key)
- IV (hex): `00112233445566778899aabb`
- AAD: `waf-v1`
- Plaintext (JSON string):
```
{"method":"POST","endpoint":"/api/payments/submit","ipAddress":"198.51.100.42","country":"US","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36","headers":{"content-type":"application/json","x-request-id":"req-demo-large-001","x-forwarded-for":"198.51.100.42","authorization":"Bearer demo-token"},"payload":{"transactionId":"txn-884422","customer":{"id":"cust-332211","email":"demo@example.com","roles":["user","beta"],"preferences":{"mfa":true,"alerts":["email","sms"],"language":"en-US"}},"items":[{"sku":"SKU-1000","name":"Edge Firewall Addon","qty":2,"price":49.99,"meta":{"plan":"pro","region":"us-east-1"}},{"sku":"SKU-2000","name":"AI WAF Credits","qty":500,"price":0.05,"meta":{"model":"waf-v2","burst":true}},{"sku":"SKU-3000","name":"Support","qty":1,"price":199.0,"meta":{"sla":"gold","contact":"pager"}}],"totals":{"subtotal":274.99,"tax":23.12,"discounts":[{"code":"SAVE10","amount":10.00},{"code":"BETA5","amount":5.00}],"grandTotal":283.11},"flags":{"suspect":false,"source":"demo-ingest","notes":"Large payload encryption demo"}}}
```
- Encrypted blob (matches `encryptUtf8`):
```
{
  "nonce_b64": "ABEiM0RVZneImaq7",
  "ciphertext_b64": "wS9rzPC2q3o1tbF5WSxgvrQQyqKW0uBExOrmkU8kIn5RjQgfCx/ZFPOXPbadc+JIo8FHVbAq389BWymXZi4VXuNu3uaOGgzSjDToSdzaiUtctwn6EaHXHJW5dw3J/MC4wbmKFF0IykLeY4GfMw/VakofhL4XhrL+HWJympOQLe6TdvCLfWRxM07sjbc5vSySzNVBs9Qq7z2XFmsqnqz6P1r8P6iSIkXUQOTxtsjhq/o1bvyxB5LLTuKES+UQ+FEZyRdGH58MRWKPyqxtPZ5YfgbmGg8HLLPZUvr+hcm4Rc7UCo0sGHW3bNulcE/kEyHV/yZYjViV9BO4g9/DZYiOcSwYjkqr/37hPbVkexFrNnjtOeA3/bOt9rknhmTmrl8BRZ69TjoC6hBgwnfG6puLUbYPXwPzGfs4yRbjrrAIFGKO+tnnDUC7RzW1HhagL2l2w4p2Yo1UvROdEhEYLUUVLAcW0iWzFpanMXtTMCcYWwtOYr0fORqlBOY/yL+RT9ZwNJwL5qRVAoiKhGxdbXrlUQpSp1w3p0krMcFPHR6QnzPgn5LEObsZqCMYw10btTPN2fC95uNNY+rLMY6NTQ2M3CfjdFnwwYXJbVFD1SG2pgwCggRII6/uXccLGFU/8oasmMi6q1VECkP75sQ3ggZUl6jaf5j0y4XZ2Xw8gCk8BJ42mRVqM3rGa/aN08eW/oAljSjVpJFmg5zy6pOLef25Po4L0ANshRafjE0it2PYvaYQlk4q6y8EeBrer/g6V8/KxuffK/0rFAQrwGzhlq/k+mBV/9knm43gmVIUuWVxYxY4e/NPJbYoN1++P7iHp8+GKcv1y1pEtgCJ0IdjloikGCATtb3YpNDdDuvFxtwcLpxUemd1St4hq5wjO4p0yVGcqKLBOk3lHGnSLcIS4/RuHKdUiwQPQTdDuYaEFP2Qfe6NCInhmhZ67VomQk8OCHqo6g9ksFbeBDBc43XGWs8TZx4lWTAnvj2xu89AzlsM5IG6/t6uGk1dIQumhUbD4h9a0jyw6plLy66+9PPMg96HFDJlxrrEyClm8KmZ+aXk0g1j7p/ebktXrB4YqfAz5UIHv5yLmo8LBMYBHYb+bCEZpUITONPfwa8ysDrQugcgAn+bK/25U9EB1LgP0p5VRAPz0aTVR5jGEx87itn395L2R95oYELaywDIFMLyImurCCQdydq03sqPSmvsO4CWUrtyp/TJSIct7ndjz96rqo32cXa5OnRlRCRQVaV+8v6LyJ7rcN6sBoAAwpxHB3eAtGzpzDJZ55MYGHcL+g4tDl0/mnj2vti21rzf3IbEXs20YYj1mcamz/ew6xmnLTVI5yiNHK4WG6b3HPcDhUPy75WL4DUY7qPIWlxniZ5T89dEP7Zxji6CeqR9S0Q3wh7hVca0lgLZe1f3bNbFFqPSGwLCUzt5d61pWjNhMlmYYFMpXx9QkorzN5B+R/kgWsaHYBM+MYatprSvquN2t+WZTyi9KwqdbLTxzamdn2LWMwNL7fGX",
  "aad_b64": "d2FmLXYx",
  "algo": "aes-256-gcm-app-layer"
}
```

## How to send it
Example curl (adjust host):
```
curl -X POST http://127.0.0.1:7000/traffic/ingest \
  -H "content-type: application/json" \
  -d '{
    "correlationId": "demo-large-001",
    "encryptedRequest": {
      "nonce_b64": "ABEiM0RVZneImaq7",
      "ciphertext_b64": "wS9rzPC2q3o1tbF5WSxgvrQQyqKW0uBExOrmkU8kIn5RjQgfCx/ZFPOXPbadc+JIo8FHVbAq389BWymXZi4VXuNu3uaOGgzSjDToSdzaiUtctwn6EaHXHJW5dw3J/MC4wbmKFF0IykLeY4GfMw/VakofhL4XhrL+HWJympOQLe6TdvCLfWRxM07sjbc5vSySzNVBs9Qq7z2XFmsqnqz6P1r8P6iSIkXUQOTxtsjhq/o1bvyxB5LLTuKES+UQ+FEZyRdGH58MRWKPyqxtPZ5YfgbmGg8HLLPZUvr+hcm4Rc7UCo0sGHW3bNulcE/kEyHV/yZYjViV9BO4g9/DZYiOcSwYjkqr/37hPbVkexFrNnjtOeA3/bOt9rknhmTmrl8BRZ69TjoC6hBgwnfG6puLUbYPXwPzGfs4yRbjrrAIFGKO+tnnDUC7RzW1HhagL2l2w4p2Yo1UvROdEhEYLUUVLAcW0iWzFpanMXtTMCcYWwtOYr0fORqlBOY/yL+RT9ZwNJwL5qRVAoiKhGxdbXrlUQpSp1w3p0krMcFPHR6QnzPgn5LEObsZqCMYw10btTPN2fC95uNNY+rLMY6NTQ2M3CfjdFnwwYXJbVFD1SG2pgwCggRII6/uXccLGFU/8oasmMi6q1VECkP75sQ3ggZUl6jaf5j0y4XZ2Xw8gCk8BJ42mRVqM3rGa/aN08eW/oAljSjVpJFmg5zy6pOLef25Po4L0ANshRafjE0it2PYvaYQlk4q6y8EeBrer/g6V8/KxuffK/0rFAQrwGzhlq/k+mBV/9knm43gmVIUuWVxYxY4e/NPJbYoN1++P7iHp8+GKcv1y1pEtgCJ0IdjloikGCATtb3YpNDdDuvFxtwcLpxUemd1St4hq5wjO4p0yVGcqKLBOk3lHGnSLcIS4/RuHKdUiwQPQTdDuYaEFP2Qfe6NCInhmhZ67VomQk8OCHqo6g9ksFbeBDBc43XGWs8TZx4lWTAnvj2xu89AzlsM5IG6/t6uGk1dIQumhUbD4h9a0jyw6plLy66+9PPMg96HFDJlxrrEyClm8KmZ+aXk0g1j7p/ebktXrB4YqfAz5UIHv5yLmo8LBMYBHYb+bCEZpUITONPfwa8ysDrQugcgAn+bK/25U9EB1LgP0p5VRAPz0aTVR5jGEx87itn395L2R95oYELaywDIFMLyImurCCQdydq03sqPSmvsO4CWUrtyp/TJSIct7ndjz96rqo32cXa5OnRlRCRQVaV+8v6LyJ7rcN6sBoAAwpxHB3eAtGzpzDJZ55MYGHcL+g4tDl0/mnj2vti21rzf3IbEXs20YYj1mcamz/ew6xmnLTVI5yiNHK4WG6b3HPcDhUPy75WL4DUY7qPIWlxniZ5T89dEP7Zxji6CeqR9S0Q3wh7hVca0lgLZe1f3bNbFFqPSGwLCUzt5d61pWjNhMlmYYFMpXx9QkorzN5B+R/kgWsaHYBM+MYatprSvquN2t+WZTyi9KwqdbLTxzamdn2LWMwNL7fGX",
      "aad_b64": "d2FmLXYx",
      "algo": "aes-256-gcm-app-layer"
    }
  }'
```

## Batch samples (JSON + CSV)
This folder also contains a pre-generated *series* of large encrypted samples:
- `encrypted-traffic-samples.large.json`
- `encrypted-traffic-samples.large.csv`

To regenerate them (deterministic nonces):
```
node livepage/backend/demo/generate-encrypted-traffic-samples.js --count=25 --seed=twilight-demo-seed-v1
```

Notes:
- The generated files depend on the active key: `APP_LAYER_MASTER_KEY_B64` if set, otherwise the fallback dev key (see `keyMode` in the JSON).
- For production, do not use deterministic nonces; this is strictly for reproducible demos.

Notes:
- If `APP_LAYER_MASTER_KEY_B64` is set, regenerate with that key; otherwise decryption will fail.
- Keep IVs unique in production; fixed IVs are used here only for deterministic demo payloads.
