/*
  Generates a batch of LARGE encryptedRequest samples compatible with:
  - livepage/backend/utils/envelope-crypto.js (AES-256-GCM + AAD)
  - POST /traffic/ingest (body: { correlationId, encryptedRequest })

  Output:
  - encrypted-traffic-samples.large.json
  - encrypted-traffic-samples.large.csv

  Notes:
  - Uses APP_LAYER_MASTER_KEY_B64 if set, otherwise falls back to
    SHA256('twilight-dev-master-key') (matches envelope-crypto.js).
  - Nonces are deterministic (derived from seed + index) so the output is stable.
*/

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const AAD = 'waf-v1';

function getMasterKey() {
  const keyBase64 = process.env.APP_LAYER_MASTER_KEY_B64;
  if (!keyBase64) {
    return crypto.createHash('sha256').update('twilight-dev-master-key').digest();
  }

  const decoded = Buffer.from(keyBase64, 'base64');
  if (decoded.length !== 32) {
    throw new Error('APP_LAYER_MASTER_KEY_B64 must decode to 32 bytes');
  }
  return decoded;
}

function nonceFor(seed, index) {
  return crypto
    .createHash('sha256')
    .update(`${seed}:${index}`)
    .digest()
    .subarray(0, 12);
}

function encryptUtf8WithNonce(plaintext, nonce, aad = AAD) {
  const masterKey = getMasterKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    nonce_b64: nonce.toString('base64'),
    ciphertext_b64: Buffer.concat([encrypted, authTag]).toString('base64'),
    aad_b64: Buffer.from(aad, 'utf8').toString('base64'),
    algo: 'aes-256-gcm-app-layer',
  };
}

function ipFor(index) {
  const a = 198;
  const b = 51;
  const c = 100;
  const d = (index % 250) + 1;
  return `${a}.${b}.${c}.${d}`;
}

function largePayloadFor(index) {
  const itemCount = 12 + (index % 8);
  const items = Array.from({ length: itemCount }, (_v, i) => {
    const sku = `SKU-${String(1000 + i).padStart(4, '0')}`;
    return {
      sku,
      name: `Demo Line Item ${i + 1}`,
      qty: (i % 5) + 1,
      price: Number((19.95 + i * 1.1).toFixed(2)),
      meta: {
        region: ['us-east-1', 'us-west-2', 'eu-central-1'][i % 3],
        plan: ['free', 'pro', 'enterprise'][index % 3],
        burst: i % 2 === 0,
      },
    };
  });

  const notesBase = [
    'Large payload encryption demo',
    'Contains nested arrays and objects',
    'Used to validate app-layer envelope decryption',
    'Not a real customer record',
  ];

  // Include a couple of “security-ish” strings for classification demos.
  const securityStrings = [
    "search=1' OR '1'='1",
    '<script>alert("xss")</script>',
    '../../../../../etc/passwd',
    'UNION SELECT username, password FROM users',
  ];

  const extraPadding = 'X'.repeat(900 + (index % 5) * 250);

  return {
    transactionId: `txn-${String(880000 + index).padStart(6, '0')}`,
    customer: {
      id: `cust-${String(330000 + index).padStart(6, '0')}`,
      email: `demo+${index}@example.com`,
      roles: ['user', index % 3 === 0 ? 'beta' : 'standard'],
      preferences: {
        mfa: index % 2 === 0,
        alerts: ['email', index % 4 === 0 ? 'sms' : 'none'].filter((v) => v !== 'none'),
        language: 'en-US',
      },
    },
    items,
    totals: {
      subtotal: Number((items.reduce((acc, it) => acc + it.qty * it.price, 0)).toFixed(2)),
      tax: Number((2.5 + (index % 10) * 0.7).toFixed(2)),
      discounts: [
        { code: 'SAVE10', amount: 10.0 },
        ...(index % 5 === 0 ? [{ code: 'BETA5', amount: 5.0 }] : []),
      ],
    },
    flags: {
      suspect: index % 4 === 0,
      source: 'demo-ingest',
      notes: `${notesBase[index % notesBase.length]} | ${securityStrings[index % securityStrings.length]} | pad=${extraPadding}`,
    },
  };
}

function buildPlaintextRecord(index) {
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
  const endpoints = [
    '/api/payments/submit',
    '/api/orders/create',
    '/api/profile/update',
    '/api/search',
    '/api/support/ticket',
  ];

  const method = methods[index % methods.length];
  const endpoint = endpoints[index % endpoints.length];

  return {
    method,
    endpoint,
    ipAddress: ipFor(index),
    country: ['US', 'IN', 'DE', 'GB', 'BR'][index % 5],
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    headers: {
      'content-type': 'application/json',
      'x-request-id': `req-demo-large-${String(index).padStart(3, '0')}`,
      'x-forwarded-for': ipFor(index),
      authorization: 'Bearer demo-token',
    },
    payload: largePayloadFor(index),
    receivedAt: new Date(Date.UTC(2026, 1, 13, 0, 0, 0 + index)).toISOString(),
  };
}

function csvEscape(value) {
  const text = String(value ?? '');
  if (text.includes('"')) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  if (text.includes(',') || text.includes('\n') || text.includes('\r')) {
    return `"${text}"`;
  }
  return text;
}

function main() {
  const args = process.argv.slice(2);
  const countArg = args.find((a) => a.startsWith('--count='));
  const seedArg = args.find((a) => a.startsWith('--seed='));
  const outDirArg = args.find((a) => a.startsWith('--outDir='));

  const count = countArg ? Number(countArg.split('=')[1]) : 25;
  const seed = seedArg ? seedArg.split('=')[1] : 'twilight-demo-seed-v1';
  const outDir = outDirArg ? outDirArg.split('=')[1] : __dirname;

  if (!Number.isFinite(count) || count <= 0) {
    throw new Error('Invalid --count');
  }

  const rows = [];

  for (let i = 0; i < count; i += 1) {
    const correlationId = `demo-large-${String(i + 1).padStart(3, '0')}`;
    const plaintextObj = buildPlaintextRecord(i + 1);
    const plaintext = JSON.stringify(plaintextObj);

    const nonce = nonceFor(seed, i + 1);
    const encryptedRequest = encryptUtf8WithNonce(plaintext, nonce, AAD);

    rows.push({
      correlationId,
      method: plaintextObj.method,
      endpoint: plaintextObj.endpoint,
      ipAddress: plaintextObj.ipAddress,
      plaintext_len: plaintext.length,
      encryptedRequest,
    });
  }

  const jsonOut = {
    generatedAt: new Date().toISOString(),
    count: rows.length,
    aad: AAD,
    algo: 'aes-256-gcm-app-layer',
    keyMode: process.env.APP_LAYER_MASTER_KEY_B64 ? 'env:APP_LAYER_MASTER_KEY_B64' : 'fallback:sha256(twilight-dev-master-key)',
    seed,
    samples: rows,
  };

  const jsonPath = path.join(outDir, 'encrypted-traffic-samples.large.json');
  fs.writeFileSync(jsonPath, JSON.stringify(jsonOut, null, 2), 'utf8');

  const csvHeader = [
    'correlationId',
    'method',
    'endpoint',
    'ipAddress',
    'plaintext_len',
    'nonce_b64',
    'aad_b64',
    'algo',
    'ciphertext_b64',
  ].join(',');

  const csvLines = [csvHeader];
  for (const row of rows) {
    csvLines.push(
      [
        row.correlationId,
        row.method,
        row.endpoint,
        row.ipAddress,
        row.plaintext_len,
        row.encryptedRequest.nonce_b64,
        row.encryptedRequest.aad_b64,
        row.encryptedRequest.algo,
        row.encryptedRequest.ciphertext_b64,
      ]
        .map(csvEscape)
        .join(','),
    );
  }

  const csvPath = path.join(outDir, 'encrypted-traffic-samples.large.csv');
  fs.writeFileSync(csvPath, csvLines.join('\n') + '\n', 'utf8');

  // eslint-disable-next-line no-console
  console.log(`Wrote ${jsonPath}`);
  // eslint-disable-next-line no-console
  console.log(`Wrote ${csvPath}`);
}

main();
