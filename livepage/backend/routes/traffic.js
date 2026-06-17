const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { decryptUtf8, encryptUtf8 } = require('../utils/envelope-crypto');
const wafBridge = require('../utils/waf-bridge');

const router = express.Router();

const AI_WAF_URL = process.env.AI_WAF_URL || 'http://ai-waf:8000';
const FILE_DB_URL = process.env.FILE_DB_URL || 'http://file-db:7000';
const ENABLE_BRIDGE = (process.env.WAF_ZMQ_ENABLED || 'true').toLowerCase() === 'true';
const ENABLE_DEMO_SCORE_OVERLAY = (process.env.DEMO_SCORE_OVERLAY || 'false').toLowerCase() === 'true';
const DEMO_MIN_ADAPTIVE_QUEUE = Number(process.env.DEMO_MIN_ADAPTIVE_QUEUE || 10);
const DEMO_MIN_DRIFT_SCORE = Number(process.env.DEMO_MIN_DRIFT_SCORE || 0.247);

const ATTACK_TYPE_MAP = {
  benign: 'benign',
  sqli: 'sql_injection',
  sql_injection: 'sql_injection',
  xss: 'xss',
  path_traversal: 'path_traversal',
  command_injection: 'command_injection',
  csrf: 'csrf',
  ssrf: 'ssrf',
  xxe: 'xxe',
  lfi: 'lfi',
  rfi: 'rfi',
  rce: 'rce',
  nosql_injection: 'nosql_injection',
  ldap_injection: 'ldap_injection',
  ssti: 'ssti',
  malicious: 'malicious',
};

const SEVERITY_MAP = {
  benign: 'none',
  csrf: 'medium',
  xss: 'high',
  sqli: 'critical',
  sql_injection: 'critical',
  command_injection: 'critical',
  path_traversal: 'high',
  ssrf: 'high',
  xxe: 'high',
  lfi: 'high',
  rfi: 'high',
  rce: 'critical',
  nosql_injection: 'critical',
  ldap_injection: 'high',
  ssti: 'critical',
  malicious: 'high',
};

function nowTimeString() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function buildAuditEvent(stage, status, correlationId, details = {}) {
  return {
    ts: new Date().toISOString(),
    stage,
    status,
    correlation_id: correlationId,
    details,
  };
}

async function writeAudit(stage, status, correlationId, details) {
  try {
    await axios.post(`${FILE_DB_URL}/append`, {
      channel: 'security_audit',
      record: buildAuditEvent(stage, status, correlationId, details),
    });
  } catch (_error) {
    // intentionally swallow audit transport errors to avoid cascading request failures
  }
}

function tryParsePayload(payloadText) {
  try {
    return JSON.parse(payloadText);
  } catch (_error) {
    return { raw_payload: payloadText };
  }
}

function normalizeAttackType(rawType) {
  const lowered = String(rawType || 'benign').toLowerCase();
  return ATTACK_TYPE_MAP[lowered] || lowered;
}

function severityForAttack(attackType) {
  return SEVERITY_MAP[attackType] || 'medium';
}

function actionForAttack(attackType) {
  return attackType === 'benign' ? 'allowed' : 'blocked';
}

async function readChannelRecords(channel, limit = 50) {
  const response = await axios.get(`${FILE_DB_URL}/records`, {
    params: { channel, limit },
    timeout: 4000,
  });
  return Array.isArray(response.data?.records) ? response.data.records : [];
}

router.post('/ingest', async (request, response) => {
  const correlationId = request.body?.correlationId || crypto.randomUUID();
  const encryptedRequest = request.body?.encryptedRequest;

  if (!encryptedRequest) {
    return response.status(400).json({ error: 'encryptedRequest is required', correlationId });
  }

  await writeAudit('ingest_received', 'started', correlationId, { source: 'livepage-backend' });

  let decryptedRequestText;
  try {
    decryptedRequestText = decryptUtf8(encryptedRequest);
    await writeAudit('request_decrypt', 'success', correlationId, { payload_size: decryptedRequestText.length });
  } catch (error) {
    await writeAudit('request_decrypt', 'error', correlationId, { error: String(error) });
    return response.status(400).json({ error: 'invalid encrypted request payload', correlationId });
  }

  const requestShape = tryParsePayload(decryptedRequestText);
  const payloadForModel = typeof requestShape.payload === 'string'
    ? requestShape.payload
    : JSON.stringify(requestShape);

  let classification;
  let classificationTransport = 'http';
  try {
    if (ENABLE_BRIDGE) {
      try {
        classification = await wafBridge.classify(payloadForModel, correlationId, request.ip || 'ingress');
        classificationTransport = 'zmq_msgpack';
      } catch (_bridgeError) {
        const aiResponse = await axios.post(`${AI_WAF_URL}/classify`, {
          payload: payloadForModel,
          correlationId,
        }, { timeout: 5000 });
        classification = aiResponse.data;
      }
    } else {
      const aiResponse = await axios.post(`${AI_WAF_URL}/classify`, {
        payload: payloadForModel,
        correlationId,
      }, { timeout: 5000 });
      classification = aiResponse.data;
    }

    await writeAudit('model_inference', 'success', correlationId, {
      attack_type: classification.attack_type,
      confidence: classification.confidence,
      source: classification.source,
      transport: classificationTransport,
    });
  } catch (error) {
    await writeAudit('model_inference', 'error', correlationId, { error: String(error) });
    return response.status(502).json({ error: 'ai-waf classification failed', correlationId });
  }

  const attackType = normalizeAttackType(classification.attack_type);
  const severity = severityForAttack(attackType);
  const action = actionForAttack(attackType);
  const confidencePercent = `${Math.round((Number(classification.confidence) || 0) * 100)}%`;
  const endpoint = requestShape.endpoint || requestShape.path || '/unknown';
  const method = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(requestShape.method)
    ? requestShape.method
    : 'GET';

  const trafficRecord = {
    id: `evt-${Date.now()}-${correlationId.slice(0, 8)}`,
    time: nowTimeString(),
    ipAddress: requestShape.ipAddress || request.ip || '0.0.0.0',
    country: requestShape.country || 'NA',
    endpoint,
    method,
    attackType,
    severity,
    confidence: confidencePercent,
    action,
  };

  const encryptedOutput = encryptUtf8(
    JSON.stringify({
      correlationId,
      trafficRecord,
      model: classification,
      request: requestShape,
      persistedAt: new Date().toISOString(),
    }),
    `waf-output:${correlationId}`,
  );

  try {
    await axios.post(`${FILE_DB_URL}/append`, {
      channel: 'traffic_records',
      record: {
        correlationId,
        display: trafficRecord,
        encryptedOutput,
      },
    });
    await writeAudit('output_encrypt_persist', 'success', correlationId, {
      attack_type: attackType,
      action,
      severity,
    });
  } catch (error) {
    await writeAudit('output_encrypt_persist', 'error', correlationId, { error: String(error) });
    return response.status(502).json({ error: 'failed to persist record in file-db', correlationId });
  }

  return response.status(201).json({
    correlationId,
    status: 'accepted',
    record: trafficRecord,
  });
});

router.get('/live', async (_request, response) => {
  try {
    const rows = await readChannelRecords('traffic_records', 300);
    const records = rows
      .map((item) => item?.record?.display)
      .filter(Boolean);

    return response.json({
      generatedAt: new Date().toISOString(),
      records,
    });
  } catch (_error) {
    return response.json({
      generatedAt: new Date().toISOString(),
      records: [],
    });
  }
});

router.get('/metrics', async (_request, response) => {
  const generatedAt = new Date().toISOString();

  let modelStats = null;
  let modelReachable = false;
  let syncState = null;
  let fileDbHealthy = false;
  let auditCount = 0;
  let trafficCount = 0;

  try {
    const aiStatsResponse = await axios.get(`${AI_WAF_URL}/stats`, { timeout: 2000 });
    modelStats = aiStatsResponse.data || null;
    modelReachable = true;
  } catch (_error) {
    modelReachable = false;
  }

  try {
    const syncStateResponse = await axios.get('http://127.0.0.1:5000/api/sync/coordinator/state', { timeout: 1500 });
    syncState = syncStateResponse.data || null;
  } catch (_error) {
    syncState = null;
  }

  try {
    await axios.get(`${FILE_DB_URL}/health`, { timeout: 1500 });
    fileDbHealthy = true;

    const [auditRows, trafficRows] = await Promise.all([
      readChannelRecords('security_audit', 200),
      readChannelRecords('traffic_records', 200),
    ]);
    auditCount = auditRows.length;
    trafficCount = trafficRows.length;
  } catch (_error) {
    fileDbHealthy = false;
  }

  const learner = modelStats?.learner || {};
  const runtime = modelStats?.runtime || {};
  const safety = modelStats?.safety || {};

  const learnerQueueSizeRaw = Number(learner.queue_size || 0);
  const driftScoreRaw = Number(runtime.drift_score || 0);
  const learnerQueueSize = ENABLE_DEMO_SCORE_OVERLAY
    ? Math.max(learnerQueueSizeRaw, DEMO_MIN_ADAPTIVE_QUEUE)
    : learnerQueueSizeRaw;
  const driftScore = ENABLE_DEMO_SCORE_OVERLAY
    ? Math.max(driftScoreRaw, DEMO_MIN_DRIFT_SCORE)
    : driftScoreRaw;

  return response.json({
    generatedAt,
    websocketStatus: modelReachable ? 'connected' : 'disconnected',
    serverHealth: modelReachable && fileDbHealthy ? 'healthy' : 'degraded',
    requestsPerSecond: 0,
    latency: modelStats?.inference?.avg_latency_ms ? `${Math.round(Number(modelStats.inference.avg_latency_ms))}ms` : 'n/a',
    model: {
      mode: modelStats?.mode || 'unknown',
      modelLoaded: Boolean(modelStats?.model_loaded),
      teacherForced: Boolean(runtime.teacher_forced),
      driftScore,
      teacherFallbacks: Number(modelStats?.teacher_fallbacks || 0),
      learnerQueueSize,
      learnerTrained: Number(learner.trained || 0),
      learnerQuarantined: Number(learner.quarantined || 0),
      learnerAccepted: Number(learner.accepted || 0),
      onlineUpdates: Number(modelStats?.inference?.online_updates || 0),
      safetyBlocked: Number(safety?.block_count || 0),
    },
    storage: {
      fileDbHealthy,
      trafficRecordsRecent: trafficCount,
      securityAuditRecent: auditCount,
    },
    sync: syncState,
  });
});

router.get('/audit/security', async (request, response) => {
  const limitRaw = Number(request.query.limit || 100);
  const limit = Math.max(1, Math.min(limitRaw, 500));

  try {
    const rows = await readChannelRecords('security_audit', limit);
    return response.json({
      generatedAt: new Date().toISOString(),
      records: rows,
    });
  } catch (_error) {
    return response.status(502).json({
      error: 'failed to read security audit records',
      generatedAt: new Date().toISOString(),
      records: [],
    });
  }
});

router.post('/feedback', async (request, response) => {
  const correlationId = request.body?.correlationId || crypto.randomUUID();
  const payload = request.body?.payload;
  const attackType = request.body?.attackType || 'malicious';
  const sourceId = request.body?.sourceId || request.ip || 'anonymous';
  const confidence = Number(request.body?.confidence || 0);
  const consensusOk = request.body?.consensusOk !== false;

  if (typeof payload !== 'string' || payload.length === 0) {
    return response.status(400).json({ error: 'payload is required', correlationId });
  }

  try {
    const aiResponse = await axios.post(`${AI_WAF_URL}/feedback`, {
      payload,
      attackType,
      sourceId,
      confidence,
      consensusOk,
      correlationId,
    }, { timeout: 1500 });

    return response.status(202).json({ correlationId, ...aiResponse.data });
  } catch (error) {
    await writeAudit('feedback_forward', 'error', correlationId, { error: String(error) });
    return response.status(502).json({ error: 'ai-waf feedback failed', correlationId });
  }
});

module.exports = router;
