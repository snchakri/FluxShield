const crypto = require('crypto');
const express = require('express');

const router = express.Router();

const IDEMPOTENCY_TTL_SECONDS = Number(process.env.SYNC_IDEMPOTENCY_TTL_SECONDS || 300);
const JITTER_SECONDS = Number(process.env.SYNC_JITTER_SECONDS || 45);
const BACKOFF_MIN_SECONDS = Number(process.env.SYNC_BACKOFF_MIN_SECONDS || 1);
const BACKOFF_MAX_SECONDS = Number(process.env.SYNC_BACKOFF_MAX_SECONDS || 60);

const seenBatches = new Map();
const nodeStates = new Map();

let globalSnapshotVersion = 1;
let globalChecksum = 'bootstrap';

function cleanupSeenBatches() {
  const now = Date.now();
  for (const [batchKey, expiresAt] of seenBatches.entries()) {
    if (expiresAt <= now) {
      seenBatches.delete(batchKey);
    }
  }
}

function nextPacingHintSeconds(attempt = 0) {
  const cappedAttempt = Math.max(0, Number(attempt) || 0);
  const exponential = Math.min(BACKOFF_MAX_SECONDS, BACKOFF_MIN_SECONDS * (2 ** cappedAttempt));
  const jitter = Math.floor(Math.random() * (JITTER_SECONDS + 1));
  return exponential + jitter;
}

router.post('/coordinator/push', (request, response) => {
  cleanupSeenBatches();

  const nodeId = String(request.body?.nodeId || 'unknown-node');
  const batchId = String(request.body?.batchId || '');
  const checksum = String(request.body?.checksum || '');
  const sampleCount = Number(request.body?.sampleCount || 0);
  const attempt = Number(request.body?.attempt || 0);

  if (!batchId || !checksum) {
    return response.status(400).json({ error: 'batchId and checksum are required' });
  }

  const idempotencyKey = `${nodeId}:${batchId}`;
  if (seenBatches.has(idempotencyKey)) {
    return response.status(202).json({
      accepted: true,
      duplicate: true,
      nextSyncAfterSeconds: nextPacingHintSeconds(attempt),
    });
  }

  seenBatches.set(idempotencyKey, Date.now() + IDEMPOTENCY_TTL_SECONDS * 1000);

  const newGlobalSeed = `${globalChecksum}:${checksum}:${sampleCount}:${Date.now()}`;
  globalChecksum = crypto.createHash('sha256').update(newGlobalSeed).digest('hex').slice(0, 16);
  globalSnapshotVersion += 1;

  nodeStates.set(nodeId, {
    lastPushAt: new Date().toISOString(),
    checksum,
    batchId,
    sampleCount,
  });

  return response.status(202).json({
    accepted: true,
    duplicate: false,
    snapshotVersion: globalSnapshotVersion,
    globalChecksum,
    nextSyncAfterSeconds: nextPacingHintSeconds(attempt),
  });
});

router.get('/coordinator/pull', (request, response) => {
  const nodeId = String(request.query.nodeId || 'unknown-node');
  const localChecksum = String(request.query.checksum || '');
  const attempt = Number(request.query.attempt || 0);

  if (localChecksum && localChecksum === globalChecksum) {
    return response.status(304).send();
  }

  return response.json({
    nodeId,
    snapshotVersion: globalSnapshotVersion,
    globalChecksum,
    nextSyncAfterSeconds: nextPacingHintSeconds(attempt),
  });
});

router.get('/coordinator/state', (_request, response) => {
  cleanupSeenBatches();
  return response.json({
    snapshotVersion: globalSnapshotVersion,
    globalChecksum,
    knownNodes: nodeStates.size,
    idempotencyEntries: seenBatches.size,
    config: {
      idempotencyTtlSeconds: IDEMPOTENCY_TTL_SECONDS,
      jitterSeconds: JITTER_SECONDS,
      backoffMinSeconds: BACKOFF_MIN_SECONDS,
      backoffMaxSeconds: BACKOFF_MAX_SECONDS,
    },
  });
});

module.exports = router;
