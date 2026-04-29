# Self-Healing Distributed WAF Deployment Summary

## KPI Contract (Primary Gate: Set A)
- Accuracy gate: global accuracy must remain >= 85% on golden holdout + rolling live window.
- Latency gate: average request latency target is 5-10ms.
- Worst-case gate: worst-case latency target is 25-40ms.
- Stretch objective: approach <10ms p99 on inference hot path.

## Latency Budget by Stage
- Pre-gate regex path target: <= 3ms average.
- Model path target (regex + student/teacher decision): <= 10ms average.
- Feedback enqueue target: non-blocking, <= 1ms in hot path.
- Learning/sync/log flushing: must run off hot path and must not block inference.

## Threat Model Contracts
- Poisoning definition: any feedback attempting to shift decision boundary against teacher-validated behavior.
- Unsafe feedback is blocked via trust gate + quarantine lane.
- Trust policy is asymmetric: slow trust gain, immediate trust drop on malicious teacher signal.
- Quarantined sources cannot influence student updates.

## Sync-Storm and Control Plane Limits
- Sync operations must use jittered intervals and exponential backoff.
- Idempotency key is required for sync batch acceptance.
- Coordinator endpoints are control-plane only and must not run in request hot path.

## Self-Heal and Rollback SLO
- Bounded staleness/drift breach triggers automatic teacher-forced inference mode.
- Student checkpoint rollback is automatic on sustained drift/quality regression or learner queue failure.
- Node state must expose: teacher-forced mode, drift score, rollback count, queue depth, and sync lag.
