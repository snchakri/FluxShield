# Flux Shield — Theory & Protocols

Authors: Flux Shield contributors

Version: 0.1 — Formalization of core algorithms and protocols implemented in the codebase.

Abstract
--------
This document formalizes the algorithms, protocols, and safety controls used by Flux Shield (formerly Twilight WAF). It consolidates the implemented behavior across runtime, learner, and safety modules into rigorous, reproducible descriptions suitable for research review or operational audit. The text connects code locations to formal definitions, pseudocode, and theoretical guarantees where applicable.

Readers should consult the implementation in `backup_model/v1/` (notably `inference.py`, `robust_inference_engine.py`, `async_learner.py`, `safety_module.py`, `attack_labeler.py`) as parallel reference material.

1. System Model
---------------
We model Flux Shield as a distributed detection and learning system with two primary planes:

- Hot path (detection): deterministic pre-gate filters + student model inference. Implementations: `attack_labeler.AttackLabeler` (pre-gate), `inference.InferenceEngine` (student prediction).
- Off-path (learning): asynchronous feedback ingestion, quarantine lanes, replay anchoring, and periodic model updates. Implementations: `async_learner.AsyncLearner` and `robust_inference_engine.RobustInferenceEngine`.

Notation
- Let R be the set of incoming requests (payloads). Each request r ∈ R has metadata (source_id, timestamp) and content payload(r).
- Student model parameter vector: θ_s. Teacher model (immutable snapshot) parameters: θ_T.
- Feedback sample: s = (payload, label, source_id, confidence, teacher_agreement).
- File-db is an append-only, sharded JSONL store (channels). Each node writes local shards; aggregator composes those shards into centralized datasets.

2. Safety & Trust Protocol (SafetyModule)
----------------------------------------
Purpose: decide whether a feedback sample should be accepted for learning, quarantined for manual review, or rejected.

State per feedback source (source_id):
- trust ∈ ℝ (bounded), first_seen, last_seen, accepted_count, rejected_count.

Algorithm (informal):
1. Compute baseline_signal = 0.5 + confidence bonuses − teacher_penalty + consensus bonus.
2. Update trust: if baseline_signal < 0 then trust ← clip(trust − trust_drop) else trust ← clip(trust + trust_gain).
3. Compute warmed_up = (now − first_seen) ≥ warmup_seconds.
4. Accept iff warmed_up ∧ trust ≥ min_trust_to_learn ∧ confidence ≥ c_min ∧ consensus_ok ∧ ¬teacher_flags_malicious.
5. Quarantine iff trust < quarantine_floor.

Formalization (pseudo):

  state = get_state(source_id)
  baseline = 0.5
  if confidence ≥ 0.85: baseline += 0.2
  if consensus_ok: baseline += 0.2
  if teacher_flags_malicious: baseline -= 0.7

  if baseline < 0:
      state.trust = clip(state.trust − trust_drop)
  else:
      state.trust = clip(state.trust + trust_gain)

  accepted = (state.trust ≥ min_trust_to_learn) ∧ warmed_up ∧ (confidence ≥ 0.55) ∧ consensus_ok ∧ ¬teacher_flags_malicious
  quarantined = state.trust < quarantine_floor

Implementation notes: see `backup_model/v1/safety_module.py`.

Design rationale and properties
- Slow trust accumulation (small trust_gain) favors stable sources and resists flash poisoning attempts.
- Teacher flag strongly reduces acceptance (teacher_flags_malicious subtracts 0.7), forcing quarantine or rejection.

3. Teacher ⇄ Student Protocol (Alignment, Rollback, and Promotion)
------------------------------------------------------------------
The system maintains both a producible student model θ_s and a teacher snapshot θ_T. The teacher acts as high-assurance oracle for fallback and for identifying drift.

Protocol steps on request r:
1. Run pre-gate; if deterministic attack with confidence ≥ τ_pre, immediately block/report.
2. Run student prediction: y_s = student.predict(payload).
3. If teacher snapshot exists, compute y_T = teacher.predict(payload) and set agreement = (y_s == y_T) and probability_gap = |p_s − p_T|.
4. Update a drift estimator: D_{t+1} = α D_t + (1−α) I_disagreement where I_disagreement ∈ [0,1] is a function of (agreement, probability_gap).
5. If D exceeds drift_trigger, enable teacher_forced mode (future queries are resolved by teacher when available) and consider rollback.

Acceptance/promotion of updates (from AsyncLearner):
- The AsyncLearner performs partial_fit updates and writes checkpoints. Promotion to production teacher snapshot requires passing offline evaluation gates:

  Let θ' be candidate parameters after update. Compute Eval(θ', V) on validation set V. Promote θ' iff Eval(θ', V) ≥ Eval(θ, V) − ε and drift(θ') ≤ δ.

Rollback policy: when post-deployment metrics fall below thresholds (e.g., drop in F1 or increase in false negatives), revert to last safe checkpoint and increment rollback_count.

Implementation notes: `robust_inference_engine.py` implements drift scoring and `rollback_to_teacher()`.

4. Asynchronous Learner & Anchored Replay
-----------------------------------------
The AsyncLearner ingests accepted samples into an in-memory queue with capacity Q_max and a quarantine_lane of size Q_quarantine.

Batching and anchoring
- For each minibatch B of size b drawn from the training queue, compute anchor_count = ⌊b * replay_ratio⌋ and sample anchor_count examples from replay_samples (gold or anchored dataset) to append to the minibatch. This stabilizes updates by mixing historical trusted data with recent feedback.

Partial-fit workflow (pseudocode):

  while not stop_event:
      batch = drain_queue(batch_size)
      anchor_batch = sample(replay_samples, anchor_count)
      payloads, labels = batch.payloads + anchor_batch.payloads
      updated = engine.partial_fit_batch(payloads, labels)
      if updated: dump_checkpoint()

Deadlock prevention and concurrency model
- Worker uses Python multiprocessing with `spawn` context and non-blocking queue operations (timeout on get, get_nowait for draining). This pattern prevents blocking the parent process and avoids classic queue-based deadlocks: worker loops poll with timeouts and the parent can set stop_event.

Implementation notes: see `backup_model/v1/async_learner.py`.

5. Gold Dataset Construction, Centralized Aggregation and Anti-Poison Protocols
-------------------------------------------------------------------------------
Goal: maintain a central, versioned, high-quality "gold" dataset G used for anchoring and retraining while preventing poisoning.

Architecture:
- Each runtime node writes append-only JSONL feedback to local shards (file-db channels). An aggregator job periodically reads all shards, applies sanitization, deduplication, and attack labeling, producing a centralized candidate dataset D_c.
- The candidate dataset D_c undergoes automated vetting: automated label consistency checks, statistical tests for distributional drift, sanity filters (PII removal), and adversarial example screenings. A human-in-the-loop review may be required when automated gates flag anomalies.
- Only upon passing vetting does D_c become promoted to the gold dataset G_k (versioned). Replay samples for AsyncLearner are sampled from the current gold dataset G_k.

Poisoning defenses
- Source-trust gating: SafetyModule prevents low-trust sources from contributing directly to training.
- Anchor mixing: replay_ratio ensures each minibatch includes trusted examples from G_k to reduce catastrophic forgetting and dilution of gold data.
- Statistical audits: run tests (e.g., class-balance checks, label consistency, within-feature-range checks) to detect sudden anomalies in D_c.
- Human review for anomalous batches: quarantine lane and operator review process.

Formal vetting gate (example):

  if (consistency_score(D_c) ≥ τ_consistency) and (drift(D_c, G_{k}) ≤ τ_drift) and (no_high_weight_outliers(D_c)):
      promote D_c → G_{k+1}
  else:
      quarantine D_c and notify operators

6. Distributed Deployment: Multi-Region Proxies, Load Balancing & Rate Limiting
-----------------------------------------------------------------------------
Design objectives: maintain low-latency inference for geographically-distributed origins while preventing overload, ensuring eventual consistency of feedback aggregates, and providing localized defense layers.

Edge-side components (per-region / per-proxy):
- Pre-gate filter (fast regex/heuristics) to block obvious attacks locally.
- Local rate limiter (token-bucket or leaky-bucket) per-client/IP to protect origin.
- Local circuit-breaker to degrade to a safe fallback when backend latency spikes.

Global control plane:
- Routing: DNS-based geo-routing or global load balancer routes clients to nearest region.
- Consistent hashing / sticky routing: for stateful session affinity where necessary.

Data synchronization model:
- Writes (feedback) are first appended locally. An asynchronous replicator ships local shards to an aggregator (push or pull) with sequence numbers and checksums. The aggregator composes a globally ordered stream for offline vetting. This eventual-consistency model reduces hot-path coordination while providing a single authoritative dataset for training.

Rate limiting and high-traffic handling
- Use hierarchical token-bucket: local limit L_local and global per-backend limit L_global. If local load > L_local, apply backpressure locally (reject or delay); if global capacity is constrained, edge nodes apply graded shedding.

Flow control pseudocode (edge):

  if client_tokens.consume(1):
      forward request to backend
  else:
      return 429 or apply graceful degradation

Backpressure & circuit-breaker
- If backend average latency > threshold or error rate > threshold, trip circuit: edge enters degraded mode where pre-gate-only decisions and cached model responses are used.

7. Deadlock & Liveness Guarantees
----------------------------------
Key patterns used to ensure liveness:

- Non-blocking I/O and bounded queues: training queue uses maxsize and put_nowait to avoid blocking the caller; workers poll with timeouts.
- Spawned worker process for training decouples CPU-bound training from the main runtime event loop, preventing worker stalls from freezing the hot path.
- Timeouts at transport layer (ZeroMQ + configured timeouts) force fallbacks to HTTP transport on unresponsive endpoints.

These features together yield a system that avoids global blocking on single-node faults and provides predictable degradation modes.

8. Evaluation Metrics and Reproducible Benchmarks
-------------------------------------------------
Recommended metrics to continuously monitor:
- Detection metrics: precision, recall, F1 on periodic labeled samples.
- Runtime metrics: p50/p95/p99 latency, throughput (rps), queue depth, teacher fallbacks per minute.
- Safety metrics: number of quarantined sources, trust score distribution, accepted vs rejected feedback ratio.

Reproducible benchmarking harness
- Use `loadtest/seed_traffic.py` and `loadtest/locustfile.py` to generate representative traffic. Capture metrics for each model checkpoint and compare with baseline.

9. Formal pseudocode summary
----------------------------

Teacher-Student decision (per-request):

```
pre_gate_attack, pre_gate_conf = labeler.detect_attack_type(payload, return_confidence=True)
if pre_gate_attack != 'benign' and pre_gate_conf >= τ_pre:
    return block(pre_gate_attack)

compare = inference.predict_with_teacher(payload)
student = compare.student
teacher = compare.teacher
agreement = compare.agreement
prob_gap = compare.probability_gap

update_drift(agreement, prob_gap)

if teacher_forced or (teacher exists and (not agreement or student.confidence < confidence_threshold)):
    use_teacher
else:
    use_student
```

Async learner (worker loop skeleton):

```
while not stop_event:
    batch = drain_queue(batch_size)
    if replay_ratio > 0:
        anchors = sample(replay_samples, floor(len(batch)*replay_ratio))
        batch.extend(anchors)
    updated = engine.partial_fit_batch(batch.payloads, batch.labels)
    if updated: dump_checkpoint()
```

10. Operational Recommendations
-------------------------------
- Set conservative defaults for `TRUST_MIN_SCORE`, `DRIFT_TRIGGER`, and `PRE_GATE_THRESHOLD` for early deployments.
- Use small `LEARNER_BATCH_SIZE` and non-zero `REPLAY_RATIO` during canary periods.
- Enable Prometheus metrics and implement alerting for drift and queue depth anomalies.
- Maintain a human-in-the-loop workflow for promoting gold datasets and for adjudicating quarantined batches.

11. Future Formalisms and Proofs
--------------------------------
The current engineering choices are amenable to stronger formal guarantees; possible future directions:
- Statistical bounds on poisoning resistance given trust update dynamics (Markov model of source trust evolution).
- Convergence proofs for partial-fit updates under anchored replay (stability via reservoir sampling analysis).
- Formal latency-availability trade-off models for multi-region deployments (queuing theory with shedding policies).

References & Code pointers
- Safety & trust policy: `backup_model/v1/safety_module.py`
- Async learner: `backup_model/v1/async_learner.py`
- Inference engine and teacher checks: `backup_model/v1/inference.py`
- Runtime orchestration and drift logic: `backup_model/v1/robust_inference_engine.py`
- Dockerized deployment hints: `DOCKER_RUNBOOK.md`, `docker-compose.swarm.yml`, `k8s/configmap.yaml`

Appendix: notation glossary
- See System Model section for primary symbols and definitions.

Acknowledgements
- This formalization was produced from the Flux Shield codebase and aims to document implemented protocols for reviewers, operators, and contributors.
