# Flux Shield — Open Source AI-Powered Web Application Firewall

Flux Shield is an open-source, production-oriented AI-assisted web application firewall and traffic defense platform. It combines deterministic pre-gate heuristics, a high-performance ML inference runtime, and an asynchronous learning pipeline to deliver a defendable, auditable, and deployable WAF that integrates with modern cloud and container platforms.

Flux Shield is designed for security engineers, SecOps teams, and platform operators who need strong, low-latency protections for web services while preserving a safe, reviewable feedback loop for model-driven decisions.

---

**Key principles**
- Defendable: human-reviewable gates, append-only audit trails, and conservative trust gates to avoid silent model failures.
- Low-latency: pre-gate heuristics + fast model runtimes keep hot-path latency within strict budgets.
- Observability-first: rich metrics, JSONL audit logs, and integration hooks for SIEM and Prometheus.
- Open and extensible: clear dataflows, modular runtime components, and permissive contribution paths for researchers and operators.

---

**Table of Contents**
- **Project Overview**
- **Capabilities & Features**
- **Architecture & Components**
- **Install & Quick Start**
- **Operational Guides**
- **Development & Contributing**
- **Security, Privacy & Trust**
- **Roadmap & Governance**
- **License & Attribution**
- **Contact & Community**

---

## Unique Value Propistion

Flux Shield is designed and positioned as the state-of-the-art AI-driven web application firewall architecture available in the open-source ecosystem. Its combination of a defendable teacher/student learning model, append-only auditable dataflows, constrained AutoML practices, and production-grade operational controls is intended to deliver a practical and verifiable security posture that is difficult to match in other open-source WAF projects.

We encourage independent validation: the project supplies reproducible checkpoints, evaluation metrics (F1, ROC, drift), and a benchmark harness so that operators and researchers can measure latency, throughput, and detection performance on representative workloads. This public, testable transparency is central to Flux Shield's claim of leadership — not as marketing hyperbole, but as an empirically verifiable design objective.

---

**Project Overview**

Flux Shield provides a multi-path traffic inspection pipeline: lightweight deterministic pre-gate checks, a primary ML inference path (low-latency), and a teacher/student arbitration layer that records human feedback for asynchronous learning. It is intended to be deployed inside a cluster (Docker Compose or Kubernetes), colocated with backends, or run as a standalone runtime for testing.

Flux Shield's goals:
- Block known, rule-based attacks with minimal cost using pre-gate heuristics.
- Classify ambiguous traffic with an ML runtime while maintaining clear audit trails.
- Capture operator feedback and safely update online learners in an off-path manner.

**Capabilities & Features**

- Pre-Gate Heuristics: regex, signature checks, header anomalies — sub-3ms target latency.
- ML Inference Runtime: model loading, vectorized predictSingle(), confidence scoring, and fallback transport options (ZeroMQ primary, HTTP fallback).
- Teacher/Student Arbitration: enforce teacher flags and allow operator overrides to prevent poisoning.
- Async Learner: batch replay, partial fit flows, checkpointing and rollback support.
- Append-only file-db logs: JSONL audit channels for security_audit.jsonl and traffic_records.jsonl suited to offline analysis and SIEM ingestion.
- Observability: Prometheus metrics, drift score, queue depth, p50/p95 latencies, and health checks.
- Load & Chaos Testing Support: Locust scenarios and seeded encrypted traffic flows for realistic validation.

**Architecture & Components**

High-level components (see detailed diagrams in [docs/system_diagrams.md](docs/system_diagrams.md)):

- Backend API (Node/Express): decrypts payloads, performs pre-gate checks, and orchestrates inference/fallbacks.
- Pre-Gate Filter: deterministic rules and heuristics to quickly block obvious attacks.
- ZeroMQ Bridge: low-latency transport to the AI runtime with configurable timeouts and retries.
- AI-WAF Runtime (Python): robust inference engine, teacher/student arbitration, model checkpoints and audit logging.
- Async Learner: processes feedback events from the runtime and performs safe offline updates.
- file-db: append-only JSONL channels for auditability and data exchange.

Design guarantees and metrics:
- Latency budget: pre-gate ≤3ms, ML path ≤10ms average, worst-case ≤40ms.
- Throughput: horizontally scalable AI runtime; aim >200 req/s per runtime instance under typical models.
- Accuracy gate: recommended model validation threshold ≥85% on holdout before promoting to production.

**Install & Quick Start**

Minimum prerequisites:
- Python 3.11+ (for AI runtime components)
- Node.js 16+ (for Backend API and web UI)
- Docker & Docker Compose or a Kubernetes cluster

Quick local run (developer test):

1. Clone the repository and switch to the project root:

```bash
git clone <your-fork-or-upstream-url>
cd twilight_exp
```

2. Create a Python virtual environment and install runtime deps:

```bash
python -m venv .venv
source .venv/bin/activate    # or .venv\\Scripts\\Activate.ps1 on Windows PowerShell
pip install -r backup_model/v1/requirements.txt
```

3. Start the file-db and backend (quick compose example):

```bash
docker-compose up file-db backend
```

4. Start the AI runtime locally (development mode):

```bash
cd backup_model/v1
python api_service.py        # development entrypoint for inference runtime
```

5. Send a test encrypted payload (see `livepage/demo/generate-encrypted-traffic-samples.js` for examples) or run Locust scenarios from `loadtest/`.

**Operational Guides**

Recommended deployment:
- Use container orchestration (Kubernetes) with liveness/readiness probes and HPA for the AI runtime.
- Keep the async learner isolated from the hot path and throttle replay windows to avoid instability.
- Export Prometheus metrics and configure Alertmanager rules for drift thresholds and high queue depths.

Audit & retention:
- Flux Shield writes append-only JSONL to `file-db/data/` (or a mounted volume). Rotate and archive these files into object storage regularly for long-term retention and compliance.

Failover & transport policies:
- Configure ZeroMQ as primary transport; set a short (e.g., 15ms) request timeout and enable HTTP fallback for reliability.

**Development & Contributing**

We welcome contributors. Key suggestions for first contributions:
- Review the architecture in [docs/system_diagrams.md](docs/system_diagrams.md).
- Run unit tests for the component you intend to change. The repo contains component-level requirements and tests under `backup_model/` and `loadtest/`.
- When proposing model changes, include evaluation artifacts (F1, ROC, drift scores) alongside datasets or synthetic test harnesses.

Suggested local workflows:

```bash
# run backend tests
cd backup_model/v1
pytest -q

# run a basic locust profile
cd loadtest
locust -f locustfile.py --headless -u 50 -r 5 --run-time 2m
```

Contribution process:
- Fork the repository, create a feature branch, and open a PR with a clear description and tests where applicable.
- For model or policy changes that affect production behavior, provide a rollback plan and test artifacts.

**Security, Privacy & Trust**

Flux Shield is built around strong auditability and safe learning principles:

- Append-only logs: audit trails are preserved in JSONL, suitable for forensic review.
- Trust ledger & gate: sources and feedback are scored; low-trust sources are quarantined for manual review before being used to retrain models.
- Manual teacher flags: operator-provided teacher signals can override automated decisions and prevent unsafe updates.
- Data privacy: the system supports encryption-in-transit (TLS + AES-GCM envelopes) and recommends limiting personally identifying fields in logs.

When reporting security issues, please follow the standard responsible disclosure process. If you find a critical vulnerability, contact the maintainers privately (see Contact & Community below).

**Roadmap & Governance**

Planned short- and medium-term items:
- Harden the teacher-student arbitration to include automatic rollback when learner instability is detected.
- Provide an official Helm chart and production Compose stacks with sensible defaults for persistence and monitoring.
- Add model packaging and reproducible training pipelines (containerized GPU training + CI gates).

We intend Flux Shield to be community-governed. Major changes that alter runtime behavior or trust policies will require review and explicit approval by maintainers.

**License & Attribution**

Flux Shield is intended to be open-source. If you want us to apply a permissive license (recommended for broad community adoption), consider the Apache-2.0 or MIT license. We can add a LICENSE file on request and help prepare a contributor license agreement if the project needs one.

**Contact & Community**

To discuss Flux Shield, open issues or PRs in this repository. For private or sensitive security reports, send an email to the maintainer contact listed in the repository metadata.

**Appendix: Useful Paths**
- System diagrams and MERMAID flows: [docs/system_diagrams.md](docs/system_diagrams.md)
- AI runtime and training code: [backup_model/](backup_model/)
- Load testing & locust scenarios: [loadtest/locustfile.py](loadtest/locustfile.py)
- File-db (append-only JSONL storage): [file-db/](file-db/)

---

If you'd like, I can also:
- produce a short project tagline and elevator pitch for the repository header
- generate an initial `LICENSE` file (Apache-2.0 or MIT)
- update `sample_readme.md` and additional docs to consistently use the `Flux Shield` name

Tell me which of those follow-ups you'd like me to do next.

---

## Theory & Design (Philosophy, Models, Data & Performance)

This section describes the theoretical foundations and design choices that guide Flux Shield's architecture and operational behavior. It is intended for researchers, platform architects, and SecOps engineers who want to understand the safety model, data topology, AutoML trade-offs, and predicted performance characteristics.

### Design Philosophy

- Separation of concerns: keep hot-path inference minimal and deterministic where possible (pre-gate), while placing learning and model updates off-path to avoid performance regressions.
- Fail-safe by design: decisions with insufficient confidence fall back to conservative actions (manual review, quarantine, or HTTP fallback); teacher signals and audit logs enable human-in-the-loop remediation.
- Observability and verifiability: every decision path produces append-only audit records suitable for retrospective analysis and compliance.
- Minimally-invasive learning: online updates require gated acceptance with drift detection and rollback support to prevent model poisoning.

### Teacher ⇄ Student (Safe Online Learning)

Flux Shield adopts a teacher/student style architecture with explicit trust controls:

- Teacher(s): can be human analysts, strong rule-based classifiers (pre-gate), or an ensemble oracle used during offline training. Teachers produce high-quality labels and may mark samples as authoritative (teacher flag).
- Student(s): lightweight models deployed in the inference path. Students learn from teacher-labeled examples via an asynchronous learner that performs batched incremental updates or periodic re-training.

Core safety mechanisms:
- Trust ledger: each feedback source (human, automated) has a trust score ∈ [0,1]. Only feedback above a configurable trust threshold is used for training without manual review.
- Gated acceptance: model updates require passing validation gates (holdout metrics, drift constraints) before being promoted to production.
- Rollback & checkpointing: every promoted checkpoint is versioned; automatic rollback triggers when post-deployment metrics drop below pre-defined thresholds.

Mathematical sketch (informal):

- Let D_t be the current production dataset snapshot and θ the student model parameters. New batch B from trusted feedback updates θ via a partial-fit or SGD step:

	$$\theta_{t+1} = \theta_t - \eta \nabla L(\theta_t; B)$$


- Acceptance condition: if Eval(\theta_{t+1}, V) ≥ Eval(\theta_t, V) - \epsilon and drift(\theta_{t+1}) ≤ \delta, promote; otherwise keep \theta_t and enqueue for offline analysis.

Where Eval is an evaluation metric (F1, AUC), V is a validation set, \epsilon is a small tolerance, and \delta is a drift score threshold.

### Data Topology: Distributed Ingest, Centralized Training

Practical deployments collect feedback and traffic logs in an append-only, sharded store (file-db). The system distinguishes two roles:

- Distributed hot-path collectors: lightweight writers co-located with runtime nodes that append JSONL records (minimal processing). This keeps per-node I/O cheap and reduces cross-node latency.
- Centralized aggregation & training: periodic jobs (or a control-plane service) aggregate shards into a sanitized training dataset, apply feature extraction and deduplication, and run AutoML/training pipelines.

Benefits:
- Local append-only storage avoids synchronous cross-node coordination on the hot path.
- Central aggregation enables consistent feature computation, versioned datasets, and reproducible runs.

Privacy and governance:
- Store minimal PII, anonymize where possible, and enforce retention/rotation policies on append-only channels. Use metadata and pseudonymization for analyst-attributed feedback.

### AutoML & Model Selection (auto-sklearn as an example)

For tabular or engineered feature sets (TF-IDF for textual traffic features, numeric header/statistics), an AutoML system such as `auto-sklearn` can be used to automatically search model families, preprocessing pipelines, and hyperparameters subject to constraints:

- Cost/latency constraint: restrict candidate models to those with inference latency ≤ L_max (operator-set), measured on representative hardware.
- Resource-aware search: include CPU/GPU availability in the search budget; prefer lightweight ensemble or single-model deployments for low-latency requirements.

Typical AutoML workflow:

1. Prepare versioned features and holdout splits from central dataset.
2. Define optimization objective(s): primary (F1 / recall), secondary (inference latency, model size).
3. Run constrained AutoML search (time budget + latency constraints).
4. Evaluate candidate models on calibration, robustness (via adversarial/synthetic tests), and drift sensitivity.
5. Package selected model (e.g., `.joblib`), produce a reproducible training artifact, and store checkpoint with metadata.

Notes on ensembles: ensembles may improve accuracy but often increase inference latency and memory footprint — balance via latency gates and possible distillation into smaller students.

### Theoretical Latency, Throughput & Performance Estimates

These are engineering estimates to help capacity planning. Actual results depend on model choice, feature pipeline, hardware, and serialization.

Assumptions (example baseline):
- Pre-gate deterministic checks: 0.3–3.0 ms (single-threaded regex/header checks).
- Serialization & deserialization (msgpack/json): 0.2–1.0 ms.
- ZeroMQ network transport (in-cluster): 0.5–10 ms (median depends on node topology and message size).
- Model inference (student) per-request: 1–10 ms for small/optimized models on modern CPU; 0.5–2 ms on optimized vectorized inference or small GPU.

End-to-end median latency (typical low-latency path):

	pre-gate (1 ms) + transport (5 ms) + model inference (3 ms) + serialization (0.5 ms) = ~9.5 ms

Simple throughput estimate (per runtime instance):

	throughput ≈ 1000 / latency_ms  (requests/sec per single worker core)

So with 10 ms latency, approximate throughput ≈ 100 req/s per worker thread. With 4 worker threads and optimized I/O, a single container can typically handle several hundred req/s. Achieving >200 req/s per runtime is realistic with tuned models and concurrency.

Batching trade-offs:
- Batching increases throughput but also increases tail latency and jitter — unacceptable for strict hot-path budgets unless application can tolerate slightly higher latencies.

Scaling strategies:
- Horizontal scaling (replicate AI runtime pods) with load balancing at the ZeroMQ/HTTP bridge.
- Model quantization/distillation for lower inference cost.
- Use of specialized inference runtimes (ONNX, TensorRT) for heavy models when GPU resources are available.

### Evaluation & Monitoring Strategy

- Metrics to track continuously: p50/p95 latency, queue depth, drift score, recall/precision on sampled labeled traffic, teacher overrides per minute, and audit log write latency.
- Gates: require models to pass offline accuracy (≥85% F1 or operator-defined), calibration checks, and drift tolerance before production rollout.
- Canary/promoted rollout: deploy to a small percentage of traffic and compare metrics for 24–72 hours before full promotion.

---
