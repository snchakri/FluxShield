# Twilight WAF AI — Diagram Suite

Professional palette reference:
- Deep Navy `#0B1F2A` (frames/background accents)
- Steel Gray `#2F3C48` (infrastructure layers)
- Teal Accent `#00A8B5` (data/control flows)
- Amber `#F5A623` (latency/alerts)
- Soft Neutral `#E5E9EC` / White `#FDFDFD` (text panels)

All diagrams below use quoted labels and `<br/>` line breaks so they render reliably in GitHub Markdown.

---

## 1. System Architecture (Services & Flows)

```mermaid
flowchart LR
  classDef clients fill:#0B1F2A,stroke:#00A8B5,color:#FDFDFD,stroke-width:2;
  classDef service fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef data fill:#E5E9EC,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;
  classDef storage fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;
  classDef control fill:#00A8B5,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  subgraph ClientLayer[Client & Ops Layer]
    FE["SecOps Analyst<br/>React Dashboard"]
    LT["Locust / Seed Traffic<br/>(load & chaos tests)"]
  end

  subgraph AppLayer[Livepage Application Layer]
    UI["Frontend (Vite + Nginx)<br/>Port 8081"]
    BE["Backend API<br/>(Node/Express)<br/>Port 5000"]
  end

  subgraph AILayer[AI Defense Layer]
    PG["Pre-Gate Heuristics<br/>(regex + heuristics)<br/>&lt;=3ms"]
    ZQ["ZeroMQ Bridge<br/>15ms timeout"]
    AI["AI-WAF Runtime<br/>(Python AutoML)<br/>Port 8000"]
    TE["Teacher/Student<br/>Arbitration"]
    AL["Async Learner<br/>(batch 8, replay 1.0)"]
  end

  subgraph DataLayer[Data & Ops Layer]
    FD["file-db Service<br/>(JSONL channels)<br/>Port 7000"]
    LG["Security & Traffic Logs<br/>security_audit.jsonl<br/>traffic_records.jsonl"]
    DS["Datasets & Checkpoints<br/>CSIC2010, models/, cache/"]
    KP["K8s / Compose<br/>scaling & health metrics"]
  end

  FE -->|HTTPS<br/>Live metrics| UI
  LT -->|Encrypted test traffic| BE
  UI -->|REST / WebSocket| BE
  BE -->|Decrypt + validate| PG
  PG -->|pass| ZQ
  BE --fallback--> AI
  ZQ -->|msgpack req| AI
  AI --> TE
  TE -->|allow/block decision<br/>latency 5-10ms avg| BE
  TE -->|feedback events| FD
  TE --> AL
  AL -->|student updates<br/>drift &lt;=0.12| AI
  AI -->|audit logs| FD
  FD --> LG
  BE -->|audit API| LG
  AI -->|checkpoints| DS
  KP -->|orchestrates| UI
  KP --> BE
  KP --> AI
  KP --> FD

  class FE,LT clients;
  class UI,BE service;
  class PG,ZQ,AI,TE,AL service;
  class FD storage;
  class LG,DS data;
  class KP control;
```

### Architecture Metrics & Guarantees
- **Latency budget:** pre-gate ≤3ms, ML path ≤10ms avg, worst-case ≤40ms.
- **Throughput target:** >200 req/s per AI runtime; horizontally scale via Compose/K8s replicas.
- **Accuracy gate:** ≥85% global on holdout; false negatives <5%.
- **Reliability levers:** ZeroMQ retry → HTTP fallback, async learner isolated from hot path, file-db append-only with health probes.

---

## 2. UML Diagrams

### 2.1 Use-Case Overview
```mermaid
flowchart TB
  classDef actor fill:#0B1F2A,stroke:#00A8B5,color:#FDFDFD,stroke-width:2;
  classDef usecase fill:#E5E9EC,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;

  subgraph Actors
    User["End User"]
    SecOps["SecOps Analyst"]
    DevOps["DevOps Engineer"]
  end

  subgraph UseCases
    UC1["Submit HTTP Request"]
    UC2["Inspect & Classify Traffic"]
    UC3["Review Live Metrics"]
    UC4["Provide Feedback / Tuning"]
    UC5["Scale & Deploy Services"]
  end

  User --> UC1
  UC1 --> UC2
  SecOps --> UC3
  SecOps --> UC4
  DevOps --> UC5
  UC4 --> UC2
  UC5 --> UC2
  UC5 --> UC3
```

### 2.2 Sequence Diagram — Request Inspection & Feedback Loop
```mermaid
sequenceDiagram
  autonumber
  participant Client
  participant Backend as Backend API
  participant PreGate as Pre-Gate Filter
  participant ZMQ as ZeroMQ Bridge
  participant AIRuntime as AI-WAF Runtime
  participant Learner as Async Learner
  participant FileDB as file-db

  Client->>Backend: HTTPS request (encrypted payload)
  Backend->>Backend: Decrypt + basic validation (<=2ms)
  Backend->>PreGate: Regex/heuristic scan
  alt Known attack
    PreGate-->>Backend: Blocked (<=3ms total)
    Backend->>FileDB: Append security audit
  else Suspicious/Unknown
    PreGate->>ZMQ: forward payload (msgpack)
    ZMQ->>AIRuntime: classify (<=10ms)
    AIRuntime-->>Backend: malicious/benign + confidence
    Backend->>FileDB: persist verdict + metrics
    Backend-->>Client: allow/block response
    AIRuntime->>Learner: enqueue feedback (async)
    Learner->>AIRuntime: batch update / checkpoint (off-path)
  end
```

### 2.3 Component/Class Diagram (High-Level)
```mermaid
classDiagram
  class BackendAPI {
    +decryptRequest()
    +invokeClassifier()
    +fallbackHttp()
    +streamMetrics()
  }
  class PreGateFilter {
    +regexScore()
    +heuristicThreshold
  }
  class ZmqBridge {
    +endpoint: tcp://ai-waf:5557
    +timeoutMs: 15
    +send()
  }
  class RobustInferenceEngine {
    +loadModel()
    +predictSingle()
    +teacherForcedMode
    +driftScore
  }
  class AsyncLearner {
    +queueDepth
    +replayRatio
    +partialFit()
  }
  class FileDbClient {
    +append(channel, record)
    +fetch(channel, limit)
  }

  BackendAPI --> PreGateFilter
  BackendAPI --> ZmqBridge
  ZmqBridge --> RobustInferenceEngine
  RobustInferenceEngine --> AsyncLearner
  BackendAPI --> FileDbClient
  RobustInferenceEngine --> FileDbClient
```

---

## 3. ML & MLOps Diagrams

### 3.1 Training & Deployment Lifecycle
```mermaid
flowchart LR
  classDef stage fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef metric fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  DS["Datasets<br/>CSIC2010 + huggingface"]
  FE["Feature Extraction<br/>TF-IDF + stats"]
  ALBL["Attack Labeler<br/>18 OWASP classes"]
  AUTO["AutoML Training<br/>auto-sklearn / AutoKeras"]
  EVAL["Evaluation Suite<br/>F1, ROC, drift"]
  PKG["Model Packaging<br/>.joblib / SavedModel"]
  DEP["Runtime Deploy<br/>AI-WAF container"]
  MON["Monitoring<br/>metrics_v1.json"]

  DS --> ALBL --> FE --> AUTO --> EVAL --> PKG --> DEP --> MON
  MON -->|accuracy ≥85%?| DEP
  EVAL -.->|fail gate| AUTO
  class DS,FE,ALBL,AUTO,EVAL,PKG,DEP,MON stage;
```

### 3.2 Online Learning & Drift Control
```mermaid
stateDiagram-v2
  [*] --> Monitoring
  Monitoring --> Stable : drift < 0.08
  Monitoring --> Watch : 0.08 ≤ drift < 0.12
  Monitoring --> ForcedTeacher : drift ≥ 0.12

  state Stable {
    [*] --> Normal
    Normal --> Normal : enqueue feedback
  }

  state Watch {
    [*] --> Guarded
    Guarded --> Guarded : tighter trust gate
    Guarded --> ForcedTeacher : sustained drift
  }

  state ForcedTeacher {
    [*] --> TeacherOnly
    TeacherOnly --> Rollback : learner instability
    Rollback --> Normal : checkpoint restore
  }
```

---

## 4. DataOps & Dataflow

### 4.1 End-to-End Dataflow
```mermaid
flowchart TB
  classDef ingest fill:#0B1F2A,stroke:#00A8B5,color:#FDFDFD,stroke-width:2;
  classDef process fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef store fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;
  classDef analytics fill:#00A8B5,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  Ingest["Encrypted Payloads<br/>HTTPS/TLS + AES-GCM"]
  Decrypt["App-layer Decrypt"]
  Validate["Schema & sanity checks"]
  Classify["Pre-Gate + AI inference"]
  Decision["Allow/Block + Confidence"]
  Logs["file-db channels<br/>JSONL append-only"]
  Metrics["Live Metrics API<br/>p50/p95 latency, drift"]
  LearnerBuf["Replay Buffer<br/>(queue depth &lt;=5000)"]
  Analytics["BI / SIEM / Dashboard"]

  Ingest --> Decrypt --> Validate --> Classify --> Decision
  Decision --> Logs
  Decision --> Metrics
  Decision --> LearnerBuf --> Classify
  Logs --> Analytics
  Metrics --> Analytics
```

### 4.2 Data Reliability & Governance Controls
- **Encryption:** TLS in transit + AES-256-GCM envelope for payload body.
- **Storage:** Append-only `.jsonl` with host bind mounts; backups via Git-ignored `file-db/data` snapshots.
- **Retention knobs:** rotate by file size/time; export to SIEM for immutable retention.
- **Reliability hooks:** health checks (`/health`, `/records`), idempotent sync batches, jitter + exponential backoff for coordination.
- **Observability metrics:** learner queue depth, drift score, teacher forced flag, replay acceptance, log write latency.

---

## 5. Quality Attribute Annotations
- **Scalability:** horizontal scaling at backend, AI runtime, and file-db tiers; ZeroMQ endpoint pool + Kubernetes HPA for sustained >10k req/s.
- **Reliability:** teacher/learner arbitration, automatic rollback, dual-transport (ZMQ + HTTP) path, append-only logging, trust gate preventing poisoning.
- **Latency:** strict budgets per stage with monitoring hooks; diagrams note ≤3ms pre-gate, ≤10ms inference, ≤1ms enqueue.
- **Performance:** async learning off hot path, replay buffer to avoid catastrophic forgetting, Locust-based load tests to validate KPIs.

> Render each Mermaid block to SVG/PNG with a consistent canvas size (minimum width 1200px) to preserve spacing and prevent label overlap.

---

## 6. Security & Trust Controls

### 6.1 Threat Intake & Trust Pipeline
```mermaid
flowchart LR
  classDef gate fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef alert fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;
  classDef neutral fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;

  Payload["Incoming Payload<br/>metadata + body"]
  Scrub["PII Scrubber<br/>regex masks"]
  Trust["Trust Ledger<br/>score ∈ [0,1]"]
  Gate["Safety Gate<br/>min score 0.35"]
  Quarantine["Quarantine Lane<br/>review queue"]
  Approved["Approved Feedback<br/>Learner queue"]
  Drop["Drop With Audit"]

  Payload --> Scrub --> Trust --> Gate
  Gate -->|score ≥ threshold| Approved
  Gate -->|score < threshold| Quarantine
  Quarantine -->|manual/auto review| Approved
  Quarantine -->|malicious evidence| Drop
  Drop -->|append| security_audit.jsonl
  class Payload,Scrub,Trust,Gate,Quarantine,Approved,Drop gate;
```

### 6.2 Trust Score Evolution (Example Source)
```mermaid
flowchart LR
  classDef event fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef quarantine fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  S0["00:00<br/>Score 0.20<br/>(new source)"]
  S1["00:05<br/>+0.01 benign agreement"]
  S2["00:12<br/>+0.01 benign agreement"]
  S3["00:18<br/>-1.00 malicious disagreement<br/>(teacher)"]
  S4["00:18<br/>quarantined (score floored)"]
  S5["00:30<br/>manual review confirms malicious"]
  S6["00:30<br/>remains quarantined<br/>future feedback ignored"]

  S0 --> S1 --> S2 --> S3 --> S4 --> S5 --> S6
  class S0,S1,S2,S3,S5,S6 event;
  class S4 quarantine;
```

---

## 7. Sync & Deployment Operations

### 7.1 Sync Coordinator Sequence
```mermaid
sequenceDiagram
  autonumber
  participant NodeA as Runtime Node A
  participant Sync as Sync Coordinator
  participant NodeB as Runtime Node B

  NodeA->>Sync: POST /sync/batch (idempotency-key, checksum)
  Sync-->>NodeA: 202 Accepted (jitter + backoff timers)
  Sync->>NodeA: validate checksum + drift stats
  Sync-->>NodeA: OK, mark batch available
  NodeB->>Sync: GET /sync/next?last=token
  Sync-->>NodeB: batch payload (student checkpoint, metrics)
  NodeB->>NodeB: apply checkpoint, update learner queue
  NodeB->>Sync: ACK idempotency-key within TTL
  Sync-->>NodeB: recorded and schedule next interval
```

### 7.2 Deployment Footprint
```mermaid
flowchart TB
  classDef layer fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef node fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;

  subgraph Cloud[K8s / Compose Cluster]
    LB["Ingress / Load Balancer"]
    subgraph App
      FEPod["Frontend Pod"]
      BEPod["Backend Pod"]
    end
    subgraph AI
      AIPod1["AI-WAF Pod 1"]
      AIPod2["AI-WAF Pod 2"]
    end
    subgraph Data
      FileDbPod["file-db Pod"]
      Volume["Persistent Volume<br/>(JSONL, checkpoints)"]
    end
  end

  LB --> FEPod --> BEPod
  BEPod --> AIPod1
  BEPod --> AIPod2
  AIPod1 --> FileDbPod
  AIPod2 --> FileDbPod
  FileDbPod --> Volume
```

---

## 8. Encryption & Transport Detail

### 8.1 Envelope Encryption Lifecycle
```mermaid
flowchart LR
  classDef enc fill:#2F3C48,stroke:#00A8B5,color:#FDFDFD,stroke-width:1.5;
  classDef key fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  Client["Client Payload"]
  Cache["Data Key Cache<br/>TTL=120s, max uses=1000"]
  DataKey["Symmetric Data Key"]
  Cipher["AES-GCM Encrypt"]
  Envelope["Envelope Payload<br/>{nonce, ciphertext, aad, key_b64}"]
  Backend["Backend Decrypt"]

  Client --> Cache
  Cache -->|hit| DataKey
  Cache -->|miss| DataKey
  DataKey --> Cipher
  Cipher --> Envelope
  Envelope --> Backend
  Backend -->|decrypt data key| PayloadOut["Plaintext Payload"]
```

### 8.2 Transport Fallback Logic
```mermaid
stateDiagram-v2
  [*] --> ZMQPrimary
  ZMQPrimary --> ZMQPrimary : response < timeout (15ms)
  ZMQPrimary --> HTTPFallback : timeout or socket error
  HTTPFallback --> HTTPFallback : retry attempts ≤ 3
  HTTPFallback --> Failure : retries exhausted
  HTTPFallback --> ZMQPrimary : success; resume primary path
```

---

## 9. Load Testing & Observability Flows

### 9.1 Locust Test Pipeline
```mermaid
flowchart LR
  classDef test fill:#0B1F2A,stroke:#00A8B5,color:#FDFDFD,stroke-width:2;
  classDef stage fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;

  Runner["Locust Runner"] --> Scenarios["Benign/Malicious Scenarios"]
  Scenarios --> Encryptor["AES-GCM Wrapper"]
  Encryptor --> Sender["HTTP POST /api/traffic/ingest"]
  Sender --> Backend["Backend"]
  Backend --> MetricsAPI["/api/traffic/metrics"]
  Backend --> LiveStream["/api/traffic/live"]
  MetricsAPI --> Dashboard["Live Dashboard"]
  LiveStream --> Dashboard
```

### 9.2 Metrics & Alert Streams
```mermaid
flowchart TB
  classDef metric fill:#00A8B5,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;
  classDef sink fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;

  subgraph Runtime Metrics
    Lat["P50/P95 Latency"]
    Drift["Drift Score"]
    Queue["Learner Queue Depth"]
    Teacher["Teacher Forced Flag"]
    Storage["File-DB Write Latency"]
  end

  Lat --> Prom["Prometheus / Metrics API"]
  Drift --> Prom
  Queue --> Prom
  Teacher --> Prom
  Storage --> Prom
  Prom --> Alerts["Alertmanager / Pager"]
  Prom --> Dashboards["Grafana / Custom UI"]
```

---

All additional diagrams follow the same palette and grid layout rules. Ensure exports maintain multi-line labels to prevent overlap when embedding in documentation or slide decks.

---

## 10. Incident Response & Rollback Flow

```mermaid
flowchart LR
  classDef alert fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;
  classDef action fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef decision fill:#00A8B5,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  Alert["Drift / Accuracy Alert"]
  Inspect["SecOps Inspect Metrics"]
  Confirm["Confirm Regression"]
  ForceTeacher["Enable Teacher-Only Mode"]
  Rollback["Rollback Student Checkpoint"]
  Validate["Re-run validation set"]
  Resume["Resume Student Learning"]

  Alert --> Inspect --> Confirm
  Confirm --> ForceTeacher --> Rollback --> Validate
  Validate -->|pass| Resume
  Validate -->|fail| ForceTeacher
```

---

## 11. User Journey (SecOps Dashboard)

```mermaid
journey
  title SecOps Analyst Daily Loop
  section Morning Checks
    Review live metrics: 4
    Inspect overnight alerts: 3
  section Active Monitoring
    Watch drift & queue widgets: 5
    Drill into traffic table filters: 4
    Trigger manual quarantine review: 3
  section Feedback & Tuning
    Submit feedback annotations: 4
    Validate async learner updates: 3
  section Reporting
    Export security audit slice: 4
    Share KPIs with exec dashboard: 3
```

---

## 12. Automated MLOps Pipeline (CI/CD)

```mermaid
flowchart LR
  classDef stage fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;
  classDef gate fill:#F5A623,stroke:#0B1F2A,color:#0B1F2A,stroke-width:1.5;

  Commit["Git Commit<br/>(model/config change)"]
  CI["CI Job<br/>pytest + lint"]
  Train["Automated Training Job<br/>GPU runner"]
  Bench["Benchmark Stage<br/>latency + accuracy gates"]
  Package["Container Build<br/>model + service"]
  Canary["Canary Deploy<br/>1 replica"]
  Observe["Observe metrics<br/>24h"]
  Rollout["Full rollout"]

  Commit --> CI --> Train --> Bench --> Package --> Canary --> Observe --> Rollout
  Bench -->|gate fail| Train
  Observe -->|metrics drop| Canary
```

---

## 13. Storage Lifecycle & Governance

```mermaid
flowchart TB
  classDef store fill:#FDFDFD,stroke:#2F3C48,color:#0B1F2A,stroke-width:1.5;
  classDef process fill:#2F3C48,stroke:#E5E9EC,color:#FDFDFD,stroke-width:1.5;

  Ingest["file-db<br/>security_audit.jsonl"]
  Rotate["Rotation Policy<br/>size/time triggers"]
  Archive["Archive to Object Storage"]
  Catalog["Metadata Catalog<br/>dataset lineage"]
  SIEM["SIEM / Data Lake"]
  Purge["Purge expired data"]

  Ingest --> Rotate --> Archive --> Catalog --> SIEM
  Archive --> Purge
```

---

## 14. Capability Roadmap (High-Level)

```mermaid
gantt
  title Capability Phases
  dateFormat  YYYY-MM
  section Foundation
    Open-source WAF Core        :done,    des1, 2025-01, 2025-06
    Async Learning & Trust Gate :done,    des2, 2025-04, 2025-09
  section Growth
    Enterprise Control Plane    :active,  des3, 2026-01, 2026-06
    API Discovery & Bot Mgmt    :         des4, 2026-04, 2026-12
  section Edge Expansion
    Managed Cloud Service       :         des5, 2027-01, 2027-09
    Edge Partnerships           :         des6, 2027-04, 2027-12
```
