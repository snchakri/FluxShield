import json
import os
import time
import uuid
import atexit
import multiprocessing
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

from attack_labeler import AttackLabeler
from config import LOGS_DIR, owasp_config
from ipc_server import run_ipc_server
from robust_inference_engine import RobustInferenceEngine

# Flask application initialization
app = Flask(__name__)

# Model version for response metadata
MODEL_VERSION = os.environ.get("MODEL_VERSION", "v1.0.0")
# Audit log file path
AUDIT_LOG_PATH = Path(os.environ.get("AI_AUDIT_LOG_PATH", str(LOGS_DIR / "security_audit.jsonl")))
# Maximum allowed payload size (in bytes) for incoming requests
MAX_PAYLOAD_BYTES = int(os.environ.get("MAX_PAYLOAD_BYTES", "16384"))
# Ensure the audit log directory exists
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


class ClassifierRuntime:
    """
    Manages the classification engine, model loading, feedback, audit logging,
    and fallback to heuristic mode if the learned model cannot be used.
    """

    def __init__(self) -> None:
        # Initialize robust inference engine and attack labeler (heuristics)
        self.engine = RobustInferenceEngine()
        self.labeler = AttackLabeler()
        # Default to heuristic mode (fallback)
        self.mode = "heuristic"
        self.model_loaded = False
        self.ipc_process = None  # IPC process handle for ZeroMQ child

    def load(self) -> None:
        """
        Load the WAF model and feature extraction.
        If model can't be loaded, system falls back to heuristic/regex pattern matching.
        Starts ZeroMQ IPC server in a subprocess if enabled.
        """
        try:
            self.engine.load()
            self.mode = "robust"
            self.model_loaded = True

            enable_ipc = os.environ.get("AI_WAF_ENABLE_ZMQ", "true").lower() == "true"
            if enable_ipc:
                # Start child process to handle IPC (for local/legacy integrations)
                self.ipc_process = multiprocessing.Process(target=run_ipc_server, daemon=True)
                self.ipc_process.start()

            write_audit_event(
                event_type="model_loaded",
                status="success",
                details={"mode": self.mode, "model_path": self.engine.engine.model_path},
            )
        except Exception as error:
            # Fallback to heuristics (pattern/regex-based if model loading fails)
            self.mode = "heuristic"
            self.model_loaded = False
            write_audit_event(
                event_type="model_loaded",
                status="fallback",
                details={"mode": self.mode, "error": str(error)},
            )

    def classify(self, payload: str):
        """
        Run classification on an input payload using the ML model if available,
        otherwise falls back to heuristic rules.
        Returns a dict result describing attack type, malicious status, confidence.
        """
        start = time.perf_counter()

        if self.model_loaded:
            # Use AI model
            result = self.engine.classify(payload)
        else:
            # Use regex/heuristic if model is not loaded (safe fallback)
            attack_type, confidence = self.labeler.detect_attack_type(payload, return_confidence=True)
            result = {
                "attack_type": attack_type,
                "is_malicious": attack_type != "benign",
                "confidence": round(float(confidence), 6),
                "source": "heuristic",
            }

        # Compute and include inference latency
        latency_ms = (time.perf_counter() - start) * 1000
        result["latency_ms"] = round(latency_ms, 4)
        return result

    def submit_feedback(
        self,
        payload: str,
        attack_type: str,
        source_id: str,
        confidence: float,
        consensus_ok: bool,
    ) -> dict:
        """
        Submit a feedback payload for online model learning. 
        If no ML model is loaded, queues are not used.
        """
        if not self.model_loaded:
            return {
                "accepted": False,
                "queued": False,
                "quarantined": False,
                "reason": "model_not_loaded",
                "trust_score": 0.0,
            }

        # Map attack type string to numeric label (uses heuristics for fallback types)
        label = owasp_config.ATTACK_TYPES.get(str(attack_type).lower(), owasp_config.ATTACK_TYPES["malicious"])
        return self.engine.submit_feedback(
            payload=payload,
            label=label,
            source_id=source_id,
            confidence=confidence,
            consensus_ok=consensus_ok,
        )

    def stats(self) -> dict:
        """
        Gather and return runtime/model statistics.
        """
        if not self.model_loaded:
            return {
                "mode": self.mode,
                "model_loaded": self.model_loaded,
            }

        # Add engine-level stats when model is loaded
        return {
            "mode": self.mode,
            "model_loaded": self.model_loaded,
            **self.engine.get_stats(),
        }

    def shutdown(self) -> None:
        """
        Shutdown the model, engine, and clean up (e.g., terminate IPC process).
        Handles atexit cleanup.
        """
        try:
            self.engine.stop()
        except Exception:
            pass
        try:
            if self.ipc_process is not None and self.ipc_process.is_alive():
                self.ipc_process.terminate()
                self.ipc_process.join(timeout=1.5)
        except Exception:
            pass


# Global singleton instance
runtime = ClassifierRuntime()
atexit.register(runtime.shutdown)


def write_audit_event(event_type: str, status: str, correlation_id: str | None = None, details: dict | None = None) -> None:
    """
    Append an audit event as JSONL to the audit log file.
    Events capture major API, model, and feedback events for security/traceability.
    """
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "status": status,
        "correlation_id": correlation_id,
        "model_version": MODEL_VERSION,
        "details": details or {},
    }
    try:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        # Audit logging should not block or crash main API
        pass


# ---- FLASK HTTP Endpoints ---- #

@app.get("/health")
def health_check():
    """
    Basic readiness/liveness check.
    Returns overall service health, loaded model status, version, etc.
    """
    return jsonify(
        {
            "status": "ok",
            "mode": runtime.mode,
            "model_loaded": runtime.model_loaded,
            "model_version": MODEL_VERSION,
        }
    )


@app.post("/classify")
def classify_payload():
    """
    Main API endpoint for classifying a single HTTP/web payload.
    Accepts: {payload: <str>, correlationId: <optional str>}
    Returns: classification including attack_type, malicious/benign, confidence, latency, etc.
    """
    request_body = request.get_json(silent=True) or {}
    payload = request_body.get("payload", "")
    correlation_id = request_body.get("correlationId") or str(uuid.uuid4())

    # Validate input: must be non-empty string
    if not isinstance(payload, str) or not payload:
        write_audit_event(
            event_type="inference_rejected",
            status="error",
            correlation_id=correlation_id,
            details={"reason": "payload must be non-empty string"},
        )
        return jsonify({"error": "payload must be a non-empty string", "correlationId": correlation_id}), 400

    # Enforce maximum allowed content size
    if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        write_audit_event(
            event_type="inference_rejected",
            status="error",
            correlation_id=correlation_id,
            details={"reason": "payload too large", "max_payload_bytes": MAX_PAYLOAD_BYTES},
        )
        return jsonify({"error": "payload exceeds maximum allowed size", "correlationId": correlation_id}), 413

    write_audit_event(
        event_type="inference_requested",
        status="started",
        correlation_id=correlation_id,
        details={"payload_size": len(payload)},
    )

    try:
        # Run classification (AI or fallback heuristics)
        classification = runtime.classify(payload)
        write_audit_event(
            event_type="inference_completed",
            status="success",
            correlation_id=correlation_id,
            details=classification,
        )
        return jsonify(
            {
                "correlationId": correlation_id,
                "modelVersion": MODEL_VERSION,
                **classification,
            }
        )
    except Exception as error:
        write_audit_event(
            event_type="inference_failed",
            status="error",
            correlation_id=correlation_id,
            details={"error": str(error)},
        )
        return jsonify({"error": "inference failed", "correlationId": correlation_id}), 500


@app.post("/feedback")
def submit_feedback():
    """
    Endpoint for submitting feedback to retrain the model (online learning or human review).
    Accepts: payload, attackType, sourceId, confidence, consensusOk.
    Returns: feedback result including queue/quarantine/accept/reject state.
    """
    request_body = request.get_json(silent=True) or {}
    payload = request_body.get("payload", "")
    attack_type = request_body.get("attackType", "malicious")
    source_id = request_body.get("sourceId", "anonymous")
    confidence = float(request_body.get("confidence", 0.0) or 0.0)
    consensus_ok = bool(request_body.get("consensusOk", True))
    correlation_id = request_body.get("correlationId") or str(uuid.uuid4())

    # Validate input
    if not isinstance(payload, str) or not payload:
        return jsonify({"error": "payload must be a non-empty string", "correlationId": correlation_id}), 400

    if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return jsonify({"error": "payload exceeds maximum allowed size", "correlationId": correlation_id}), 413

    try:
        outcome = runtime.submit_feedback(
            payload=payload,
            attack_type=str(attack_type),
            source_id=str(source_id),
            confidence=confidence,
            consensus_ok=consensus_ok,
        )
        write_audit_event(
            event_type="feedback_received",
            status="success",
            correlation_id=correlation_id,
            details={
                "source_id": source_id,
                "attack_type": attack_type,
                "accepted": outcome.get("accepted"),
                "queued": outcome.get("queued"),
                "reason": outcome.get("reason"),
            },
        )
        return jsonify({"correlationId": correlation_id, **outcome})
    except Exception as error:
        write_audit_event(
            event_type="feedback_received",
            status="error",
            correlation_id=correlation_id,
            details={"error": str(error)},
        )
        return jsonify({"error": "feedback processing failed", "correlationId": correlation_id}), 500


@app.get("/stats")
def stats_payload():
    """
    Returns current engine statistics including mode, loaded model, and detailed engine stats if available.
    """
    try:
        return jsonify(runtime.stats())
    except Exception as error:
        return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    # Entrypoint: load the WAF model and start the server (default port: 8000)
    runtime.load()
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
