import time
import os
from dataclasses import asdict, dataclass
from typing import Dict, Optional

from attack_labeler import AttackLabeler
from async_learner import AsyncLearner
from inference import InferenceEngine
from safety_module import SafetyModule


@dataclass
class RuntimeState:
    teacher_forced: bool = False
    drift_score: float = 0.0
    rollback_count: int = 0
    last_rollback_ts: Optional[float] = None


class RobustInferenceEngine:
    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        pre_gate_threshold: Optional[float] = None,
        drift_trigger: Optional[float] = None,
    ) -> None:
        confidence_threshold = float(os.environ.get("CONFIDENCE_THRESHOLD", confidence_threshold or 0.7))
        pre_gate_threshold = float(os.environ.get("PRE_GATE_THRESHOLD", pre_gate_threshold or 0.92))
        drift_trigger = float(os.environ.get("DRIFT_TRIGGER", drift_trigger or 0.35))

        trust_min = float(os.environ.get("TRUST_MIN_SCORE", "0.35"))
        trust_warmup_seconds = int(os.environ.get("TRUST_WARMUP_SECONDS", str(24 * 60 * 60)))
        learner_queue_max = int(os.environ.get("LEARNER_QUEUE_MAX", "5000"))
        learner_batch_size = int(os.environ.get("LEARNER_BATCH_SIZE", "32"))
        learner_replay_ratio = float(os.environ.get("LEARNER_REPLAY_RATIO", "1.0"))

        self.engine = InferenceEngine()
        self.labeler = AttackLabeler()
        self.safety = SafetyModule(
            min_trust_to_learn=trust_min,
            warmup_seconds=trust_warmup_seconds,
        )
        self.learner = AsyncLearner(
            max_queue_size=learner_queue_max,
            batch_size=learner_batch_size,
            replay_ratio=learner_replay_ratio,
        )

        self.confidence_threshold = confidence_threshold
        self.pre_gate_threshold = pre_gate_threshold
        self.drift_trigger = drift_trigger

        self.state = RuntimeState()
        self.total_inferences = 0
        self.teacher_fallbacks = 0

    def load(self, start_learner: bool = True) -> None:
        self.engine.load_model()
        try:
            self.engine.load_teacher_snapshot()
        except Exception:
            self.engine.teacher_model = None
        if start_learner:
            self.learner.start()

    def stop(self) -> None:
        self.learner.stop()

    def _update_drift(self, agreement: bool, probability_gap: float) -> None:
        disagreement = 0.0 if agreement else 1.0
        instant = 0.5 * disagreement + 0.5 * min(probability_gap, 1.0)
        self.state.drift_score = 0.95 * self.state.drift_score + 0.05 * instant

        if self.state.drift_score >= self.drift_trigger:
            self.state.teacher_forced = True

    def rollback_to_teacher(self) -> None:
        self.state.teacher_forced = True
        self.state.rollback_count += 1
        self.state.last_rollback_ts = time.time()

    def classify(self, payload: str, source_id: str = "anonymous") -> Dict[str, object]:
        start = time.perf_counter()
        self.total_inferences += 1

        pre_gate_attack, pre_gate_confidence = self.labeler.detect_attack_type(payload, return_confidence=True)
        if pre_gate_attack != "benign" and pre_gate_confidence >= self.pre_gate_threshold:
            latency_ms = (time.perf_counter() - start) * 1000
            return {
                "attack_type": pre_gate_attack,
                "is_malicious": True,
                "confidence": round(float(pre_gate_confidence), 6),
                "source": "regex_pre_gate",
                "latency_ms": round(latency_ms, 4),
                "teacher_forced": self.state.teacher_forced,
            }

        compare = self.engine.predict_with_teacher(payload)
        student = compare["student"]
        teacher = compare["teacher"]
        agreement = bool(compare["agreement"])
        probability_gap = float(compare["probability_gap"])

        self._update_drift(agreement=agreement, probability_gap=probability_gap)

        use_teacher = False
        reason = "student_confident"
        if self.state.teacher_forced:
            use_teacher = teacher is not None
            reason = "teacher_forced"
        elif teacher is not None and (not agreement or student.confidence < self.confidence_threshold):
            use_teacher = True
            reason = "teacher_disagreement_or_low_confidence"

        if use_teacher and teacher is not None:
            attack_type = teacher["attack_type"]
            is_malicious = teacher["is_malicious"]
            confidence = float(teacher["confidence"])
            output_source = "teacher"
            self.teacher_fallbacks += 1
        else:
            attack_type = student.attack_type
            is_malicious = student.is_malicious
            confidence = float(student.confidence)
            output_source = "student"

        latency_ms = (time.perf_counter() - start) * 1000
        return {
            "attack_type": attack_type,
            "is_malicious": is_malicious,
            "confidence": round(confidence, 6),
            "source": output_source,
            "latency_ms": round(latency_ms, 4),
            "teacher_forced": self.state.teacher_forced,
            "alignment": {
                "agreement": agreement,
                "probability_gap": round(probability_gap, 6),
                "decision_reason": reason,
            },
            "source_id": source_id,
        }

    def submit_feedback(
        self,
        payload: str,
        label: int,
        source_id: str,
        confidence: float,
        consensus_ok: bool = True,
    ) -> Dict[str, object]:
        teacher_flags_malicious = False
        if self.engine.teacher_model is not None:
            teacher_compare = self.engine.predict_with_teacher(payload)
            teacher_info = teacher_compare.get("teacher")
            teacher_flags_malicious = bool(teacher_info and teacher_info.get("is_malicious"))

        decision = self.safety.evaluate_feedback(
            payload=payload,
            source_id=source_id,
            confidence=confidence,
            consensus_ok=consensus_ok,
            teacher_flags_malicious=teacher_flags_malicious,
        )

        sample = {
            "payload": decision.sanitized_payload,
            "label": int(label),
            "source_id": source_id,
            "confidence": float(confidence),
            "teacher_agreement": not teacher_flags_malicious,
        }

        queued = False
        if decision.accepted:
            queued = self.learner.enqueue_feedback(sample)
            if not queued:
                self.rollback_to_teacher()
        elif decision.quarantined:
            self.learner.enqueue_quarantine(sample)
        else:
            self.learner.reject_feedback()

        return {
            "accepted": decision.accepted,
            "queued": queued,
            "quarantined": decision.quarantined,
            "reason": decision.reason,
            "trust_score": round(float(decision.trust_score), 6),
        }

    def get_stats(self) -> Dict[str, object]:
        learner_stats = self.learner.get_stats()
        perf = self.engine.get_performance_metrics()
        safety = self.safety.get_global_stats()

        return {
            "runtime": asdict(self.state),
            "total_inferences": self.total_inferences,
            "teacher_fallbacks": self.teacher_fallbacks,
            "learner": learner_stats,
            "inference": perf,
            "safety": safety,
        }
