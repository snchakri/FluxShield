import re
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TrustDecision:
    accepted: bool
    quarantined: bool
    trust_score: float
    reason: str
    sanitized_payload: str


class SafetyModule:
    def __init__(
        self,
        min_trust_to_learn: float = 0.35,
        trust_gain: float = 0.01,
        trust_drop: float = 1.0,
        quarantine_floor: float = 0.0,
        warmup_seconds: int = 24 * 60 * 60,
    ) -> None:
        self.min_trust_to_learn = min_trust_to_learn
        self.trust_gain = trust_gain
        self.trust_drop = trust_drop
        self.quarantine_floor = quarantine_floor
        self.warmup_seconds = warmup_seconds

        self._source_state: Dict[str, Dict[str, float]] = {}

        self._pii_patterns = [
            re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
            re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?"),
            re.compile(r"(?i)\b(bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)"),
        ]

    @staticmethod
    def _clip(value: float, low: float, high: float) -> float:
        return max(low, min(high, value))

    def scrub_pii(self, payload: str) -> str:
        sanitized = payload or ""
        for pattern in self._pii_patterns:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized

    def _get_state(self, source_id: str) -> Dict[str, float]:
        if source_id not in self._source_state:
            self._source_state[source_id] = {
                "trust": 0.0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "accepted": 0.0,
                "rejected": 0.0,
            }
        return self._source_state[source_id]

    def evaluate_feedback(
        self,
        payload: str,
        source_id: str,
        confidence: float,
        consensus_ok: bool,
        teacher_flags_malicious: bool,
    ) -> TrustDecision:
        now = time.time()
        state = self._get_state(source_id)
        state["last_seen"] = now

        baseline_signal = 0.5
        if confidence >= 0.85:
            baseline_signal += 0.2
        if consensus_ok:
            baseline_signal += 0.2
        if teacher_flags_malicious:
            baseline_signal -= 0.7

        if baseline_signal < 0:
            state["trust"] = self._clip(state["trust"] - self.trust_drop, -1.0, 1.0)
            state["rejected"] += 1.0
        else:
            state["trust"] = self._clip(state["trust"] + self.trust_gain, -1.0, 1.0)

        source_age = now - state["first_seen"]
        warmed_up = source_age >= self.warmup_seconds

        quarantined = state["trust"] < self.quarantine_floor
        accepted = (
            not quarantined
            and warmed_up
            and state["trust"] >= self.min_trust_to_learn
            and confidence >= 0.55
            and consensus_ok
            and not teacher_flags_malicious
        )

        if accepted:
            state["accepted"] += 1.0

        reason = "accepted"
        if quarantined:
            reason = "quarantined_low_trust"
        elif not warmed_up:
            reason = "cooldown_active"
        elif confidence < 0.55:
            reason = "low_confidence"
        elif not consensus_ok:
            reason = "consensus_failed"
        elif teacher_flags_malicious:
            reason = "teacher_rejected"
        elif state["trust"] < self.min_trust_to_learn:
            reason = "insufficient_trust"

        return TrustDecision(
            accepted=accepted,
            quarantined=quarantined,
            trust_score=state["trust"],
            reason=reason,
            sanitized_payload=self.scrub_pii(payload),
        )

    def get_source_stats(self, source_id: str) -> Dict[str, float]:
        state = self._get_state(source_id)
        return dict(state)

    def get_global_stats(self) -> Dict[str, float]:
        if not self._source_state:
            return {
                "sources": 0,
                "avg_trust": 0.0,
                "quarantined_sources": 0,
            }

        trusts = [s["trust"] for s in self._source_state.values()]
        quarantined = sum(1 for t in trusts if t < self.quarantine_floor)
        return {
            "sources": len(trusts),
            "avg_trust": sum(trusts) / len(trusts),
            "quarantined_sources": quarantined,
        }
