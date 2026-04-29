"""High-throughput inference for the AutoKeras WAF model."""

import json
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Optional

import numpy as np

from config import export_config, inference_config, runtime_config


@dataclass
class InferenceResult:
    is_malicious: bool
    attack_type: str
    confidence: float
    latency_ms: float


class InferenceEngine:
    def __init__(self, prefer_tflite: bool = False):
        self.prefer_tflite = prefer_tflite
        self.model = None
        self.labels = None
        self.safe_charset = re.compile(inference_config.SAFE_CHARSET_RE)

    def load_model(self) -> None:
        self.labels = self._load_labels()

        if self.prefer_tflite:
            tflite = self._load_tflite()
            if tflite is not None:
                self.model = tflite
                return

        self.model = self._load_keras()

    def _load_keras(self):
        import tensorflow as tf

        return tf.keras.models.load_model(str(export_config.SAVED_MODEL_DIR))

    def _load_tflite(self):
        try:
            import tensorflow as tf

            interpreter = tf.lite.Interpreter(model_path=str(export_config.TFLITE_PATH))
            interpreter.allocate_tensors()
            return interpreter
        except Exception:
            return None

    def _load_labels(self) -> Dict[int, str]:
        with open(runtime_config.LABELS_JSON, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return {int(k): v for k, v in payload["id_to_label"].items()}

    def _fast_prefilter(self, text: str) -> Optional[InferenceResult]:
        if not inference_config.ENABLE_FAST_PREFILTER:
            return None

        lowered = text.lower()
        if len(lowered) > inference_config.MAX_SAFE_LENGTH:
            return None

        if not self.safe_charset.match(lowered):
            return None

        if any(token in lowered for token in inference_config.SUSPICIOUS_TOKENS):
            return None

        return InferenceResult(
            is_malicious=False,
            attack_type="benign",
            confidence=inference_config.BENIGN_CONFIDENCE,
            latency_ms=0.0,
        )

    def predict_single(self, text: str) -> InferenceResult:
        start = time.perf_counter()

        prefilter = self._fast_prefilter(text)
        if prefilter is not None:
            prefilter.latency_ms = (time.perf_counter() - start) * 1000.0
            return prefilter

        result = self._cached_predict(text)
        result.latency_ms = (time.perf_counter() - start) * 1000.0
        return result

    def predict_batch(self, texts: List[str]) -> List[InferenceResult]:
        start = time.perf_counter()
        results = self._predict_batch(texts)
        latency_ms = (time.perf_counter() - start) * 1000.0
        if results:
            per_item = latency_ms / len(results)
            for result in results:
                result.latency_ms = per_item
        return results

    @lru_cache(maxsize=inference_config.MAX_CACHE_SIZE)
    def _cached_predict(self, text: str) -> InferenceResult:
        return self._predict_batch([text])[0]

    def _predict_batch(self, texts: List[str]) -> List[InferenceResult]:
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        if self._is_tflite():
            return self._predict_batch_tflite(texts)
        return self._predict_batch_keras(texts)

    def _is_tflite(self) -> bool:
        return self.model.__class__.__name__ == "Interpreter"

    def _predict_batch_keras(self, texts: List[str]) -> List[InferenceResult]:
        import tensorflow as tf

        inputs = np.array(texts, dtype=object)
        preds = self.model.predict(inputs, batch_size=inference_config.BATCH_SIZE)

        results = []
        for row in preds:
            idx = int(np.argmax(row))
            confidence = float(np.max(row))
            label = self.labels.get(idx, str(idx))
            results.append(
                InferenceResult(
                    is_malicious=label != "benign",
                    attack_type=label,
                    confidence=confidence,
                    latency_ms=0.0,
                )
            )
        return results

    def _predict_batch_tflite(self, texts: List[str]) -> List[InferenceResult]:
        interpreter = self.model
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()

        results = []
        for text in texts:
            input_tensor = np.array([text], dtype=np.object_)
            interpreter.set_tensor(input_details[0]["index"], input_tensor)
            interpreter.invoke()
            output = interpreter.get_tensor(output_details[0]["index"])

            idx = int(np.argmax(output[0]))
            confidence = float(np.max(output[0]))
            label = self.labels.get(idx, str(idx))
            results.append(
                InferenceResult(
                    is_malicious=label != "benign",
                    attack_type=label,
                    confidence=confidence,
                    latency_ms=0.0,
                )
            )
        return results
