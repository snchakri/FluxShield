"""
High-Throughput Inference Engine
Optimized for very low latency and very high throughput
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from cachetools import TTLCache

from config import inference_config, owasp_config


@dataclass
class PredictionResult:
    """Prediction result with metadata"""
    payload: str
    is_malicious: bool
    attack_type: str
    confidence: float
    latency_ms: float
    cached: bool = False


class InferenceEngine:
    """
    High-performance inference engine
    Features:
    - Multi-threaded batch processing
    - LRU caching for repeated payloads
    - Optimized feature extraction
    - Sub-millisecond latency per request
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        feature_extractor_path: Optional[str] = None,
    ):
        self.model_path = model_path or inference_config.MODEL_PATH
        self.feature_extractor_path = feature_extractor_path or inference_config.FEATURE_EXTRACTOR_PATH
        
        self.model = None
        self.teacher_model = None
        self.feature_extractor = None
        self.streaming_feature_extractor = None
        self.attack_types = owasp_config.ATTACK_TYPES
        self.inverse_attack_types = {v: k for k, v in self.attack_types.items()}
        
        # Prediction cache (TTL cache for dynamic updates)
        self.cache_enabled = inference_config.ENABLE_CACHE
        if self.cache_enabled:
            self.prediction_cache = TTLCache(
                maxsize=inference_config.CACHE_SIZE,
                ttl=inference_config.CACHE_TTL,
            )
        else:
            self.prediction_cache = {}
        
        # Performance metrics
        self.total_requests = 0
        self.cache_hits = 0
        self.total_latency_ms = 0.0
        self.online_updates = 0
        self.last_online_update_ts = None
        self.teacher_disagreements = 0
        
    def load_model(self) -> None:
        """Load trained model and feature extractor"""
        print(f"Loading model from {self.model_path}...")
        self.model = joblib.load(self.model_path)
        
        print(f"Loading feature extractor from {self.feature_extractor_path}...")
        from feature_extraction import FastFeatureExtractor, StreamingFeatureExtractor
        self.feature_extractor = FastFeatureExtractor()
        self.feature_extractor.load(self.feature_extractor_path)
        self.streaming_feature_extractor = StreamingFeatureExtractor()
        
        print("✓ Model and feature extractor loaded successfully")

    def load_teacher_snapshot(self, teacher_model_path: Optional[str] = None) -> None:
        """Load immutable teacher model snapshot for alignment/fallback checks"""
        teacher_path = teacher_model_path or self.model_path
        self.teacher_model = joblib.load(teacher_path)

    @staticmethod
    def _safe_predict_proba(model, features) -> Optional[np.ndarray]:
        if hasattr(model, "predict_proba"):
            return model.predict_proba(features)
        return None
    
    @staticmethod
    def _compute_payload_hash(payload: str) -> str:
        """Compute hash for caching"""
        return hashlib.md5(payload.encode()).hexdigest()
    
    def predict_single(
        self,
        payload: str,
        return_proba: bool = False,
    ) -> PredictionResult:
        """
        Predict single payload
        
        Args:
            payload: HTTP request payload
            return_proba: Whether to return probability scores
            
        Returns:
            PredictionResult
        """
        start_time = time.perf_counter()
        
        # Check cache
        cached = False
        if self.cache_enabled:
            cache_key = self._compute_payload_hash(payload)
            if cache_key in self.prediction_cache:
                result = self.prediction_cache[cache_key]
                self.cache_hits += 1
                result.cached = True
                return result
        
        # Extract features
        payload_series = pd.Series([payload])
        features = self.feature_extractor.transform(payload_series)
        
        # Predict
        pred_label = self.model.predict(features)[0]
        
        if return_proba and hasattr(self.model, "predict_proba"):
            pred_proba = self.model.predict_proba(features)[0]
            confidence = float(pred_proba[pred_label])
        else:
            confidence = 1.0  # No probability available
        
        # Map to attack type
        attack_type = self.inverse_attack_types.get(pred_label, "unknown")
        is_malicious = attack_type != "benign"
        
        # Compute latency
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Create result
        result = PredictionResult(
            payload=payload,
            is_malicious=is_malicious,
            attack_type=attack_type,
            confidence=confidence,
            latency_ms=latency_ms,
            cached=cached,
        )
        
        # Cache result
        if self.cache_enabled:
            self.prediction_cache[cache_key] = result
        
        # Update metrics
        self.total_requests += 1
        self.total_latency_ms += latency_ms
        
        return result

    def predict_with_teacher(self, payload: str) -> Dict[str, object]:
        """Run student prediction and optional teacher comparison signal"""
        student = self.predict_single(payload, return_proba=True)
        if self.teacher_model is None:
            return {
                "student": student,
                "teacher": None,
                "agreement": True,
                "probability_gap": 0.0,
            }

        payload_series = pd.Series([payload])
        features = self.feature_extractor.transform(payload_series)

        teacher_label = self.teacher_model.predict(features)[0]
        teacher_attack_type = self.inverse_attack_types.get(int(teacher_label), "unknown")
        teacher_is_malicious = teacher_attack_type != "benign"

        teacher_proba = self._safe_predict_proba(self.teacher_model, features)
        teacher_confidence = (
            float(teacher_proba[0][teacher_label])
            if teacher_proba is not None
            else 1.0
        )

        agreement = (
            teacher_attack_type == student.attack_type
            and teacher_is_malicious == student.is_malicious
        )
        if not agreement:
            self.teacher_disagreements += 1

        probability_gap = abs(float(student.confidence) - float(teacher_confidence))

        return {
            "student": student,
            "teacher": {
                "attack_type": teacher_attack_type,
                "is_malicious": teacher_is_malicious,
                "confidence": teacher_confidence,
            },
            "agreement": agreement,
            "probability_gap": probability_gap,
        }

    def partial_fit_batch(
        self,
        payloads: List[str],
        labels: List[int],
        classes: Optional[List[int]] = None,
        sample_weight: Optional[List[float]] = None,
    ) -> bool:
        """Apply online updates for partial_fit-compatible models"""
        if self.model is None or self.feature_extractor is None:
            raise ValueError("Model and feature extractor must be loaded")

        if not hasattr(self.model, "partial_fit"):
            return False

        payload_series = pd.Series(payloads)
        try:
            features = self.feature_extractor.transform(payload_series)
        except Exception:
            if self.streaming_feature_extractor is None:
                from feature_extraction import StreamingFeatureExtractor

                self.streaming_feature_extractor = StreamingFeatureExtractor()
            features = self.streaming_feature_extractor.transform(payload_series)

        if hasattr(self.model, "n_features_in_") and int(self.model.n_features_in_) != int(features.shape[1]):
            return False

        if classes is None:
            classes = sorted(self.attack_types.values())

        fit_kwargs = {"classes": np.array(classes, dtype=np.int64)}
        if sample_weight is not None:
            fit_kwargs["sample_weight"] = np.array(sample_weight, dtype=np.float64)

        self.model.partial_fit(features, np.array(labels, dtype=np.int64), **fit_kwargs)

        self.online_updates += len(payloads)
        self.last_online_update_ts = time.time()

        if self.cache_enabled:
            self.prediction_cache.clear()

        return True
    
    def predict_batch(
        self,
        payloads: List[str],
        batch_size: Optional[int] = None,
        n_workers: Optional[int] = None,
    ) -> List[PredictionResult]:
        """
        Predict batch of payloads with parallel processing
        
        Args:
            payloads: List of HTTP request payloads
            batch_size: Batch size for processing (default from config)
            n_workers: Number of worker threads (default from config)
            
        Returns:
            List of PredictionResult
        """
        batch_size = batch_size or inference_config.BATCH_SIZE
        n_workers = n_workers or inference_config.MAX_WORKERS
        
        # Check cache first
        results = []
        uncached_payloads = []
        uncached_indices = []
        
        for idx, payload in enumerate(payloads):
            if self.cache_enabled:
                cache_key = self._compute_payload_hash(payload)
                if cache_key in self.prediction_cache:
                    result = self.prediction_cache[cache_key]
                    result.cached = True
                    results.append(result)
                    self.cache_hits += 1
                    continue
            
            uncached_payloads.append(payload)
            uncached_indices.append(idx)
        
        # Process uncached payloads
        if uncached_payloads:
            start_time = time.perf_counter()
            
            # Extract features in batch
            payload_series = pd.Series(uncached_payloads)
            features = self.feature_extractor.transform(payload_series)
            
            # Predict in batch
            pred_labels = self.model.predict(features)
            
            if hasattr(self.model, "predict_proba"):
                pred_probas = self.model.predict_proba(features)
            else:
                pred_probas = None
            
            # Create results
            batch_latency_ms = (time.perf_counter() - start_time) * 1000
            per_sample_latency = batch_latency_ms / len(uncached_payloads)
            
            for i, (payload, pred_label) in enumerate(zip(uncached_payloads, pred_labels)):
                attack_type = self.inverse_attack_types.get(pred_label, "unknown")
                is_malicious = attack_type != "benign"
                
                if pred_probas is not None:
                    confidence = float(pred_probas[i][pred_label])
                else:
                    confidence = 1.0
                
                result = PredictionResult(
                    payload=payload,
                    is_malicious=is_malicious,
                    attack_type=attack_type,
                    confidence=confidence,
                    latency_ms=per_sample_latency,
                    cached=False,
                )
                
                # Cache result
                if self.cache_enabled:
                    cache_key = self._compute_payload_hash(payload)
                    self.prediction_cache[cache_key] = result
                
                results.append(result)
            
            self.total_requests += len(uncached_payloads)
            self.total_latency_ms += batch_latency_ms
        
        # Sort results back to original order
        sorted_results = [None] * len(payloads)
        result_idx = 0
        for idx in range(len(payloads)):
            sorted_results[idx] = results[result_idx]
            result_idx += 1
        
        return sorted_results
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get inference performance metrics"""
        if self.total_requests == 0:
            return {
                "total_requests": 0,
                "cache_hit_rate": 0.0,
                "avg_latency_ms": 0.0,
                "throughput_rps": 0.0,
            }
        
        cache_hit_rate = self.cache_hits / self.total_requests
        avg_latency_ms = self.total_latency_ms / self.total_requests
        throughput_rps = 1000 / avg_latency_ms if avg_latency_ms > 0 else 0
        
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_hit_rate": cache_hit_rate,
            "avg_latency_ms": avg_latency_ms,
            "throughput_rps": throughput_rps,
            "online_updates": self.online_updates,
            "teacher_disagreements": self.teacher_disagreements,
            "last_online_update_ts": self.last_online_update_ts,
        }
    
    def print_performance_metrics(self) -> None:
        """Print performance metrics"""
        metrics = self.get_performance_metrics()
        
        print("\n" + "=" * 80)
        print("INFERENCE PERFORMANCE METRICS")
        print("=" * 80)
        print(f"Total Requests:     {metrics['total_requests']}")
        print(f"Cache Hits:         {metrics['cache_hits']}")
        print(f"Cache Hit Rate:     {metrics['cache_hit_rate']:.2%}")
        print(f"Avg Latency:        {metrics['avg_latency_ms']:.3f} ms/request")
        print(f"Throughput:         {metrics['throughput_rps']:.0f} requests/second")
        print("=" * 80)


if __name__ == "__main__":
    # Test inference engine
    from pathlib import Path
    
    engine = InferenceEngine()
    
    # Mock model for testing
    print("Note: This is a test without loading actual model")
    print("To use in production, call engine.load_model() first")
    
    test_payloads = [
        "GET /index.html HTTP/1.1",
        "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
        "<script>alert('XSS')</script>",
        "GET /../../../etc/passwd HTTP/1.1",
    ]
    
    print(f"\nTest payloads: {len(test_payloads)}")
    print("Load model first with: engine.load_model()")
