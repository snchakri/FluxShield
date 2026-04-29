"""
Twilight WAF AI v1
State-of-the-art ML-based Web Application Firewall using Auto-sklearn
"""

__version__ = "1.0.0"
__author__ = "Twilight HS Team"

from .attack_labeler import AttackLabeler
from .config import (
    automl_config,
    feature_config,
    inference_config,
    owasp_config,
    training_config,
)
from .evaluation import ModelEvaluator
from .feature_extraction import FastFeatureExtractor
from .inference import InferenceEngine, PredictionResult

__all__ = [
    "AttackLabeler",
    "FastFeatureExtractor",
    "InferenceEngine",
    "PredictionResult",
    "ModelEvaluator",
    "automl_config",
    "feature_config",
    "inference_config",
    "owasp_config",
    "training_config",
]
