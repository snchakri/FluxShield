"""
Configuration for Twilight WAF AI (Neural) v1
Optimized for: very low latency, very high throughput, very high accuracy
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

# Base directories
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent.parent / "datasets"
MODEL_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / "cache"

# Ensure directories exist
for _dir in (MODEL_DIR, LOGS_DIR, CACHE_DIR):
    _dir.mkdir(parents=True, exist_ok=True)


@dataclass
class DatasetConfig:
    TRAIN_DATA_PATH: Path = DATA_DIR / "huggingface_full.csv"
    TEXT_COLUMN: str = "text"
    LABEL_COLUMN: str = "label"
    MAX_SAMPLES: Optional[int] = None
    MIN_LABEL_COUNT: int = 50
    RANDOM_STATE: int = 42
    TEST_SIZE: float = 0.1
    VAL_SIZE: float = 0.1
    STRATIFY: bool = True


@dataclass
class AutoKerasConfig:
    MAX_TRIALS: int = 12
    TUNER: str = "hyperband"
    PROJECT_NAME: str = "waf_autokeras_text"
    DIRECTORY: Path = MODEL_DIR / "autokeras"
    OVERWRITE: bool = True
    EPOCHS: int = 12
    BATCH_SIZE: int = 128
    EARLY_STOPPING_PATIENCE: int = 2
    SEQUENCE_LENGTH: int = 256
    MAX_TOKENS: int = 20000
    NGRAM_RANGE: Tuple[int, int] = (1, 2)
    DROPOUT_RATE: float = 0.2
    CLASS_WEIGHT: bool = True


@dataclass
class ExportConfig:
    SAVED_MODEL_DIR: Path = MODEL_DIR / "saved_model"
    TFLITE_PATH: Path = MODEL_DIR / "model.tflite"
    ENABLE_TFLITE_EXPORT: bool = True
    TFLITE_QUANTIZE: bool = True


@dataclass
class InferenceConfig:
    BATCH_SIZE: int = 256
    MAX_CACHE_SIZE: int = 20000
    ENABLE_FAST_PREFILTER: bool = True
    MAX_SAFE_LENGTH: int = 200
    SAFE_CHARSET_RE: str = r"^[A-Za-z0-9\s\-\._~:/\?\[\]@!\$&'\(\)\*\+,;=%]*$"
    SUSPICIOUS_TOKENS: Tuple[str, ...] = (
        "<script",
        "union select",
        "../",
        "..\\",
        "%3c",
        "%3e",
        "cmd=",
        "powershell",
        "bash",
        "wget",
        "curl",
        "sleep(",
        "benchmark(",
        "or 1=1",
    )
    BENIGN_CONFIDENCE: float = 0.99


@dataclass
class RuntimeConfig:
    SEED: int = 42
    LOG_METRICS_JSON: Path = LOGS_DIR / "metrics.json"
    LABELS_JSON: Path = LOGS_DIR / "label_mapping.json"


dataset_config = DatasetConfig()
autokeras_config = AutoKerasConfig()
export_config = ExportConfig()
inference_config = InferenceConfig()
runtime_config = RuntimeConfig()
