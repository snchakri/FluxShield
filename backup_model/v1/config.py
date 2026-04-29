"""
Configuration for Twilight WAF AI v1
State-of-the-art ML-based WAF with auto-sklearn
Optimized for: very low latency, very high throughput, very high accuracy
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Base directories
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent.parent / "datasets"
MODEL_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / "cache"

# Ensure directories exist
MODEL_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class OWASPAttackConfig:
    """OWASP Top 10 + Extended Attack Types"""
    
    # OWASP Top 10 2021 Attack Categories
    ATTACK_TYPES: Dict[str, int] = field(default_factory=lambda: {
        "benign": 0,
        "sqli": 1,              # A03:2021 – Injection (SQL Injection)
        "xss": 2,               # A03:2021 – Injection (Cross-Site Scripting)
        "path_traversal": 3,    # A01:2021 – Broken Access Control
        "command_injection": 4, # A03:2021 – Injection (OS Command Injection)
        "xxe": 5,               # A05:2021 – Security Misconfiguration (XML External Entity)
        "ssrf": 6,              # A10:2021 – Server-Side Request Forgery
        "lfi": 7,               # A01:2021 – Broken Access Control (Local File Inclusion)
        "rfi": 8,               # A01:2021 – Broken Access Control (Remote File Inclusion)
        "rce": 9,               # A03:2021 – Injection (Remote Code Execution)
        "ldap_injection": 10,   # A03:2021 – Injection
        "xml_injection": 11,    # A03:2021 – Injection
        "nosql_injection": 12,  # A03:2021 – Injection
        "csrf": 13,             # A01:2021 – Broken Access Control
        "ssti": 14,             # A03:2021 – Injection (Server-Side Template Injection)
        "crlf_injection": 15,   # A03:2021 – Injection
        "header_injection": 16, # A05:2021 – Security Misconfiguration
        "buffer_overflow": 17,  # A04:2021 – Insecure Design
        "malicious": 18,        # Generic malicious (when specific type unknown)
    })
    
    # Attack pattern signatures for enhanced detection
    ATTACK_PATTERNS: Dict[str, List[str]] = field(default_factory=lambda: {
        "sqli": [
            r"(?i)(union.*select|select.*from|insert.*into|delete.*from|update.*set)",
            r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1)",
            r"(?i)(sleep\(|benchmark\(|waitfor\s+delay)",
            r"(?i)(exec\(|execute\(|sp_executesql)",
            r"[\'\";]\s*(?:or|and)\s*[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+",
        ],
        "xss": [
            r"<script[^>]*>.*?</script>",
            r"(?i)(javascript:|onerror=|onload=|onclick=|onmouseover=)",
            r"(?i)(<iframe|<object|<embed|<img[^>]+src)",
            r"(?i)(alert\(|prompt\(|confirm\(|eval\()",
            r"(?i)(<svg|<marquee|<audio|<video)",
        ],
        "path_traversal": [
            r"\.\./|\.\.\\",
            r"(?i)(etc/passwd|boot\.ini|win\.ini)",
            r"%2e%2e[/\\]|\.\.%2f|\.\.%5c",
            r"(?i)(file://|file:\\\\)",
        ],
        "command_injection": [
            r"(?i)(;|\||&|`|\$\(|\$\{).*?(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
            r"(?i)(&&|\|\||;)\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
            r"(?i)(exec\(|shell_exec\(|system\(|passthru\()",
        ],
        "xxe": [
            r"<!DOCTYPE.*<!ENTITY",
            r"(?i)(<!ENTITY.*SYSTEM|<!ENTITY.*PUBLIC)",
            r"(?i)(file://|php://|expect://|zip://)",
        ],
        "ssrf": [
            r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
            r"(?i)(169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)",
            r"(?i)(metadata\.google|169\.254\.169\.254)",
        ],
        "lfi": [
            r"(?i)(\.\.\/.*\/etc\/passwd|\.\.\\.*\\boot\.ini)",
            r"(?i)(php://filter|php://input|data://|expect://)",
            r"(?i)(include=|require=|file=).*\.\.",
        ],
        "rfi": [
            r"(?i)(http://|https://|ftp://).*\.(txt|php|asp|jsp)",
            r"(?i)(include=|require=|file=).*(http|https|ftp)://",
        ],
        "ssti": [
            r"\{\{.*\}\}|\{%.*%\}|\$\{.*\}",
            r"(?i)(\{\{.*config.*\}\}|\{\{.*self.*\}\})",
            r"(?i)(__class__|__mro__|__subclasses__|__globals__)",
        ],
        "ldap_injection": [
            r"\(\|\(\w+=\*\)\)",
            r"(?i)(\)\(\||&\(|\|\()",
        ],
        "nosql_injection": [
            r"(?i)(\$where|\$ne|\$gt|\$lt|\$regex|\$in)",
            r"\{\s*\$.*:\s*.*\}",
        ],
        "crlf_injection": [
            r"%0d%0a|%0a|%0d|\\r\\n|\\n|\\r",
            r"(?i)(Set-Cookie:|Location:).*(%0d%0a|\\r\\n)",
        ],
    })


@dataclass
class FeatureConfig:
    """Feature engineering configuration for low latency"""
    
    # Character n-gram configuration
    CHAR_NGRAM_RANGE: Tuple[int, int] = (2, 5)
    CHAR_NGRAM_MAX_FEATURES: int = 10000
    
    # Word n-gram configuration
    WORD_NGRAM_RANGE: Tuple[int, int] = (1, 3)
    WORD_NGRAM_MAX_FEATURES: int = 5000
    
    # TF-IDF parameters
    TFIDF_SUBLINEAR_TF: bool = True
    TFIDF_MAX_DF: float = 0.95
    TFIDF_MIN_DF: int = 2
    
    # Statistical features
    ENABLE_ENTROPY: bool = True
    ENABLE_LENGTH_FEATURES: bool = True
    ENABLE_CHAR_DISTRIBUTION: bool = True
    ENABLE_PATTERN_MATCHING: bool = True
    
    # URL-specific features
    URL_DECODE: bool = True
    URL_NORMALIZE: bool = True
    
    # Performance optimization
    CACHE_FEATURES: bool = True
    PARALLEL_PROCESSING: bool = True
    N_JOBS: int = -1  # Use all available cores
    
    # Dimensionality reduction
    USE_PCA: bool = False
    PCA_COMPONENTS: int = 500
    
    # Feature selection
    FEATURE_SELECTION: bool = True
    MAX_FEATURES_FINAL: int = 2000


@dataclass
class AutoMLConfig:
    """Auto-sklearn configuration for optimal model selection"""
    
    # Time limits (in seconds)
    TIME_LEFT_FOR_THIS_TASK: int = 7200  # 2 hours total
    PER_RUN_TIME_LIMIT: int = 360        # 6 minutes per model
    
    # Ensemble configuration
    ENSEMBLE_SIZE: int = 50
    ENSEMBLE_NBEST: int = 200
    
    # Search space
    INCLUDE_ESTIMATORS: Optional[List[str]] = None
    EXCLUDE_ESTIMATORS: Optional[List[str]] = field(default_factory=lambda: [
        "bernoulli_nb",  # Not suitable for this task
        "multinomial_nb",  # Not suitable for this task
    ])
    
    INCLUDE_PREPROCESSORS: Optional[List[str]] = None
    
    # Performance optimization
    N_JOBS: int = -1
    MEMORY_LIMIT: int = 16384  # 16 GB
    
    # Resampling strategy
    RESAMPLING_STRATEGY: str = "cv"
    RESAMPLING_STRATEGY_ARGUMENTS: Dict = field(default_factory=lambda: {"folds": 5})
    
    # Metric optimization
    METRIC: str = "f1_weighted"  # Optimized for imbalanced multi-class
    
    # Model output
    OUTPUT_FOLDER: str = str(MODEL_DIR / "autosklearn_output")
    TMP_FOLDER: str = str(MODEL_DIR / "autosklearn_tmp")
    DELETE_TMP_FOLDER_AFTER_TERMINATE: bool = False
    
    # For incremental learning
    INITIAL_CONFIGURATIONS_VIA_METALEARNING: int = 25


@dataclass
class InferenceConfig:
    """Configuration for high-throughput inference"""
    
    # Latency optimization
    BATCH_SIZE: int = 32
    MAX_WORKERS: int = 8
    
    # Caching
    ENABLE_CACHE: bool = True
    CACHE_SIZE: int = 10000
    CACHE_TTL: int = 3600  # 1 hour
    
    # Thresholds
    CONFIDENCE_THRESHOLD: float = 0.7
    
    # Model loading
    MODEL_PATH: str = str(MODEL_DIR / "waf_model.pkl")
    VECTORIZER_PATH: str = str(MODEL_DIR / "vectorizer.pkl")
    FEATURE_EXTRACTOR_PATH: str = str(MODEL_DIR / "feature_extractor.pkl")
    
    # Performance monitoring
    ENABLE_METRICS: bool = True
    METRICS_INTERVAL: int = 60  # Log metrics every 60 seconds


@dataclass
class TrainingConfig:
    """Training pipeline configuration"""
    
    # Data paths
    TRAIN_DATA_PATH: str = str(DATA_DIR / "huggingface_full.csv")
    TEXT_COLUMN: str = "text"
    LABEL_COLUMN: str = "label"
    
    # Data splits
    TEST_SIZE: float = 0.2
    VAL_SIZE: float = 0.1
    RANDOM_STATE: int = 42
    STRATIFY: bool = True
    
    # Class balancing
    BALANCE_CLASSES: bool = True
    BALANCE_METHOD: str = "class_weight"  # or "smote" or "undersample"
    
    # Preprocessing
    MAX_SAMPLES: Optional[int] = None  # None = use all data
    MIN_LABEL_COUNT: int = 10  # Minimum samples per class
    
    # Multi-label handling
    ATTACK_LABELING_METHOD: str = "pattern_based"  # or "keyword_based" or "hybrid"
    
    # Model versioning
    MODEL_VERSION: str = "v1.0.0"
    SAVE_INTERMEDIATE: bool = True


# Global config instances
owasp_config = OWASPAttackConfig()
feature_config = FeatureConfig()
automl_config = AutoMLConfig()
inference_config = InferenceConfig()
training_config = TrainingConfig()
