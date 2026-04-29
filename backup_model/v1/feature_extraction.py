"""
Feature Extraction Module
Optimized for very low latency and very high accuracy
Uses hybrid approach: statistical + TF-IDF + pattern-based features
"""

import hashlib
import math
import re
import urllib.parse
from collections import Counter
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif
from sklearn.preprocessing import StandardScaler

from config import feature_config, owasp_config


class FastFeatureExtractor:
    """
    High-performance feature extractor optimized for low latency
    Combines multiple feature types:
    1. Character n-grams (TF-IDF)
    2. Statistical features (entropy, length, char distribution)
    3. Pattern-based features (attack signatures)
    4. URL-specific features
    """
    
    def __init__(self, fitted: bool = False):
        self.fitted = fitted
        self.char_vectorizer: Optional[TfidfVectorizer] = None
        self.word_vectorizer: Optional[TfidfVectorizer] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_selector: Optional[SelectKBest] = None
        self.feature_names: List[str] = []
        self.attack_patterns = owasp_config.ATTACK_PATTERNS
        self._compile_patterns()
        
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance"""
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for attack_type, patterns in self.attack_patterns.items():
            self.compiled_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
    
    @staticmethod
    @lru_cache(maxsize=10000)
    def _normalize_cached(payload: str) -> str:
        """Cached normalization for frequently seen payloads"""
        return FastFeatureExtractor._normalize_payload(payload)
    
    @staticmethod
    def _normalize_payload(payload: str) -> str:
        """Normalize payload (URL decode, lowercase, etc.)"""
        if not payload:
            return ""
        
        # URL decode (max 3 passes for nested encoding)
        decoded = payload
        for _ in range(3):
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break
        
        return decoded
    
    def extract_statistical_features(self, payload: str, normalized: str) -> Dict[str, float]:
        """
        Extract statistical features (very fast, < 1ms per payload)
        
        Features:
        - Length metrics
        - Character distribution
        - Entropy
        - Special character ratios
        - Encoding metrics
        """
        features = {}
        
        # Length features
        features["length"] = len(payload)
        features["length_normalized"] = len(normalized)
        features["length_ratio"] = len(normalized) / max(len(payload), 1)
        
        if not normalized:
            return {k: 0.0 for k in features}
        
        # Character distribution
        char_counts = Counter(normalized)
        total_chars = len(normalized)
        
        features["unique_chars"] = len(char_counts)
        features["unique_ratio"] = len(char_counts) / total_chars
        
        # Character type ratios
        features["alpha_ratio"] = sum(1 for c in normalized if c.isalpha()) / total_chars
        features["digit_ratio"] = sum(1 for c in normalized if c.isdigit()) / total_chars
        features["upper_ratio"] = sum(1 for c in normalized if c.isupper()) / total_chars
        features["lower_ratio"] = sum(1 for c in normalized if c.islower()) / total_chars
        features["space_ratio"] = sum(1 for c in normalized if c.isspace()) / total_chars
        features["special_ratio"] = sum(
            1 for c in normalized if not c.isalnum() and not c.isspace()
        ) / total_chars
        
        # Specific special characters
        features["slash_count"] = normalized.count("/")
        features["backslash_count"] = normalized.count("\\")
        features["dot_count"] = normalized.count(".")
        features["dash_count"] = normalized.count("-")
        features["underscore_count"] = normalized.count("_")
        features["equal_count"] = normalized.count("=")
        features["question_count"] = normalized.count("?")
        features["ampersand_count"] = normalized.count("&")
        features["percent_count"] = normalized.count("%")
        features["semicolon_count"] = normalized.count(";")
        features["quote_single_count"] = normalized.count("'")
        features["quote_double_count"] = normalized.count('"')
        features["lt_count"] = normalized.count("<")
        features["gt_count"] = normalized.count(">")
        features["pipe_count"] = normalized.count("|")
        features["dollar_count"] = normalized.count("$")
        features["at_count"] = normalized.count("@")
        
        # Entropy (information theory)
        if char_counts:
            entropy = 0.0
            for count in char_counts.values():
                p = count / total_chars
                entropy -= p * math.log2(p)
            features["entropy"] = entropy
        else:
            features["entropy"] = 0.0
        
        # Maximum run length (consecutive same characters)
        max_run = 1
        current_run = 1
        for i in range(1, len(normalized)):
            if normalized[i] == normalized[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        features["max_run_length"] = max_run
        features["max_run_ratio"] = max_run / total_chars
        
        # URL encoding features
        features["url_encoded_chars"] = len(re.findall(r"%[0-9A-Fa-f]{2}", payload))
        features["url_encoded_ratio"] = features["url_encoded_chars"] / max(len(payload), 1)
        
        # Word-level features
        words = re.findall(r'\w+', normalized)
        features["word_count"] = len(words)
        features["unique_word_count"] = len(set(words))
        features["unique_word_ratio"] = len(set(words)) / max(len(words), 1) if words else 0.0
        features["avg_word_length"] = sum(len(w) for w in words) / max(len(words), 1) if words else 0.0
        
        # Non-ASCII characters
        features["non_ascii_count"] = sum(1 for c in normalized if ord(c) > 127)
        features["non_ascii_ratio"] = features["non_ascii_count"] / total_chars
        
        # Numeric features
        numbers = re.findall(r'\d+', normalized)
        features["number_count"] = len(numbers)
        features["number_total_digits"] = sum(len(n) for n in numbers)
        features["avg_number_length"] = sum(len(n) for n in numbers) / max(len(numbers), 1) if numbers else 0.0
        
        # Path-like features
        features["path_depth"] = normalized.count("/") + normalized.count("\\")
        features["has_extension"] = 1.0 if re.search(r'\.\w{2,4}($|\?|&)', normalized) else 0.0
        
        # Parameter features (query string)
        features["param_count"] = normalized.count("&") + (1 if "?" in normalized else 0)
        features["has_params"] = 1.0 if "?" in normalized else 0.0
        
        return features
    
    def extract_pattern_features(self, normalized: str) -> Dict[str, float]:
        """
        Extract pattern-based features (attack signature matches)
        Fast regex matching with compiled patterns
        """
        features = {}
        
        for attack_type, patterns in self.compiled_patterns.items():
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(normalized)
                match_count += len(matches)
            
            features[f"pattern_{attack_type}_count"] = match_count
            features[f"pattern_{attack_type}_binary"] = 1.0 if match_count > 0 else 0.0
        
        # Total suspicious pattern matches
        features["pattern_total_matches"] = sum(
            v for k, v in features.items() if k.endswith("_count")
        )
        features["pattern_diversity"] = sum(
            v for k, v in features.items() if k.endswith("_binary")
        )
        
        return features
    
    def extract_all_features(
        self,
        payloads: pd.Series,
        use_cache: bool = True,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Extract all features from payloads
        
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        # Normalize payloads
        if use_cache and feature_config.CACHE_FEATURES:
            normalized = payloads.apply(lambda x: self._normalize_cached(str(x)))
        else:
            normalized = payloads.apply(lambda x: self._normalize_payload(str(x)))
        
        # Extract statistical features
        stat_features_list = []
        pattern_features_list = []
        
        for orig, norm in zip(payloads, normalized):
            stat_feat = self.extract_statistical_features(str(orig), norm)
            pattern_feat = self.extract_pattern_features(norm)
            
            stat_features_list.append(stat_feat)
            pattern_features_list.append(pattern_feat)
        
        # Convert to DataFrames
        stat_df = pd.DataFrame(stat_features_list)
        pattern_df = pd.DataFrame(pattern_features_list)
        
        # Store feature names
        manual_features_names = list(stat_df.columns) + list(pattern_df.columns)
        
        # Combine manual features
        manual_features = np.hstack([stat_df.values, pattern_df.values])
        
        # Extract TF-IDF features (n-grams)
        if self.char_vectorizer is None:
            # Training mode: fit vectorizers
            self.char_vectorizer = TfidfVectorizer(
                analyzer="char",
                ngram_range=feature_config.CHAR_NGRAM_RANGE,
                max_features=feature_config.CHAR_NGRAM_MAX_FEATURES,
                sublinear_tf=feature_config.TFIDF_SUBLINEAR_TF,
                max_df=feature_config.TFIDF_MAX_DF,
                min_df=feature_config.TFIDF_MIN_DF,
                lowercase=True,
                strip_accents="unicode",
            )
            char_features = self.char_vectorizer.fit_transform(normalized)
            char_feature_names = [
                f"char_tfidf_{name}" for name in self.char_vectorizer.get_feature_names_out()
            ]
        else:
            # Inference mode: use fitted vectorizer
            char_features = self.char_vectorizer.transform(normalized)
            char_feature_names = [
                f"char_tfidf_{name}" for name in self.char_vectorizer.get_feature_names_out()
            ]
        
        # Word-level TF-IDF (optional, for better context)
        if self.word_vectorizer is None:
            self.word_vectorizer = TfidfVectorizer(
                analyzer="word",
                ngram_range=feature_config.WORD_NGRAM_RANGE,
                max_features=feature_config.WORD_NGRAM_MAX_FEATURES,
                sublinear_tf=feature_config.TFIDF_SUBLINEAR_TF,
                max_df=feature_config.TFIDF_MAX_DF,
                min_df=feature_config.TFIDF_MIN_DF,
                lowercase=True,
                token_pattern=r'\w+',
            )
            word_features = self.word_vectorizer.fit_transform(normalized)
            word_feature_names = [
                f"word_tfidf_{name}" for name in self.word_vectorizer.get_feature_names_out()
            ]
        else:
            word_features = self.word_vectorizer.transform(normalized)
            word_feature_names = [
                f"word_tfidf_{name}" for name in self.word_vectorizer.get_feature_names_out()
            ]
        
        # Combine all features
        all_features = sparse.hstack([
            manual_features,
            char_features,
            word_features,
        ])
        
        all_feature_names = manual_features_names + char_feature_names + word_feature_names
        self.feature_names = all_feature_names
        
        return all_features, all_feature_names
    
    def fit(self, X: pd.Series, y: np.ndarray) -> "FastFeatureExtractor":
        """
        Fit the feature extractor on training data
        
        Args:
            X: Training payloads
            y: Training labels
            
        Returns:
            Self
        """
        print("Extracting features...")
        features, feature_names = self.extract_all_features(X, use_cache=False)
        
        # Standardize manual features (first N features before TF-IDF)
        # TF-IDF features are already normalized
        print("Fitting scaler...")
        self.scaler = StandardScaler(with_mean=False)  # Sparse-compatible
        
        # Feature selection
        if feature_config.FEATURE_SELECTION:
            print(f"Selecting top {feature_config.MAX_FEATURES_FINAL} features...")
            self.feature_selector = SelectKBest(
                mutual_info_classif,
                k=min(feature_config.MAX_FEATURES_FINAL, features.shape[1]),
            )
            self.feature_selector.fit(features, y)
            
            # Get selected feature names
            selected_indices = self.feature_selector.get_support(indices=True)
            self.feature_names = [feature_names[i] for i in selected_indices]
        
        self.fitted = True
        return self
    
    def transform(self, X: pd.Series) -> np.ndarray:
        """
        Transform payloads to feature vectors
        
        Args:
            X: Payloads to transform
            
        Returns:
            Feature matrix
        """
        if not self.fitted:
            raise ValueError("FeatureExtractor must be fitted before transform")
        
        features, _ = self.extract_all_features(X, use_cache=True)
        
        # Apply feature selection
        if self.feature_selector is not None:
            features = self.feature_selector.transform(features)
        
        return features
    
    def fit_transform(self, X: pd.Series, y: np.ndarray) -> np.ndarray:
        """Fit and transform in one step"""
        self.fit(X, y)
        features, _ = self.extract_all_features(X, use_cache=False)
        
        if self.feature_selector is not None:
            features = self.feature_selector.transform(features)
        
        return features
    
    def save(self, filepath: str) -> None:
        """Save feature extractor to disk"""
        joblib.dump({
            "char_vectorizer": self.char_vectorizer,
            "word_vectorizer": self.word_vectorizer,
            "scaler": self.scaler,
            "feature_selector": self.feature_selector,
            "feature_names": self.feature_names,
            "fitted": self.fitted,
        }, filepath)
    
    def load(self, filepath: str) -> "FastFeatureExtractor":
        """Load feature extractor from disk"""
        data = joblib.load(filepath)
        self.char_vectorizer = data["char_vectorizer"]
        self.word_vectorizer = data["word_vectorizer"]
        self.scaler = data["scaler"]
        self.feature_selector = data["feature_selector"]
        self.feature_names = data["feature_names"]
        self.fitted = data["fitted"]
        return self


class StreamingFeatureExtractor:
    """Fit-free extractor for online updates with infinite vocabulary hashing."""

    def __init__(self, n_features: int = 2**14) -> None:
        self.n_features = n_features
        self.vectorizer = HashingVectorizer(
            n_features=n_features,
            alternate_sign=False,
            norm="l2",
            analyzer="char_wb",
            ngram_range=(3, 5),
            lowercase=True,
        )

    @staticmethod
    def _request_stats(payload: str) -> List[float]:
        text = payload or ""
        length = float(len(text))
        if length <= 0:
            return [0.0] * 10

        upper = sum(1 for c in text if c.isupper())
        digit = sum(1 for c in text if c.isdigit())
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        encoded = len(re.findall(r"%[0-9A-Fa-f]{2}", text))

        return [
            length,
            float(text.count("/")),
            float(text.count("?")),
            float(text.count("&")),
            float(text.count("=")),
            float(encoded),
            upper / length,
            digit / length,
            special / length,
            float(".." in text or "../" in text or "..\\" in text),
        ]

    def transform(self, payloads: pd.Series) -> csr_matrix:
        normalized = payloads.fillna("").astype(str)
        hashed = self.vectorizer.transform(normalized)
        stats = np.array([self._request_stats(payload) for payload in normalized], dtype=np.float32)
        stats_sparse = sparse.csr_matrix(stats)
        return sparse.hstack([hashed, stats_sparse], format="csr")


if __name__ == "__main__":
    # Test feature extraction
    from pathlib import Path
    
    base_dir = Path(__file__).parent
    test_payloads = pd.Series([
        "GET /index.html HTTP/1.1",
        "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
        "<script>alert('XSS')</script>",
        "GET /../../../etc/passwd HTTP/1.1",
        "GET /search?q=test&page=1 HTTP/1.1",
    ])
    
    extractor = FastFeatureExtractor()
    features, feature_names = extractor.extract_all_features(test_payloads, use_cache=False)
    
    print(f"Extracted {features.shape[1]} features from {features.shape[0]} payloads")
    print(f"Feature matrix shape: {features.shape}")
    print(f"Feature matrix sparsity: {1 - features.nnz / (features.shape[0] * features.shape[1]):.2%}")
