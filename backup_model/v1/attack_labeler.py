"""
Attack Labeling Module
Classifies payloads into OWASP attack types using pattern matching and NLP
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config import owasp_config


class AttackLabeler:
    """
    Advanced attack type labeler using multi-strategy approach:
    1. Pattern-based detection (regex)
    2. Keyword-based detection
    3. Statistical anomaly detection
    4. Context-aware classification
    """
    
    def __init__(self):
        self.attack_types = owasp_config.ATTACK_TYPES
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
    
    def normalize_payload(self, payload: str) -> str:
        """
        Normalize payload for consistent pattern matching
        Multiple decoding passes to handle nested encoding
        """
        if not payload:
            return ""
        
        # Step 1: URL decode (multiple passes for nested encoding)
        decoded = payload
        for _ in range(3):  # Max 3 decode passes
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break
        
        # Step 2: HTML entity decode
        decoded = decoded.replace("&lt;", "<").replace("&gt;", ">")
        decoded = decoded.replace("&quot;", '"').replace("&amp;", "&")
        decoded = decoded.replace("&#x27;", "'").replace("&#x2F;", "/")
        
        # Step 3: Normalize whitespace
        decoded = re.sub(r'\s+', ' ', decoded)
        
        # Step 4: Convert to lowercase for case-insensitive matching
        # (but keep original for some patterns that are case-sensitive)
        return decoded
    
    def detect_attack_type(
        self,
        payload: str,
        normalized: Optional[str] = None,
        return_confidence: bool = False,
    ) -> Tuple[str, float]:
        """
        Detect attack type from payload
        
        Returns:
            Tuple of (attack_type, confidence_score)
        """
        if normalized is None:
            normalized = self.normalize_payload(payload)
        
        # Track scores for each attack type
        scores: Dict[str, float] = {attack: 0.0 for attack in self.attack_types.keys()}
        
        # Check each attack type
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(normalized)
                if matches:
                    # Score based on number of matches and pattern confidence
                    scores[attack_type] += len(matches) * 0.3 + 0.4
        
        # Additional heuristics
        scores = self._apply_heuristics(payload, normalized, scores)
        
        # Get top scoring attack type
        if max(scores.values()) > 0.1:
            top_attack = max(scores.items(), key=lambda x: x[1])
            if return_confidence:
                return top_attack[0], min(top_attack[1], 1.0)
            return top_attack[0], min(top_attack[1], 1.0)
        
        # Default to benign if no patterns matched strongly
        return "benign", 0.0
    
    def _apply_heuristics(
        self,
        payload: str,
        normalized: str,
        scores: Dict[str, float],
    ) -> Dict[str, float]:
        """Apply additional heuristic rules for better detection"""
        
        # SQL Injection heuristics
        sql_keywords = ["select", "union", "insert", "update", "delete", "drop", "create"]
        sql_count = sum(1 for kw in sql_keywords if kw in normalized.lower())
        if sql_count >= 2:
            scores["sqli"] += 0.3 * sql_count
        
        # XSS heuristics
        if "<" in normalized and ">" in normalized:
            tag_count = len(re.findall(r"<[^>]+>", normalized))
            if tag_count > 0:
                scores["xss"] += 0.2 * tag_count
        
        # Path traversal heuristics
        if "../" in normalized or "..\\" in normalized:
            traversal_count = normalized.count("../") + normalized.count("..\\")
            scores["path_traversal"] += 0.4 * traversal_count
        
        # Command injection heuristics
        shell_chars = [";", "|", "&", "`", "$"]
        shell_count = sum(1 for char in shell_chars if char in normalized)
        if shell_count >= 2:
            scores["command_injection"] += 0.3 * shell_count
        
        # SSRF heuristics
        if any(ip in normalized for ip in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]):
            scores["ssrf"] += 0.5
        
        # SSTI heuristics
        template_markers = ["{{", "}}", "{%", "%}", "${", "}"]
        if any(marker in normalized for marker in template_markers):
            scores["ssti"] += 0.4
        
        # Generic malicious indicators
        suspicious_count = 0
        suspicious_patterns = [
            r"(exec|eval|system|shell|passthru|popen|proc_open)",
            r"(base64_decode|gzinflate|str_rot13)",
            r"(phpinfo|system|passthru|shell_exec)",
        ]
        for pattern in suspicious_patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                suspicious_count += 1
        
        if suspicious_count >= 2:
            scores["malicious"] += 0.3 * suspicious_count
        
        return scores
    
    def label_dataset(
        self,
        df: pd.DataFrame,
        text_column: str = "text",
        label_column: str = "label",
        create_multi_label: bool = False,
    ) -> pd.DataFrame:
        """
        Label entire dataset with attack types
        
        Args:
            df: Input dataframe
            text_column: Column containing payloads
            label_column: Existing label column (benign/malicious)
            create_multi_label: If True, create columns for each attack type
            
        Returns:
            DataFrame with attack_type and confidence columns
        """
        df = df.copy()
        
        # Normalize all payloads
        df["normalized_payload"] = df[text_column].fillna("").astype(str).apply(
            self.normalize_payload
        )
        
        # Detect attack types
        results = df.apply(
            lambda row: self._label_row(row, text_column, label_column),
            axis=1,
        )
        
        df["attack_type"] = results.apply(lambda x: x[0])
        df["attack_confidence"] = results.apply(lambda x: x[1])
        
        # Convert attack type to numeric label
        df["attack_label"] = df["attack_type"].map(self.attack_types)
        
        if create_multi_label:
            # Create binary columns for each attack type
            for attack_type in self.attack_types.keys():
                df[f"is_{attack_type}"] = (df["attack_type"] == attack_type).astype(int)
        
        return df
    
    def _label_row(
        self,
        row: pd.Series,
        text_column: str,
        label_column: str,
    ) -> Tuple[str, float]:
        """Label a single row"""
        # If already labeled as benign, trust it
        if label_column in row and str(row[label_column]).lower() == "benign":
            return "benign", 1.0
        
        # Otherwise, detect attack type
        payload = str(row[text_column]) if text_column in row else ""
        normalized = str(row["normalized_payload"]) if "normalized_payload" in row else ""
        
        return self.detect_attack_type(payload, normalized, return_confidence=True)
    
    def get_attack_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
        """Get statistics on detected attack types"""
        stats = df["attack_type"].value_counts().to_frame("count")
        stats["percentage"] = (stats["count"] / len(df) * 100).round(2)
        stats["label_id"] = stats.index.map(self.attack_types)
        return stats.sort_values("count", ascending=False)


def enhance_dataset_with_attack_labels(
    csv_path: str,
    output_path: str,
    text_column: str = "text",
    label_column: str = "label",
) -> pd.DataFrame:
    """
    Main function to enhance dataset with attack type labels
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"Loaded {len(df)} rows")
    
    print("Initializing attack labeler...")
    labeler = AttackLabeler()
    
    print("Labeling attack types...")
    df_labeled = labeler.label_dataset(
        df,
        text_column=text_column,
        label_column=label_column,
        create_multi_label=True,
    )
    
    print("\nAttack Type Distribution:")
    print(labeler.get_attack_statistics(df_labeled))
    
    print(f"\nSaving labeled dataset to {output_path}...")
    df_labeled.to_csv(output_path, index=False)
    
    return df_labeled


if __name__ == "__main__":
    from pathlib import Path
    
    base_dir = Path(__file__).parent
    input_csv = base_dir.parent.parent / "datasets" / "huggingface_full.csv"
    output_csv = base_dir / "data" / "huggingface_labeled.csv"
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    
    enhance_dataset_with_attack_labels(
        str(input_csv),
        str(output_csv),
    )
