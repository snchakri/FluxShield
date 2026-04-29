"""
Model Evaluation Module
Comprehensive metrics for WAF model assessment
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from config import owasp_config


class ModelEvaluator:
    """
    Comprehensive model evaluation for WAF classifier
    Focuses on metrics critical for security applications:
    - Low false negative rate (don't miss attacks)
    - Acceptable false positive rate (don't block legitimate traffic)
    - Per-attack-type performance
    - Latency metrics
    """
    
    def __init__(self, attack_types: Optional[Dict[str, int]] = None):
        self.attack_types = attack_types or owasp_config.ATTACK_TYPES
        self.inverse_attack_types = {v: k for k, v in self.attack_types.items()}
        
    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_pred_proba: Optional[np.ndarray] = None,
        class_names: Optional[List[str]] = None,
    ) -> Dict:
        """
        Comprehensive evaluation
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Prediction probabilities (if available)
            class_names: Class names for labeling
            
        Returns:
            Dictionary of metrics
        """
        if class_names is None:
            class_names = [self.inverse_attack_types.get(i, f"class_{i}") for i in range(len(self.attack_types))]
        
        metrics = {}
        
        # Overall metrics
        metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
        metrics["precision_macro"] = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        metrics["recall_macro"] = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        metrics["f1_macro"] = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
        
        metrics["precision_weighted"] = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
        metrics["recall_weighted"] = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
        metrics["f1_weighted"] = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        
        # Security-specific metrics
        # False Negative Rate (missed attacks) - CRITICAL
        benign_label = self.attack_types.get("benign", 0)
        attack_mask = y_true != benign_label
        
        if attack_mask.sum() > 0:
            false_negatives = ((y_true != benign_label) & (y_pred == benign_label)).sum()
            metrics["false_negative_rate"] = float(false_negatives / attack_mask.sum())
            metrics["attack_detection_rate"] = float(1 - metrics["false_negative_rate"])
        else:
            metrics["false_negative_rate"] = 0.0
            metrics["attack_detection_rate"] = 1.0
        
        # False Positive Rate (legitimate traffic blocked)
        benign_mask = y_true == benign_label
        if benign_mask.sum() > 0:
            false_positives = ((y_true == benign_label) & (y_pred != benign_label)).sum()
            metrics["false_positive_rate"] = float(false_positives / benign_mask.sum())
            metrics["legitimate_pass_rate"] = float(1 - metrics["false_positive_rate"])
        else:
            metrics["false_positive_rate"] = 0.0
            metrics["legitimate_pass_rate"] = 1.0
        
        # Per-class metrics
        report = classification_report(
            y_true,
            y_pred,
            target_names=class_names,
            output_dict=True,
            zero_division=0,
        )
        metrics["per_class"] = report
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics["confusion_matrix"] = cm.tolist()
        
        # AUC scores (if probabilities provided)
        if y_pred_proba is not None:
            try:
                # Multi-class AUC (one-vs-rest)
                metrics["auc_ovr_macro"] = float(roc_auc_score(
                    y_true, y_pred_proba, multi_class="ovr", average="macro"
                ))
                metrics["auc_ovr_weighted"] = float(roc_auc_score(
                    y_true, y_pred_proba, multi_class="ovr", average="weighted"
                ))
            except Exception as e:
                print(f"Could not compute AUC: {e}")
                metrics["auc_ovr_macro"] = None
                metrics["auc_ovr_weighted"] = None
        
        return metrics
    
    def print_metrics(self, metrics: Dict) -> None:
        """Pretty print evaluation metrics"""
        print("\n" + "=" * 80)
        print("MODEL EVALUATION METRICS")
        print("=" * 80)
        
        print("\n📊 Overall Performance:")
        print(f"  Accuracy:           {metrics['accuracy']:.4f}")
        print(f"  Precision (macro):  {metrics['precision_macro']:.4f}")
        print(f"  Recall (macro):     {metrics['recall_macro']:.4f}")
        print(f"  F1-Score (macro):   {metrics['f1_macro']:.4f}")
        print(f"  F1-Score (weighted):{metrics['f1_weighted']:.4f}")
        
        print("\n🛡️  Security Metrics (CRITICAL):")
        print(f"  Attack Detection Rate:    {metrics['attack_detection_rate']:.4f} ({metrics['attack_detection_rate']*100:.2f}%)")
        print(f"  False Negative Rate:      {metrics['false_negative_rate']:.4f} ({metrics['false_negative_rate']*100:.2f}%)")
        print(f"  Legitimate Pass Rate:     {metrics['legitimate_pass_rate']:.4f} ({metrics['legitimate_pass_rate']*100:.2f}%)")
        print(f"  False Positive Rate:      {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
        
        if metrics.get("auc_ovr_weighted") is not None:
            print(f"\n📈 AUC Metrics:")
            print(f"  AUC (OvR weighted):       {metrics['auc_ovr_weighted']:.4f}")
            print(f"  AUC (OvR macro):          {metrics['auc_ovr_macro']:.4f}")
        
        print("\n📋 Per-Attack-Type Performance:")
        per_class = metrics["per_class"]
        for class_name, class_metrics in per_class.items():
            if class_name not in ["accuracy", "macro avg", "weighted avg"]:
                print(f"  {class_name:20s}: P={class_metrics['precision']:.3f}, R={class_metrics['recall']:.3f}, F1={class_metrics['f1-score']:.3f}, Support={int(class_metrics['support'])}")
    
    def plot_confusion_matrix(
        self,
        cm: np.ndarray,
        class_names: List[str],
        output_path: Optional[str] = None,
        normalize: bool = False,
    ) -> None:
        """Plot confusion matrix"""
        if normalize:
            cm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
            fmt = ".2f"
            title = "Normalized Confusion Matrix"
        else:
            fmt = "d"
            title = "Confusion Matrix"
        
        plt.figure(figsize=(max(12, len(class_names)), max(10, len(class_names) * 0.8)))
        sns.heatmap(
            cm,
            annot=True,
            fmt=fmt,
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            cbar_kws={"label": "Count" if not normalize else "Proportion"},
        )
        plt.title(title)
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            print(f"Saved confusion matrix to {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_per_class_metrics(
        self,
        metrics: Dict,
        output_path: Optional[str] = None,
    ) -> None:
        """Plot per-class precision, recall, F1 scores"""
        per_class = metrics["per_class"]
        
        # Extract data
        classes = []
        precision = []
        recall = []
        f1 = []
        support = []
        
        for class_name, class_metrics in per_class.items():
            if class_name not in ["accuracy", "macro avg", "weighted avg"]:
                classes.append(class_name)
                precision.append(class_metrics["precision"])
                recall.append(class_metrics["recall"])
                f1.append(class_metrics["f1-score"])
                support.append(class_metrics["support"])
        
        # Create plot
        x = np.arange(len(classes))
        width = 0.25
        
        fig, ax = plt.subplots(figsize=(max(14, len(classes) * 0.8), 8))
        
        bars1 = ax.bar(x - width, precision, width, label="Precision", color="#4C78A8")
        bars2 = ax.bar(x, recall, width, label="Recall", color="#F58518")
        bars3 = ax.bar(x + width, f1, width, label="F1-Score", color="#54A24B")
        
        ax.set_xlabel("Attack Type")
        ax.set_ylabel("Score")
        ax.set_title("Per-Attack-Type Performance Metrics")
        ax.set_xticks(x)
        ax.set_xticklabels(classes, rotation=45, ha="right")
        ax.legend()
        ax.set_ylim([0, 1.1])
        ax.grid(axis="y", alpha=0.3)
        
        # Add value labels on bars
        for bars in [bars1, bars2, bars3]:
            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f"{height:.2f}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            print(f"Saved per-class metrics to {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def benchmark_inference_latency(
        self,
        model,
        X_test,
        n_runs: int = 100,
    ) -> Dict[str, float]:
        """
        Benchmark inference latency
        Critical for low-latency requirement
        """
        print(f"\n⏱️  Benchmarking inference latency ({n_runs} runs)...")
        
        latencies = []
        n_samples = X_test.shape[0]
        for _ in range(n_runs):
            start = time.perf_counter()
            _ = model.predict(X_test)
            end = time.perf_counter()
            latencies.append((end - start) / n_samples * 1000)  # ms per sample
        
        latency_metrics = {
            "mean_latency_ms": float(np.mean(latencies)),
            "median_latency_ms": float(np.median(latencies)),
            "p95_latency_ms": float(np.percentile(latencies, 95)),
            "p99_latency_ms": float(np.percentile(latencies, 99)),
            "min_latency_ms": float(np.min(latencies)),
            "max_latency_ms": float(np.max(latencies)),
            "std_latency_ms": float(np.std(latencies)),
        }
        
        print(f"  Mean latency:   {latency_metrics['mean_latency_ms']:.3f} ms/request")
        print(f"  Median latency: {latency_metrics['median_latency_ms']:.3f} ms/request")
        print(f"  P95 latency:    {latency_metrics['p95_latency_ms']:.3f} ms/request")
        print(f"  P99 latency:    {latency_metrics['p99_latency_ms']:.3f} ms/request")
        
        # Throughput
        throughput = 1000 / latency_metrics['mean_latency_ms']  # requests per second
        print(f"  Estimated throughput: {throughput:.0f} requests/second (single-threaded)")
        
        latency_metrics["throughput_rps"] = float(throughput)
        
        return latency_metrics
    
    def save_metrics(self, metrics: Dict, filepath: str) -> None:
        """Save metrics to JSON file"""
        with open(filepath, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"\nSaved metrics to {filepath}")


if __name__ == "__main__":
    # Test evaluator
    from sklearn.datasets import make_classification
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    
    # Generate dummy data
    X, y = make_classification(n_samples=1000, n_features=20, n_informative=15, n_classes=5, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train dummy model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    evaluator = ModelEvaluator()
    metrics = evaluator.evaluate(y_test, y_pred, y_pred_proba, class_names=[f"class_{i}" for i in range(5)])
    evaluator.print_metrics(metrics)
