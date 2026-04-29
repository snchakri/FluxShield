"""Evaluation utilities for the neural WAF model."""

import json
from typing import Dict

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, f1_score

from config import runtime_config


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: Dict[int, str],
) -> Dict[str, float]:
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro")),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted")),
    }

    report = classification_report(
        y_true,
        y_pred,
        target_names=[labels[i] for i in range(len(labels))],
        output_dict=True,
        zero_division=0,
    )

    payload = {
        "metrics": metrics,
        "per_class": report,
    }

    with open(runtime_config.LOG_METRICS_JSON, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return metrics
