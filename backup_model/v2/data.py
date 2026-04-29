"""Dataset loading, cleaning, and splitting utilities."""

import json
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

from config import dataset_config, runtime_config


def load_dataset() -> pd.DataFrame:
    df = pd.read_csv(dataset_config.TRAIN_DATA_PATH, low_memory=False)

    if dataset_config.TEXT_COLUMN not in df.columns:
        raise ValueError(f"Missing text column: {dataset_config.TEXT_COLUMN}")
    if dataset_config.LABEL_COLUMN not in df.columns:
        raise ValueError(f"Missing label column: {dataset_config.LABEL_COLUMN}")

    df = df.dropna(subset=[dataset_config.TEXT_COLUMN, dataset_config.LABEL_COLUMN])

    if dataset_config.MAX_SAMPLES is not None and len(df) > dataset_config.MAX_SAMPLES:
        df = df.sample(n=dataset_config.MAX_SAMPLES, random_state=dataset_config.RANDOM_STATE)

    label_counts = df[dataset_config.LABEL_COLUMN].value_counts()
    valid_labels = label_counts[label_counts >= dataset_config.MIN_LABEL_COUNT].index
    df = df[df[dataset_config.LABEL_COLUMN].isin(valid_labels)].copy()

    df[dataset_config.TEXT_COLUMN] = df[dataset_config.TEXT_COLUMN].astype(str)
    df[dataset_config.LABEL_COLUMN] = df[dataset_config.LABEL_COLUMN].astype(str)

    return df


def encode_labels(df: pd.DataFrame) -> Tuple[np.ndarray, LabelEncoder]:
    encoder = LabelEncoder()
    y = encoder.fit_transform(df[dataset_config.LABEL_COLUMN])

    label_to_id = {label: int(idx) for idx, label in enumerate(encoder.classes_)}
    id_to_label = {int(idx): label for label, idx in label_to_id.items()}

    with open(runtime_config.LABELS_JSON, "w", encoding="utf-8") as handle:
        json.dump({"label_to_id": label_to_id, "id_to_label": id_to_label}, handle, indent=2)

    return y, encoder


def split_dataset(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    stratify = df[dataset_config.LABEL_COLUMN] if dataset_config.STRATIFY else None

    train_val_df, test_df = train_test_split(
        df,
        test_size=dataset_config.TEST_SIZE,
        random_state=dataset_config.RANDOM_STATE,
        stratify=stratify,
    )

    val_size_adjusted = dataset_config.VAL_SIZE / (1.0 - dataset_config.TEST_SIZE)
    stratify_train = train_val_df[dataset_config.LABEL_COLUMN] if dataset_config.STRATIFY else None

    train_df, val_df = train_test_split(
        train_val_df,
        test_size=val_size_adjusted,
        random_state=dataset_config.RANDOM_STATE,
        stratify=stratify_train,
    )

    return train_df, val_df, test_df


def compute_class_weights(y: np.ndarray) -> Dict[int, float]:
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    return {int(cls): float(weight) for cls, weight in zip(classes, weights)}
