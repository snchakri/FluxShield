"""Training pipeline for the AutoKeras-based WAF model."""

import json
import time
from typing import Dict, Tuple

import numpy as np

from config import autokeras_config, dataset_config, export_config, runtime_config
from data import compute_class_weights, encode_labels, load_dataset, split_dataset
from evaluation import evaluate_predictions


def _build_model(num_classes: int):
    import autokeras as ak

    input_node = ak.TextInput()
    text_block = ak.TextBlock(
        max_tokens=autokeras_config.MAX_TOKENS,
        sequence_length=autokeras_config.SEQUENCE_LENGTH,
        ngrams=autokeras_config.NGRAM_RANGE,
    )
    output_node = text_block(input_node)
    output_node = ak.ClassificationHead(
        num_classes=num_classes,
        dropout=autokeras_config.DROPOUT_RATE,
    )(output_node)

    model = ak.AutoModel(
        inputs=input_node,
        outputs=output_node,
        max_trials=autokeras_config.MAX_TRIALS,
        tuner=autokeras_config.TUNER,
        overwrite=autokeras_config.OVERWRITE,
        project_name=autokeras_config.PROJECT_NAME,
        directory=str(autokeras_config.DIRECTORY),
    )

    return model


def _export_tflite(saved_model_dir: str) -> None:
    import tensorflow as tf

    if not export_config.ENABLE_TFLITE_EXPORT:
        return

    converter = tf.lite.TFLiteConverter.from_saved_model(saved_model_dir)
    if export_config.TFLITE_QUANTIZE:
        converter.optimizations = [tf.lite.Optimize.DEFAULT]

    tflite_model = converter.convert()
    with open(export_config.TFLITE_PATH, "wb") as handle:
        handle.write(tflite_model)


def train() -> Dict[str, float]:
    df = load_dataset()
    train_df, val_df, test_df = split_dataset(df)

    _, label_encoder = encode_labels(df)
    label_map = {int(idx): label for idx, label in enumerate(label_encoder.classes_)}

    train_texts = train_df[dataset_config.TEXT_COLUMN].to_numpy()
    val_texts = val_df[dataset_config.TEXT_COLUMN].to_numpy()
    test_texts = test_df[dataset_config.TEXT_COLUMN].to_numpy()

    y_train = label_encoder.transform(train_df[dataset_config.LABEL_COLUMN])
    y_val = label_encoder.transform(val_df[dataset_config.LABEL_COLUMN])
    y_test = label_encoder.transform(test_df[dataset_config.LABEL_COLUMN])

    class_weights = None
    if autokeras_config.CLASS_WEIGHT:
        class_weights = compute_class_weights(y_train)

    model = _build_model(num_classes=len(label_encoder.classes_))

    callbacks = []
    try:
        import tensorflow as tf

        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor="val_accuracy",
                patience=autokeras_config.EARLY_STOPPING_PATIENCE,
                restore_best_weights=True,
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor="val_loss",
                factor=0.5,
                patience=1,
                min_lr=1e-5,
            ),
        ]
    except Exception:
        callbacks = []

    start = time.time()
    model.fit(
        train_texts,
        y_train,
        validation_data=(val_texts, y_val),
        epochs=autokeras_config.EPOCHS,
        batch_size=autokeras_config.BATCH_SIZE,
        callbacks=callbacks,
        class_weight=class_weights,
        verbose=1,
    )
    train_seconds = time.time() - start

    exported = model.export_model()
    exported.save(str(export_config.SAVED_MODEL_DIR), include_optimizer=False)
    _export_tflite(str(export_config.SAVED_MODEL_DIR))

    y_pred_probs = exported.predict(test_texts, batch_size=autokeras_config.BATCH_SIZE)
    y_pred = np.argmax(y_pred_probs, axis=1)

    metrics = evaluate_predictions(y_test, y_pred, label_map)

    with open(runtime_config.LOG_METRICS_JSON, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    payload["training_seconds"] = float(train_seconds)

    with open(runtime_config.LOG_METRICS_JSON, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return metrics


if __name__ == "__main__":
    results = train()
    print("Training complete:")
    for key, value in results.items():
        print(f"{key}: {value:.4f}")
