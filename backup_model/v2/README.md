# Twilight WAF AI Neural v1

AutoKeras-powered neural WAF trained on the Hugging Face HTTP payload dataset.

## Goals

- Very low latency (<5ms target)
- Very high throughput (scale to 10k requests/sec with batching)
- Very high accuracy across all attack classes in the dataset

## Dataset

- Source: datasets/huggingface_full.csv
- Columns: label, text
- Labels are used as-is from the dataset and encoded to numeric IDs

## Project Structure

```
main_nn_wafai/v1/
├── config.py
├── data.py
├── evaluation.py
├── inference.py
├── train.py
├── requirements.txt
├── models/
└── logs/
```

## Install

```bash
cd main_nn_wafai/v1
pip install -r requirements.txt
```

## Train

```bash
python train.py
```

Artifacts:
- models/saved_model (TensorFlow SavedModel)
- models/model.tflite (optional TFLite export)
- logs/label_mapping.json
- logs/metrics.json

## Inference

```python
from inference import InferenceEngine

engine = InferenceEngine(prefer_tflite=False)
engine.load_model()

result = engine.predict_single("GET /index.html HTTP/1.1")
print(result)
```

## Notes on Throughput and Latency

- Use batching via predict_batch for sustained throughput.
- Set prefer_tflite=True if the TFLite export works for your environment.
- Tune config.py for max_tokens, sequence_length, and batch_size to meet targets.
