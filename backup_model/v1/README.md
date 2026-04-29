# Twilight WAF AI v1 🛡️

State-of-the-art Machine Learning-based Web Application Firewall using Auto-sklearn

**Optimized for: Very Low Latency ⚡ | Very High Throughput 🚀 | Very High Accuracy 🎯**

## Overview

Twilight WAF AI is a next-generation Web Application Firewall that uses automated machine learning to detect and classify web attacks covering OWASP Top 10 and beyond. It combines:

- **Auto-sklearn**: Automated algorithm selection and hyperparameter tuning
- **Advanced Feature Engineering**: Character/word n-grams, statistical features, pattern matching
- **Multi-class Classification**: Detects 18+ attack types including SQL injection, XSS, path traversal, command injection, SSRF, SSTI, and more
- **High-Performance Inference**: Sub-millisecond latency with caching and batch processing
- **Production-Ready**: Comprehensive evaluation, metrics, and deployment utilities

## Features

### Attack Detection Coverage

- **SQL Injection (SQLi)**: Detects various SQL injection techniques
- **Cross-Site Scripting (XSS)**: DOM, reflected, and stored XSS patterns
- **Path Traversal**: Directory traversal and local file inclusion
- **Command Injection**: OS command injection patterns
- **Remote Code Execution (RCE)**: Various RCE attempts
- **Server-Side Request Forgery (SSRF)**: Internal network exploitation
- **Server-Side Template Injection (SSTI)**: Template engine exploitation
- **XML External Entity (XXE)**: XML parser exploitation
- **NoSQL Injection**: MongoDB and other NoSQL injection patterns
- **LDAP Injection**: LDAP query manipulation
- **CRLF Injection**: HTTP response splitting
- **Local/Remote File Inclusion (LFI/RFI)**: File inclusion attacks
- **CSRF**: Cross-site request forgery detection
- **Generic Malicious Patterns**: Catches other suspicious patterns

### Performance Characteristics

- **Latency (Set A gate)**: average 5-10ms, worst-case 25-40ms
- **Throughput**: > 200 requests/second (single-threaded)
- **Accuracy (gate)**: >= 85% global
- **False Negative Rate**: < 5% (critical for security)
- **False Positive Rate**: < 10% (important for user experience)

### Self-Healing Runtime Notes

- Hot path classification is separated from online learning updates.
- Feedback enters an async learner queue with quarantine lane and trust gating.
- Teacher-student arbitration is used for bounded staleness and rollback decisions.
- On drift or learner instability, runtime can force teacher mode and rollback student checkpoints.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Input: HTTP Request                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Attack Labeler (Pattern Matching)               │
│  • URL Decoding (multi-pass)                                │
│  • Regex Pattern Matching                                   │
│  • Heuristic Analysis                                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           Fast Feature Extractor (Hybrid Approach)           │
│  • Statistical Features (50+)                               │
│  • Character N-grams (TF-IDF)                               │
│  • Word N-grams (TF-IDF)                                    │
│  • Pattern-based Features                                  │
│  • Feature Selection (Top 2000)                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Auto-sklearn Ensemble Classifier                │
│  • Automated Algorithm Selection                            │
│  • Hyperparameter Optimization                              │
│  • Ensemble Building                                        │
│  • Cross-Validation                                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           Output: Attack Type + Confidence Score             │
│  • is_malicious: bool                                       │
│  • attack_type: str (benign, sqli, xss, ...)               │
│  • confidence: float (0.0 - 1.0)                            │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone repository
cd twilight_hs/main_wafai/v1

# Install dependencies
pip install -r requirements.txt

# Note: If auto-sklearn installation fails, the system will fall back to
# an optimized Random Forest classifier
```

### Training

```bash
# Run full training pipeline
python train.py
```

This will:
1. Load and label the dataset with attack types
2. Create stratified train/val/test splits
3. Extract optimized features
4. Train auto-sklearn models (or fallback to Random Forest)
5. Evaluate on test set with comprehensive metrics
6. Save model artifacts and visualizations

**Training Time**: ~2-4 hours depending on dataset size and hardware

### Inference

```python
from inference import InferenceEngine

# Load trained model
engine = InferenceEngine()
engine.load_model()

# Predict single request
result = engine.predict_single("GET /admin.php?id=1' OR '1'='1 HTTP/1.1")
print(f"Malicious: {result.is_malicious}")
print(f"Attack Type: {result.attack_type}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Latency: {result.latency_ms:.2f}ms")

# Batch prediction (optimized)
payloads = [
    "GET /index.html HTTP/1.1",
    "<script>alert('XSS')</script>",
    "GET /../../../etc/passwd HTTP/1.1",
]
results = engine.predict_batch(payloads)

# Performance metrics
engine.print_performance_metrics()
```

### Configuration

Edit `config.py` to customize:

- **Feature Engineering**: N-gram ranges, TF-IDF parameters
- **Auto-sklearn**: Time limits, ensemble size, metric optimization
- **Inference**: Cache settings, batch size, worker threads
- **Training**: Data splits, class balancing, model version

## Project Structure

```
main_wafai/v1/
├── config.py                 # Configuration for all modules
├── attack_labeler.py          # Attack type classification and labeling
├── feature_extraction.py      # Fast feature extraction pipeline
├── train.py                   # Main training script
├── evaluation.py              # Model evaluation and metrics
├── inference.py               # High-performance inference engine
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── models/                    # Trained model artifacts
│   ├── waf_model.pkl         # Trained classifier
│   └── feature_extractor.pkl # Fitted feature extractor
├── logs/                      # Training logs and metrics
│   ├── metrics_v1.0.0.json
│   ├── confusion_matrix_v1.0.0.png
│   └── per_class_metrics_v1.0.0.png
└── data/                      # Processed datasets (optional)
```

## Advanced Usage

### Custom Attack Pattern Detection

Add custom patterns in `config.py`:

```python
ATTACK_PATTERNS["custom_attack"] = [
    r"your-regex-pattern-here",
    r"another-pattern",
]
```

### Fine-tuning Auto-sklearn

Adjust in `config.py`:

```python
automl_config.TIME_LEFT_FOR_THIS_TASK = 14400  # 4 hours
automl_config.ENSEMBLE_SIZE = 100
automl_config.METRIC = "f1_weighted"  # or "roc_auc", "precision", etc.
```

### Handling Imbalanced Data

The system automatically uses:
- Class weighting (balanced)
- Stratified splits
- Weighted F1 metric

For extreme imbalance, consider:
- SMOTE oversampling (add to config)
- Focal loss (custom metric)
- Cost-sensitive learning

### Production Deployment

#### Option 1: REST API (Flask)

```python
from flask import Flask, request, jsonify
from inference import InferenceEngine

app = Flask(__name__)
engine = InferenceEngine()
engine.load_model()

@app.route('/predict', methods=['POST'])
def predict():
    payload = request.get_data(as_text=True)
    result = engine.predict_single(payload)
    return jsonify({
        'malicious': result.is_malicious,
        'attack_type': result.attack_type,
        'confidence': result.confidence,
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True)
```

#### Option 2: Integration with Nginx/Apache

Use as a FastCGI or WSGI application

#### Option 3: Inline Python Module

Import directly in your application code

## Performance Optimization Tips

### For Lower Latency
1. Reduce `CHAR_NGRAM_MAX_FEATURES` (e.g., 5000)
2. Disable word n-grams (`WORD_NGRAM_RANGE = None`)
3. Enable feature caching (`CACHE_FEATURES = True`)
4. Use simpler base models (exclude slow estimators)

### For Higher Throughput
1. Increase `BATCH_SIZE` (e.g., 64)
2. Increase `MAX_WORKERS` for parallel processing
3. Use Redis for distributed caching
4. Deploy multiple instances with load balancing

### For Higher Accuracy
1. Increase auto-sklearn time budget
2. Increase `ENSEMBLE_SIZE` and `ENSEMBLE_NBEST`
3. Add more feature types
4. Collect more training data

## Evaluation Metrics

The system provides comprehensive metrics:

- **Accuracy**: Overall correctness
- **Precision/Recall/F1**: Per-class and averaged
- **AUC-ROC**: Area under ROC curve
- **False Negative Rate**: Critical for security (missed attacks)
- **False Positive Rate**: Important for usability (blocked legitimate traffic)
- **Confusion Matrix**: Detailed classification breakdown
- **Latency**: p50, p95, p99 percentiles
- **Throughput**: Requests per second

## Inspiration & Research

This project draws inspiration from several research sources in `research_sources/ai_waf/`:

- **ML-based-WAF**: TF-IDF character n-grams approach
- **Fwaf**: Logistic regression with balanced class weights
- **Advanced-WAF**: Hybrid signature + ML detection
- **Machine-Learning-WAF**: Random Forest with comprehensive features

**Key Innovations in Twilight WAF AI**:
1. **Auto-sklearn**: Automated model selection vs. manual algorithm choice
2. **Multi-class Classification**: 18+ attack types vs. binary classification
3. **Hybrid Features**: Statistical + TF-IDF + patterns vs. TF-IDF only
4. **Production-Optimized**: Caching, batching, latency benchmarks
5. **Comprehensive Evaluation**: Security-focused metrics (FNR, FPR)

## Troubleshooting

### Auto-sklearn Installation Issues

If auto-sklearn fails to install (common on Windows):
- The system automatically falls back to an optimized Random Forest
- For Linux/Mac: Use conda environment
- For Windows: Use WSL2 or Docker

### Memory Issues During Training

- Reduce `MAX_FEATURES_FINAL` in config
- Enable `FEATURE_SELECTION = True`
- Reduce `MAX_SAMPLES` for dataset sampling
- Increase swap space or use cloud instance

### Low Accuracy on Specific Attack Types

- Check class distribution (may need more samples)
- Add custom patterns for that attack type
- Adjust class weights
- Collect more diverse training data

## License

[Your License Here]

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## Citation

If you use this work in research, please cite:

```bibtex
@software{twilight_waf_ai,
  title={Twilight WAF AI: Auto-sklearn based Web Application Firewall},
  author={Your Name},
  year={2026},
  version={1.0.0}
}
```

## Contact

[Your Contact Information]

---

**Built with ❤️ for cybersecurity and ML**
