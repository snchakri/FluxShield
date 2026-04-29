# HuggingFace WAF Dataset Analysis Summary

## Key Findings
- Class distribution: {'counts': {'benign': 8658, 'malicious': 3291}, 'ratio_max_min': 2.6308113035551504}
- Training readiness score: 92.89

## Feature Engineering Recommendations
- Use character n-grams (3-5) for robust detection of obfuscated payloads.
- Add URL decoding and normalization (percent-decoding, lowercase, strip repeated delimiters).
- Extract query parameter keys/values separately and encode key presence as binary features.
- Compute entropy, max run length, and special character density to capture obfuscation.
- Add keyword-based indicators for SQLi/XSS/RCE patterns and their counts.
- Separate HTTP method, path depth, and file extension features if present in text.
- Use TF-IDF with sublinear term frequency and max_df filtering for sparse robustness.
- Consider calibrated class weights or focal loss to manage imbalance.
