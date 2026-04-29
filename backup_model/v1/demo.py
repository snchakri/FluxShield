"""
Demo Script for Twilight WAF AI v1
Shows basic usage of the inference engine
"""

from inference import InferenceEngine


def demo_single_predictions():
    """Demo single payload predictions"""
    print("\n" + "=" * 80)
    print("DEMO: Single Payload Predictions")
    print("=" * 80)
    
    # Initialize engine
    engine = InferenceEngine()
    
    # Note: This demo shows the API usage
    # To actually run predictions, you need to train the model first
    print("\n⚠️  Note: Load model with engine.load_model() after training")
    print("For now, showing the API usage...\n")
    
    # Test payloads
    test_cases = [
        {
            "name": "Benign Request",
            "payload": "GET /index.html HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
            "expected": "benign",
        },
        {
            "name": "SQL Injection",
            "payload": "GET /login.php?user=admin' OR '1'='1'-- HTTP/1.1",
            "expected": "sqli",
        },
        {
            "name": "XSS Attack",
            "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
            "expected": "xss",
        },
        {
            "name": "Path Traversal",
            "payload": "GET /../../../etc/passwd HTTP/1.1",
            "expected": "path_traversal",
        },
        {
            "name": "Command Injection",
            "payload": "GET /cmd?exec=ls;cat /etc/passwd HTTP/1.1",
            "expected": "command_injection",
        },
        {
            "name": "SSRF Attack",
            "payload": "GET /fetch?url=http://localhost:8080/admin HTTP/1.1",
            "expected": "ssrf",
        },
        {
            "name": "SSTI Attack",
            "payload": "GET /render?template={{config}} HTTP/1.1",
            "expected": "ssti",
        },
    ]
    
    print("Test Cases:")
    print("-" * 80)
    for i, test in enumerate(test_cases, 1):
        print(f"\n{i}. {test['name']}")
        print(f"   Payload: {test['payload'][:60]}...")
        print(f"   Expected: {test['expected']}")
        # Uncomment after training model:
        # result = engine.predict_single(test['payload'])
        # print(f"   Predicted: {result.attack_type} ({result.confidence:.2%} confidence)")
        # print(f"   Latency: {result.latency_ms:.2f}ms")


def demo_batch_predictions():
    """Demo batch payload predictions"""
    print("\n" + "=" * 80)
    print("DEMO: Batch Payload Predictions (High Throughput)")
    print("=" * 80)
    
    engine = InferenceEngine()
    
    # Generate batch of payloads
    payloads = [
        "GET /page1.html HTTP/1.1",
        "GET /page2.html HTTP/1.1",
        "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
        "GET /page3.html HTTP/1.1",
        "<script>alert(document.cookie)</script>",
        "GET /page4.html HTTP/1.1",
        "GET /../../../etc/passwd HTTP/1.1",
        "POST /upload HTTP/1.1",
    ]
    
    print(f"\nProcessing {len(payloads)} payloads in batch...")
    print("\n⚠️  Note: Load model with engine.load_model() after training")
    
    # Uncomment after training model:
    # results = engine.predict_batch(payloads)
    # 
    # print("\nResults:")
    # for i, (payload, result) in enumerate(zip(payloads, results), 1):
    #     status = "🚨 BLOCKED" if result.is_malicious else "✅ ALLOWED"
    #     print(f"{i}. {status} - {result.attack_type} ({result.confidence:.2%})")
    #     print(f"   Payload: {payload[:50]}...")
    #     print(f"   Latency: {result.latency_ms:.2f}ms, Cached: {result.cached}")
    # 
    # engine.print_performance_metrics()


def demo_attack_labeler():
    """Demo attack labeling module"""
    print("\n" + "=" * 80)
    print("DEMO: Attack Labeler (Pattern-Based Detection)")
    print("=" * 80)
    
    from attack_labeler import AttackLabeler
    
    labeler = AttackLabeler()
    
    test_payloads = [
        "GET /index.html HTTP/1.1",
        "SELECT * FROM users WHERE id=1 OR 1=1",
        "<img src=x onerror=alert('XSS')>",
        "../../../../etc/passwd",
        "'; DROP TABLE users;--",
        "{{7*7}}",
        "http://internal-api.local/secret",
    ]
    
    print("\nPattern-Based Attack Detection Results:")
    print("-" * 80)
    
    for payload in test_payloads:
        attack_type, confidence = labeler.detect_attack_type(payload, return_confidence=True)
        print(f"\nPayload: {payload[:60]}")
        print(f"Detected: {attack_type} (confidence: {confidence:.2f})")


def demo_feature_extraction():
    """Demo feature extraction"""
    print("\n" + "=" * 80)
    print("DEMO: Feature Extraction")
    print("=" * 80)
    
    from feature_extraction import FastFeatureExtractor
    import pandas as pd
    
    extractor = FastFeatureExtractor()
    
    test_payloads = pd.Series([
        "GET /index.html HTTP/1.1",
        "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",
        "<script>alert('XSS')</script>",
    ])
    
    print("\nExtracting features from 3 sample payloads...")
    features, feature_names = extractor.extract_all_features(test_payloads)
    
    print(f"\nFeature Matrix Shape: {features.shape}")
    print(f"Number of Features: {features.shape[1]}")
    print(f"Sparsity: {1 - features.nnz / (features.shape[0] * features.shape[1]):.2%}")
    
    print(f"\nSample Feature Names (first 10):")
    for i, name in enumerate(feature_names[:10], 1):
        print(f"  {i}. {name}")


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("TWILIGHT WAF AI v1 - DEMO SCRIPT")
    print("=" * 80)
    print("\nThis demo shows the API usage of Twilight WAF AI")
    print("To run actual predictions, first train the model with: python train.py")
    
    # Run demos
    demo_attack_labeler()
    demo_feature_extraction()
    demo_single_predictions()
    demo_batch_predictions()
    
    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print("\nNext Steps:")
    print("  1. Train model: python train.py")
    print("  2. Test inference: Uncomment prediction code in this demo")
    print("  3. Deploy to production")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
