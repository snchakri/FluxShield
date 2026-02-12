# WAFAI Quick Start Guide

This guide will help you get started with WAFAI in under 5 minutes.

## Prerequisites

- Python 3.8 or higher
- pip package manager

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/snchakri/wafai_main.git
cd wafai_main
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Install the Package

```bash
pip install -e .
```

## Quick Demo

Run the built-in demo to see WAFAI in action:

```bash
python -m src.wafai.main --demo
```

You should see output showing:
- ✓ Normal requests being allowed
- ✗ SQL injection attempts being blocked
- ✗ XSS attempts being blocked
- ✗ Path traversal attempts being blocked

## Basic Usage

### Using the Command Line

Start WAFAI with default configuration:

```bash
python -m src.wafai.main
```

With custom configuration:

```bash
python -m src.wafai.main --config config/config.yaml
```

### Using as a Python Library

```python
from src.wafai.app import Application
from src.wafai.models.request import Request

# Initialize the application
app = Application()
app.start()

# Get the WAF controller
controller = app.get_controller()

# Create a request to analyze
request = Request(
    method='GET',
    path='/api/users?id=1',
    ip_address='192.168.1.100'
)

# Analyze the request
result = controller.process_request(request)

# Check the result
if result['allowed']:
    print("✓ Request allowed")
else:
    print(f"✗ Request blocked: {result['analysis']['threat_type']}")
    print(f"  Confidence: {result['analysis']['confidence']:.2%}")

# Shutdown
app.stop()
```

## Testing Your Installation

Run the test suite to verify everything is working:

```bash
pytest tests/unit/ -v
```

Expected output: All 19 tests should pass.

## Configuration

### Quick Configuration Changes

Edit `config/config.yaml` to customize:

```yaml
# Enable/disable AI enhancement
ai:
  enabled: true
  confidence_threshold: 0.8

# Change logging level
logging:
  level: DEBUG  # INFO, WARNING, ERROR
  
# Adjust WAF settings
waf:
  enabled: true
  max_request_size: 10485760
```

## Common Use Cases

### 1. Analyze a Suspicious URL

```python
from src.wafai.app import Application
from src.wafai.models.request import Request

app = Application()
app.start()

suspicious_url = Request(
    method='GET',
    path='/admin?id=1 UNION SELECT password FROM users'
)

result = app.get_controller().process_request(suspicious_url)
print(f"Threat detected: {result['analysis']['is_threat']}")
```

### 2. Check POST Data

```python
post_request = Request(
    method='POST',
    path='/comment',
    body='<script>alert("XSS")</script>',
    ip_address='10.0.0.1'
)

result = app.get_controller().process_request(post_request)
```

### 3. Add Custom Rules

```python
from src.wafai.models.request import WAFRule

# Create a custom rule
custom_rule = WAFRule(
    id='my_rule_1',
    name='Sensitive File Access',
    pattern=r'\.env|\.git|\.ssh',
    severity='critical',
    description='Detects attempts to access sensitive files'
)

# Add to WAF service
app.waf_service.add_rule(custom_rule)
```

## Next Steps

- Read the [full README](../README.md) for detailed documentation
- Explore [Architecture documentation](ARCHITECTURE.md) to understand the design
- Check out the [test files](../tests/unit/) for more examples
- Customize rules in the WAF service for your specific needs

## Troubleshooting

### Issue: ModuleNotFoundError

**Solution**: Make sure you installed the package:
```bash
pip install -e .
```

### Issue: No module named 'pytest'

**Solution**: Install test dependencies:
```bash
pip install -r requirements.txt
```

### Issue: Import errors

**Solution**: Make sure you're running from the repository root:
```bash
cd /path/to/wafai_main
python -m src.wafai.main
```

## Getting Help

- Check the [README](../README.md) for comprehensive documentation
- Review test files for usage examples
- Open an issue on GitHub for bugs or questions

## What's Next?

Now that you have WAFAI running, you can:

1. **Integrate it into your application** - Use the library API
2. **Customize detection rules** - Add your own patterns
3. **Tune AI settings** - Adjust confidence thresholds
4. **Contribute** - Help improve the project

Happy security testing! 🔒
