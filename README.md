# WAFAI - Web Application Firewall with AI

A modular, Agile-designed Web Application Firewall with AI-enhanced threat detection capabilities.

## Overview

WAFAI is a modern, Python-based Web Application Firewall that combines traditional rule-based threat detection with AI-powered analysis. The application follows clean architecture principles with clear separation of concerns and modular design.

## Features

- **Rule-Based Threat Detection**: Built-in rules for common threats
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Custom rule support

- **AI-Enhanced Analysis**: Machine learning-based threat detection
  - Confidence scoring
  - Pattern recognition
  - Anomaly detection

- **Modular Architecture**:
  - Clean separation of concerns
  - Easily extensible
  - Well-tested components

- **Comprehensive Logging**: Detailed logging for monitoring and debugging

## Project Structure

```
wafai_main/
├── src/wafai/              # Main application source
│   ├── models/             # Data models
│   ├── services/           # Business logic
│   ├── controllers/        # Request handlers
│   ├── config.py           # Configuration management
│   ├── logger.py           # Logging utilities
│   ├── app.py              # Application orchestrator
│   └── main.py             # Entry point
├── tests/                  # Test suite
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── config/                 # Configuration files
├── docs/                   # Documentation
├── setup.py                # Package setup
└── requirements.txt        # Dependencies
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/snchakri/wafai_main.git
   cd wafai_main
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## Usage

### Running the Application

Basic usage:
```bash
python -m src.wafai.main
```

With custom configuration:
```bash
python -m src.wafai.main --config config/config.yaml
```

Demo mode (with example threats):
```bash
python -m src.wafai.main --demo
```

### Using as a Library

```python
from src.wafai.app import Application
from src.wafai.models.request import Request

# Initialize application
app = Application()
app.start()

# Get controller
controller = app.get_controller()

# Analyze a request
request = Request(
    method='GET',
    path='/api/users?id=1',
    ip_address='192.168.1.1'
)

result = controller.process_request(request)
print(result)
```

## Configuration

Configuration is managed through YAML files or programmatically. See `config/config.yaml` for all available options.

Key configuration sections:
- `app`: Application settings
- `logging`: Logging configuration
- `waf`: WAF rules and settings
- `ai`: AI service configuration

## Testing

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=src/wafai tests/
```

Run specific test file:
```bash
pytest tests/unit/test_waf_service.py
```

## Architecture

### Layers

1. **Models Layer** (`models/`): Data structures and entities
   - Request models
   - Analysis results
   - WAF rules

2. **Services Layer** (`services/`): Business logic
   - WAF Service: Rule-based threat detection
   - AI Service: Machine learning analysis

3. **Controllers Layer** (`controllers/`): Request handling
   - WAF Controller: Orchestrates analysis pipeline

4. **Infrastructure** (`config.py`, `logger.py`): Cross-cutting concerns
   - Configuration management
   - Logging infrastructure

### Design Principles

- **Separation of Concerns**: Each module has a single, well-defined responsibility
- **Dependency Injection**: Services are injected into controllers
- **Testability**: All components are independently testable
- **Extensibility**: Easy to add new rules, services, or controllers

## Development

### Adding a New WAF Rule

```python
from src.wafai.models.request import WAFRule

rule = WAFRule(
    id='custom_rule_1',
    name='Custom Threat Detection',
    pattern=r'malicious_pattern',
    severity='high',
    description='Detects custom threat pattern'
)

waf_service.add_rule(rule)
```

### Extending the AI Service

Inherit from `AIService` and override the `_get_ai_confidence` method with your ML model:

```python
from src.wafai.services.ai_service import AIService

class CustomAIService(AIService):
    def _get_ai_confidence(self, request):
        # Your ML model inference here
        return model.predict(request)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests to ensure they pass
6. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues, questions, or contributions, please open an issue on GitHub.