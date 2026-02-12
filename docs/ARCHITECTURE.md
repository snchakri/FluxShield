# WAFAI Architecture

## Overview

WAFAI follows a clean, layered architecture with clear separation of concerns. This document describes the architectural design and component interactions.

## Architecture Layers

```
┌─────────────────────────────────────────────────┐
│              Entry Point (main.py)              │
│           Command-line interface & Demo         │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│           Application (app.py)                  │
│         Orchestrator & Initialization           │
└──────────┬──────────────────────┬────────────────┘
           │                      │
┌──────────▼──────────┐  ┌────────▼───────────────┐
│  Infrastructure     │  │  Controllers Layer     │
│  - Config           │  │  - WAFController       │
│  - Logger           │  │                        │
└─────────────────────┘  └────────┬───────────────┘
                                  │
                         ┌────────▼────────┐
                         │  Services Layer │
                         │  - WAFService   │
                         │  - AIService    │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │  Models Layer   │
                         │  - Request      │
                         │  - Analysis     │
                         │  - Rules        │
                         └─────────────────┘
```

## Component Responsibilities

### 1. Entry Point (`main.py`)
- Command-line argument parsing
- Application lifecycle management
- Demo mode implementation
- User interface

### 2. Application Orchestrator (`app.py`)
- Dependency injection
- Component initialization
- Configuration loading
- Service coordination

### 3. Infrastructure

#### Config (`config.py`)
- Configuration management
- YAML file parsing
- Default configuration
- Dot-notation access to config values

#### Logger (`logger.py`)
- Centralized logging
- Singleton pattern
- Console and file logging
- Configurable log levels

### 4. Controllers Layer

#### WAFController (`controllers/waf_controller.py`)
- Request processing orchestration
- Service coordination
- Response formatting
- Decision making (allow/block)

### 5. Services Layer

#### WAFService (`services/waf_service.py`)
- Rule-based threat detection
- Pattern matching
- Rule management
- Confidence scoring

#### AIService (`services/ai_service.py`)
- AI-enhanced analysis
- Confidence boosting
- Future ML model integration point
- Heuristic analysis

### 6. Models Layer

#### Request Models (`models/request.py`)
- `Request`: HTTP request representation
- `ThreatAnalysis`: Analysis results
- `WAFRule`: Rule definitions
- Data validation and serialization

## Data Flow

### Request Processing Flow

1. **Request Input** → `WAFController.process_request()`
2. **Rule Analysis** → `WAFService.analyze_request()`
   - Pattern matching against rules
   - Threat identification
   - Base confidence calculation
3. **AI Enhancement** → `AIService.enhance_analysis()`
   - Additional heuristics
   - Confidence adjustment
   - Future ML inference
4. **Decision** → Controller determines allow/block
5. **Response** → Formatted result with analysis details

### Threat Detection Pipeline

```
Request
  │
  ├─► WAF Rule Check 1 ──► Match? ──► Add to matched_rules
  ├─► WAF Rule Check 2 ──► Match? ──► Add to matched_rules
  ├─► WAF Rule Check N ──► Match? ──► Add to matched_rules
  │
  └─► Calculate Base Confidence
        │
        └─► AI Enhancement
              │
              └─► Final Analysis
                    │
                    └─► Allow/Block Decision
```

## Design Patterns

### 1. Singleton Pattern
- **Logger**: Ensures single logging instance across application

### 2. Dependency Injection
- Services injected into controllers
- Configuration injected into services
- Enables testing and modularity

### 3. Strategy Pattern
- Different threat detection strategies (rule-based, AI)
- Easily extensible with new detection methods

### 4. Builder Pattern
- Configuration building from defaults and files
- Merge strategy for configuration

## Extension Points

### Adding New Threat Detection Rules

```python
from src.wafai.models.request import WAFRule

rule = WAFRule(
    id='custom_1',
    name='Custom Detection',
    pattern=r'pattern',
    severity='high'
)
waf_service.add_rule(rule)
```

### Adding Custom AI Logic

```python
from src.wafai.services.ai_service import AIService

class CustomAI(AIService):
    def _get_ai_confidence(self, request):
        # Custom ML model
        return model.predict(request)
```

### Adding New Controllers

```python
from src.wafai.controllers.waf_controller import WAFController

class CustomController(WAFController):
    def process_request(self, request):
        # Custom processing logic
        pass
```

## Testing Strategy

### Unit Tests
- Each component tested independently
- Mock dependencies
- Test coverage for all public methods

### Test Organization
```
tests/
├── unit/
│   ├── test_config.py       # Configuration tests
│   ├── test_waf_service.py  # WAF service tests
│   ├── test_ai_service.py   # AI service tests
│   └── test_app.py          # Application tests
└── integration/             # Future integration tests
```

## Configuration Management

### Configuration Sources (Priority Order)
1. Programmatic configuration (highest)
2. Configuration file (YAML)
3. Default values (lowest)

### Configuration Structure
```yaml
app:        # Application settings
logging:    # Logging configuration
waf:        # WAF service settings
ai:         # AI service settings
```

## Security Considerations

1. **Input Validation**: All request data validated
2. **Pattern Safety**: Regex patterns validated for safety
3. **Logging**: Sensitive data not logged
4. **Configuration**: Secure defaults
5. **Dependencies**: Minimal external dependencies

## Performance Considerations

1. **Rule Matching**: Optimized regex compilation
2. **Logging**: Asynchronous logging recommended for production
3. **Caching**: Future enhancement for rule compilation
4. **Scalability**: Stateless design enables horizontal scaling

## Future Enhancements

1. **ML Model Integration**: Replace heuristic AI with trained models
2. **Rule Learning**: Automatic rule generation from threats
3. **Real-time Updates**: Dynamic rule updates without restart
4. **Distributed Mode**: Multi-instance coordination
5. **Analytics Dashboard**: Web-based monitoring interface
6. **Performance Metrics**: Request processing time tracking
