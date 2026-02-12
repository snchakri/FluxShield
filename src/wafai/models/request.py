from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class Request:
    """HTTP Request model"""
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    ip_address: str = "0.0.0.0"
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        """Convert request to dictionary"""
        return {
            'method': self.method,
            'path': self.path,
            'headers': self.headers,
            'body': self.body,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
        }


@dataclass
class ThreatAnalysis:
    """Threat analysis result model"""
    is_threat: bool
    confidence: float
    threat_type: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    rules_matched: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert analysis to dictionary"""
        return {
            'is_threat': self.is_threat,
            'confidence': self.confidence,
            'threat_type': self.threat_type,
            'details': self.details,
            'rules_matched': self.rules_matched,
        }


@dataclass
class WAFRule:
    """WAF Rule model"""
    id: str
    name: str
    pattern: str
    severity: str = "medium"  # low, medium, high, critical
    enabled: bool = True
    description: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert rule to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'pattern': self.pattern,
            'severity': self.severity,
            'enabled': self.enabled,
            'description': self.description,
        }
