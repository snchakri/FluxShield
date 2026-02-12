import re
from typing import List, Optional
from ..models.request import Request, ThreatAnalysis, WAFRule
from ..logger import Logger


class WAFService:
    """WAF Service - Core Web Application Firewall logic"""
    
    def __init__(self, config: dict):
        """
        Initialize WAF Service
        
        Args:
            config: WAF configuration
        """
        self.config = config
        self.logger = Logger().get_logger('waf_service')
        self.rules: List[WAFRule] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default WAF rules"""
        default_rules = [
            WAFRule(
                id="sql_injection_1",
                name="SQL Injection Detection",
                pattern=r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b)",
                severity="critical",
                description="Detects basic SQL injection patterns"
            ),
            WAFRule(
                id="xss_1",
                name="XSS Detection",
                pattern=r"<script[^>]*>.*?</script>|javascript:",
                severity="high",
                description="Detects Cross-Site Scripting attempts"
            ),
            WAFRule(
                id="path_traversal_1",
                name="Path Traversal Detection",
                pattern=r"\.\./|\.\\.\\",
                severity="high",
                description="Detects directory traversal attempts"
            ),
        ]
        self.rules.extend(default_rules)
        self.logger.info(f"Loaded {len(default_rules)} default WAF rules")
    
    def add_rule(self, rule: WAFRule):
        """Add a new WAF rule"""
        self.rules.append(rule)
        self.logger.info(f"Added WAF rule: {rule.id}")
    
    def analyze_request(self, request: Request) -> ThreatAnalysis:
        """
        Analyze HTTP request for threats
        
        Args:
            request: HTTP request to analyze
            
        Returns:
            ThreatAnalysis result
        """
        self.logger.debug(f"Analyzing request: {request.method} {request.path}")
        
        matched_rules = []
        max_severity = 0
        threat_type = None
        
        # Check request path and body against rules
        content = f"{request.path} {request.body or ''}"
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            try:
                if re.search(rule.pattern, content, re.IGNORECASE):
                    matched_rules.append(rule.id)
                    
                    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                    rule_severity = severity_map.get(rule.severity, 0)
                    
                    if rule_severity > max_severity:
                        max_severity = rule_severity
                        threat_type = rule.name
                    
                    self.logger.warning(f"Rule matched: {rule.id} - {rule.name}")
            except re.error as e:
                self.logger.error(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        is_threat = len(matched_rules) > 0
        confidence = min(0.5 + (max_severity * 0.15), 1.0) if is_threat else 0.0
        
        analysis = ThreatAnalysis(
            is_threat=is_threat,
            confidence=confidence,
            threat_type=threat_type,
            rules_matched=matched_rules,
            details={'severity_level': max_severity}
        )
        
        if is_threat:
            self.logger.warning(f"Threat detected: {threat_type} (confidence: {confidence:.2f})")
        else:
            self.logger.debug("No threats detected")
        
        return analysis
