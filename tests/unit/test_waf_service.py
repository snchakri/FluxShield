import pytest
from src.wafai.models.request import Request, ThreatAnalysis, WAFRule
from src.wafai.services.waf_service import WAFService


class TestWAFService:
    """Test WAF Service"""
    
    def test_initialization(self):
        """Test WAF service initialization"""
        config = {'enabled': True}
        service = WAFService(config)
        
        assert service.config == config
        assert len(service.rules) > 0  # Should have default rules
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        service = WAFService({'enabled': True})
        
        request = Request(
            method='GET',
            path='/api/users?id=1 UNION SELECT password FROM users',
            ip_address='192.168.1.1'
        )
        
        analysis = service.analyze_request(request)
        
        assert analysis.is_threat is True
        assert analysis.confidence > 0
        assert len(analysis.rules_matched) > 0
    
    def test_xss_detection(self):
        """Test XSS detection"""
        service = WAFService({'enabled': True})
        
        request = Request(
            method='POST',
            path='/comment',
            body='<script>alert("xss")</script>',
            ip_address='192.168.1.2'
        )
        
        analysis = service.analyze_request(request)
        
        assert analysis.is_threat is True
        assert 'xss' in analysis.threat_type.lower() or analysis.confidence > 0
    
    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        service = WAFService({'enabled': True})
        
        request = Request(
            method='GET',
            path='/file?path=../../../etc/passwd',
            ip_address='192.168.1.3'
        )
        
        analysis = service.analyze_request(request)
        
        assert analysis.is_threat is True
        assert analysis.confidence > 0
    
    def test_clean_request(self):
        """Test clean request (no threat)"""
        service = WAFService({'enabled': True})
        
        request = Request(
            method='GET',
            path='/api/users',
            ip_address='192.168.1.4'
        )
        
        analysis = service.analyze_request(request)
        
        assert analysis.is_threat is False
        assert analysis.confidence == 0.0
        assert len(analysis.rules_matched) == 0
    
    def test_add_custom_rule(self):
        """Test adding custom WAF rule"""
        service = WAFService({'enabled': True})
        initial_count = len(service.rules)
        
        custom_rule = WAFRule(
            id='custom_1',
            name='Custom Rule',
            pattern='malicious',
            severity='high'
        )
        
        service.add_rule(custom_rule)
        
        assert len(service.rules) == initial_count + 1
