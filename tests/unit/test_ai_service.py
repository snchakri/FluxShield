import pytest
from src.wafai.models.request import Request, ThreatAnalysis
from src.wafai.services.ai_service import AIService


class TestAIService:
    """Test AI Service"""
    
    def test_initialization_enabled(self):
        """Test AI service initialization when enabled"""
        config = {'enabled': True, 'confidence_threshold': 0.8}
        service = AIService(config)
        
        assert service.enabled is True
        assert service.confidence_threshold == 0.8
    
    def test_initialization_disabled(self):
        """Test AI service initialization when disabled"""
        config = {'enabled': False}
        service = AIService(config)
        
        assert service.enabled is False
    
    def test_enhance_analysis_disabled(self):
        """Test that enhancement is skipped when AI is disabled"""
        config = {'enabled': False}
        service = AIService(config)
        
        request = Request(method='GET', path='/test')
        base_analysis = ThreatAnalysis(is_threat=False, confidence=0.0)
        
        enhanced = service.enhance_analysis(request, base_analysis)
        
        # Should return the same analysis
        assert enhanced.is_threat == base_analysis.is_threat
        assert enhanced.confidence == base_analysis.confidence
    
    def test_enhance_analysis_enabled(self):
        """Test analysis enhancement when AI is enabled"""
        config = {'enabled': True, 'confidence_threshold': 0.8}
        service = AIService(config)
        
        request = Request(method='GET', path='/test')
        base_analysis = ThreatAnalysis(is_threat=False, confidence=0.0)
        
        enhanced = service.enhance_analysis(request, base_analysis)
        
        # Enhanced analysis should have AI confidence
        assert 'ai_confidence' in enhanced.details
        assert 'ai_enhanced' in enhanced.details
        assert enhanced.details['ai_enhanced'] is True
    
    def test_enhance_existing_threat(self):
        """Test enhancing an existing threat detection"""
        config = {'enabled': True, 'confidence_threshold': 0.8}
        service = AIService(config)
        
        request = Request(method='GET', path='/malicious')
        base_analysis = ThreatAnalysis(
            is_threat=True,
            confidence=0.6,
            threat_type='SQL Injection'
        )
        
        enhanced = service.enhance_analysis(request, base_analysis)
        
        # Should still be a threat
        assert enhanced.is_threat is True
        # Confidence should be at least as high as base
        assert enhanced.confidence >= base_analysis.confidence
