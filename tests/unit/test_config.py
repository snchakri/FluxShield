import pytest
from src.wafai.config import Config


class TestConfig:
    """Test Configuration class"""
    
    def test_default_config(self):
        """Test default configuration loading"""
        config = Config()
        
        assert config.get('app.name') == 'WAFAI'
        assert config.get('app.version') == '0.1.0'
        assert config.get('app.debug') is False
    
    def test_get_nested_config(self):
        """Test getting nested configuration values"""
        config = Config()
        
        assert config.get('logging.level') == 'INFO'
        assert config.get('waf.enabled') is True
        assert config.get('ai.confidence_threshold') == 0.8
    
    def test_get_with_default(self):
        """Test getting configuration with default value"""
        config = Config()
        
        assert config.get('nonexistent.key', 'default') == 'default'
        assert config.get('also.missing', None) is None
    
    def test_set_config(self):
        """Test setting configuration values"""
        config = Config()
        
        config.set('app.debug', True)
        assert config.get('app.debug') is True
        
        config.set('new.nested.value', 'test')
        assert config.get('new.nested.value') == 'test'
    
    def test_get_all(self):
        """Test getting all configuration"""
        config = Config()
        all_config = config.get_all()
        
        assert 'app' in all_config
        assert 'logging' in all_config
        assert 'waf' in all_config
        assert 'ai' in all_config
