import pytest
from src.wafai.app import Application


class TestApplication:
    """Test Application class"""
    
    def test_initialization(self):
        """Test application initialization"""
        app = Application()
        
        assert app.config is not None
        assert app.waf_service is not None
        assert app.ai_service is not None
        assert app.waf_controller is not None
    
    def test_get_controller(self):
        """Test getting controller instance"""
        app = Application()
        controller = app.get_controller()
        
        assert controller is not None
        assert controller == app.waf_controller
    
    def test_start_stop(self):
        """Test application start and stop"""
        app = Application()
        
        # Should not raise any exceptions
        app.start()
        app.stop()
