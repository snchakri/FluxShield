"""Application class - Main application orchestrator"""

from .config import Config
from .logger import Logger
from .services.waf_service import WAFService
from .services.ai_service import AIService
from .controllers.waf_controller import WAFController


class Application:
    """Main WAFAI Application class"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize application
        
        Args:
            config_path: Optional path to configuration file
        """
        # Load configuration
        self.config = Config(config_path)
        
        # Setup logging
        logger_instance = Logger()
        logger_instance.setup(self.config.get('logging'))
        self.logger = logger_instance.get_logger('app')
        
        self.logger.info(f"Initializing {self.config.get('app.name')} v{self.config.get('app.version')}")
        
        # Initialize services
        self.waf_service = WAFService(self.config.get('waf'))
        self.ai_service = AIService(self.config.get('ai'))
        
        # Initialize controllers
        self.waf_controller = WAFController(self.waf_service, self.ai_service)
        
        self.logger.info("Application initialized successfully")
    
    def start(self):
        """Start the application"""
        self.logger.info("Application started")
        print(f"\n{self.config.get('app.name')} v{self.config.get('app.version')}")
        print("=" * 50)
        print("WAF AI System is running...")
        print(f"WAF Rules loaded: {len(self.waf_service.rules)}")
        print(f"AI Service enabled: {self.ai_service.enabled}")
        print("=" * 50)
    
    def stop(self):
        """Stop the application"""
        self.logger.info("Application stopped")
        print("\nShutting down...")
    
    def get_controller(self) -> WAFController:
        """Get the WAF controller instance"""
        return self.waf_controller
