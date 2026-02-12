import logging
import sys
from typing import Optional


class Logger:
    """Logging utility class for WAFAI application"""
    
    _instance = None
    _logger = None
    
    def __new__(cls):
        """Singleton pattern for Logger"""
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def setup(self, config: dict):
        """
        Setup logger with configuration
        
        Args:
            config: Logging configuration dictionary
        """
        if self._logger is not None:
            return self._logger
        
        level = getattr(logging, config.get('level', 'INFO'))
        log_format = config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = config.get('file')
        
        # Create logger
        self._logger = logging.getLogger('wafai')
        self._logger.setLevel(level)
        
        # Create formatter
        formatter = logging.Formatter(log_format)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)
        
        # File handler (optional)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)
        
        return self._logger
    
    def get_logger(self, name: Optional[str] = None):
        """
        Get logger instance
        
        Args:
            name: Logger name (optional)
            
        Returns:
            Logger instance
        """
        if self._logger is None:
            # Default setup if not configured
            self.setup({'level': 'INFO'})
        
        if name:
            return self._logger.getChild(name)
        return self._logger
