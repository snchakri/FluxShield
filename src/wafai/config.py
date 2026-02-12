import os
import yaml
from typing import Dict, Any


class Config:
    """Configuration management class for WAFAI application"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to configuration file. If None, uses default config.
        """
        self._config = {}
        self._load_defaults()
        
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
    
    def _load_defaults(self):
        """Load default configuration"""
        self._config = {
            'app': {
                'name': 'WAFAI',
                'version': '0.1.0',
                'debug': False,
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'wafai.log',
            },
            'waf': {
                'enabled': True,
                'rules_path': 'config/rules.yaml',
                'max_request_size': 10485760,  # 10MB
            },
            'ai': {
                'enabled': True,
                'model': 'default',
                'confidence_threshold': 0.8,
            }
        }
    
    def _load_from_file(self, config_path: str):
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f)
            self._merge_config(file_config)
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing configuration"""
        def deep_merge(base: dict, update: dict):
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
        
        deep_merge(self._config, new_config)
    
    def get(self, key: str, default=None):
        """
        Get configuration value by dot-notation key
        
        Args:
            key: Configuration key in dot notation (e.g., 'app.name')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set configuration value by dot-notation key
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return self._config.copy()
