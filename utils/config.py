"""
Configuration management for CyberNox
"""

import os
import yaml
from pathlib import Path

class Config:
    """Configuration manager for CyberNox toolkit"""
    
    def __init__(self, config_file="config.yml"):
        self.config_file = config_file
        self.config_path = Path(__file__).parent.parent / config_file
        self._config = self._load_config()
    
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            else:
                return self._get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self):
        """Return default configuration"""
        return {
            'general': {
                'debug': False,
                'log_level': 'INFO',
                'output_format': 'json',
                'max_threads': 10,
                'timeout': 5
            },
            'network': {
                'user_agent': 'CyberNox-Scanner/1.0',
                'default_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080],
                'socket_timeout': 3
            }
        }
    
    def get(self, key, default=None):
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def get_wordlist_path(self, wordlist_name):
        """Get full path to wordlist file"""
        base_path = Path(__file__).parent.parent / "data" / "wordlists"
        return base_path / wordlist_name

# Global config instance
config = Config()
