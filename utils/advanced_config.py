"""
Advanced configuration management for CyberNox
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from utils.logger import logger

@dataclass
class NetworkConfig:
    """Network configuration settings"""
    user_agent: str = "CyberNox-Scanner/1.0"
    timeout: int = 5
    max_retries: int = 3
    default_ports: list = None
    socket_timeout: int = 3
    
    def __post_init__(self):
        if self.default_ports is None:
            self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]

@dataclass
class ScanConfig:
    """Scanning configuration settings"""
    default_threads: int = 50
    max_threads: int = 200
    rate_limit: float = 10.0
    aggressive_mode: bool = False
    stealth_mode: bool = False

@dataclass
class ReportConfig:
    """Reporting configuration settings"""
    output_directory: str = "reports"
    template_directory: str = "templates"
    include_timestamps: bool = True
    include_metadata: bool = True
    auto_archive: bool = True

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    ssl_verify: bool = False
    follow_redirects: bool = True
    max_redirects: int = 5
    allow_dangerous_operations: bool = False

class ConfigManager:
    """Advanced configuration manager with environment variable support"""
    
    def __init__(self, config_file: str = "config.yml"):
        self.config_file = Path(config_file)
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        
        # Initialize configuration objects
        self.network = NetworkConfig()
        self.scan = ScanConfig()
        self.report = ReportConfig()
        self.security = SecurityConfig()
        
        # Load configuration
        self._load_configuration()
        self._load_environment_variables()
        
    def _load_configuration(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f) or {}
                
                # Update configuration objects
                if 'network' in config_data:
                    self._update_dataclass(self.network, config_data['network'])
                
                if 'scan' in config_data:
                    self._update_dataclass(self.scan, config_data['scan'])
                
                if 'report' in config_data:
                    self._update_dataclass(self.report, config_data['report'])
                
                if 'security' in config_data:
                    self._update_dataclass(self.security, config_data['security'])
                
                logger.info(f"Configuration loaded from {self.config_file}")
                
            except Exception as e:
                logger.warning(f"Failed to load configuration: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _update_dataclass(self, obj, data: dict):
        """Update dataclass object with dictionary data"""
        for key, value in data.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
    
    def _load_environment_variables(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'CYBERNOX_USER_AGENT': ('network', 'user_agent'),
            'CYBERNOX_TIMEOUT': ('network', 'timeout'),
            'CYBERNOX_THREADS': ('scan', 'default_threads'),
            'CYBERNOX_RATE_LIMIT': ('scan', 'rate_limit'),
            'CYBERNOX_OUTPUT_DIR': ('report', 'output_directory'),
            'CYBERNOX_SSL_VERIFY': ('security', 'ssl_verify'),
            'CYBERNOX_STEALTH_MODE': ('scan', 'stealth_mode'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                
                # Convert value to appropriate type
                if key in ['timeout', 'default_threads', 'max_threads', 'max_redirects']:
                    value = int(value)
                elif key in ['rate_limit']:
                    value = float(value)
                elif key in ['ssl_verify', 'follow_redirects', 'stealth_mode', 'aggressive_mode']:
                    value = value.lower() in ('true', '1', 'yes', 'on')
                
                # Set the value
                section_obj = getattr(self, section)
                setattr(section_obj, key, value)
                
                logger.debug(f"Environment variable {env_var} loaded: {key}={value}")
    
    def _create_default_config(self):
        """Create default configuration file"""
        try:
            config_data = {
                'network': asdict(self.network),
                'scan': asdict(self.scan),
                'report': asdict(self.report),
                'security': asdict(self.security)
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Default configuration created: {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to create default configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        try:
            keys = key.split('.')
            if len(keys) != 2:
                return default
            
            section, attr = keys
            section_obj = getattr(self, section, None)
            if section_obj:
                return getattr(section_obj, attr, default)
            
            return default
            
        except Exception:
            return default
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config_data = {
                'network': asdict(self.network),
                'scan': asdict(self.scan),
                'report': asdict(self.report),
                'security': asdict(self.security)
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            logger.info("Configuration saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate configuration settings"""
        issues = []
        
        # Validate network settings
        if self.network.timeout <= 0:
            issues.append("Network timeout must be positive")
        
        if self.network.socket_timeout <= 0:
            issues.append("Socket timeout must be positive")
        
        # Validate scan settings
        if self.scan.default_threads <= 0:
            issues.append("Default threads must be positive")
        
        if self.scan.rate_limit <= 0:
            issues.append("Rate limit must be positive")
        
        # Validate report settings
        if not self.report.output_directory:
            issues.append("Output directory cannot be empty")
        
        if issues:
            for issue in issues:
                logger.error(f"Configuration validation error: {issue}")
            return False
        
        logger.info("Configuration validation passed")
        return True

# Global configuration manager instance
config_manager = ConfigManager()

# Backward compatibility
def get_config():
    """Get the global configuration manager"""
    return config_manager

# Legacy function for backward compatibility
config = config_manager
