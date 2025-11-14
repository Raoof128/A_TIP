"""
Threat Intelligence Collectors
Collection of modules for gathering IOCs from various threat feeds
"""

from .base_collector import BaseCollector, IOC

__all__ = ['BaseCollector', 'IOC']
__version__ = '1.0.0'
