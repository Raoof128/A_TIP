"""
Base Threat Intelligence Collector
Provides common functionality for all feed collectors
"""

import requests
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any
import hashlib
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IOC:
    """Indicator of Compromise data structure"""

    def __init__(self, ioc_type: str, value: str, source: str,
                 confidence: int = 50, tags: List[str] = None):
        self.ioc_type = ioc_type  # ip, domain, url, hash, email
        self.value = value
        self.source = source
        self.confidence = confidence
        self.tags = tags or []
        self.first_seen = datetime.utcnow().isoformat()
        self.last_seen = datetime.utcnow().isoformat()
        self.ioc_id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate unique ID for IOC"""
        data = f"{self.ioc_type}:{self.value}:{self.source}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'ioc_id': self.ioc_id,
            'type': self.ioc_type,
            'value': self.value,
            'source': self.source,
            'confidence': self.confidence,
            'tags': self.tags,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen
        }


class BaseCollector(ABC):
    """Abstract base class for threat feed collectors"""

    def __init__(self, api_key: str = None, config: Dict = None):
        self.api_key = api_key
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'TIP-Collector/1.0'})
        self.collected_iocs = []

    @abstractmethod
    def collect(self) -> List[IOC]:
        """Implement in subclass to collect IOCs from specific feed"""
        pass

    def normalize_ioc(self, raw_data: Dict) -> IOC:
        """Normalize raw feed data to IOC format"""
        # Implement normalization logic based on feed format
        pass

    def validate_ioc(self, ioc: IOC) -> bool:
        """Validate IOC format and content"""
        import re

        validators = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
            'domain': r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
            'url': r'^https?://',
            'md5': r'^[a-f0-9]{32}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }

        if ioc.ioc_type in validators:
            return bool(re.match(validators[ioc.ioc_type], ioc.value, re.IGNORECASE))
        return True

    def save_to_elasticsearch(self, iocs: List[IOC], es_client):
        """Save IOCs to Elasticsearch"""
        from elasticsearch import helpers

        actions = [
            {
                '_index': 'threat-intel-iocs',
                '_id': ioc.ioc_id,
                '_source': ioc.to_dict()
            }
            for ioc in iocs
        ]

        success, failed = helpers.bulk(es_client, actions, raise_on_error=False)
        logger.info(f"Saved {success} IOCs to Elasticsearch, {failed} failed")
        return success, failed

    def get_metrics(self) -> Dict[str, int]:
        """Return collection metrics"""
        return {
            'total_collected': len(self.collected_iocs),
            'by_type': self._count_by_type(),
            'by_confidence': self._count_by_confidence()
        }

    def _count_by_type(self) -> Dict[str, int]:
        """Count IOCs by type"""
        counts = {}
        for ioc in self.collected_iocs:
            counts[ioc.ioc_type] = counts.get(ioc.ioc_type, 0) + 1
        return counts

    def _count_by_confidence(self) -> Dict[str, int]:
        """Count IOCs by confidence level"""
        ranges = {'high': 0, 'medium': 0, 'low': 0}
        for ioc in self.collected_iocs:
            if ioc.confidence >= 80:
                ranges['high'] += 1
            elif ioc.confidence >= 50:
                ranges['medium'] += 1
            else:
                ranges['low'] += 1
        return ranges


# Example usage
if __name__ == "__main__":
    import os
    from elasticsearch import Elasticsearch

    # This is a base class example
    print("Base Collector Framework loaded successfully")
    print("Use specific collectors like AlienVaultCollector to collect IOCs")
