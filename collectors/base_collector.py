"""
Base Threat Intelligence Collector
Provides common functionality for all feed collectors
"""

import requests
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
import hashlib
import json
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CollectorError(Exception):
    """Base exception for collector errors"""
    pass


class APIKeyError(CollectorError):
    """Raised when API key is missing or invalid"""
    pass


class RateLimitError(CollectorError):
    """Raised when rate limit is exceeded"""
    pass


class NetworkError(CollectorError):
    """Raised when network connection fails"""
    pass


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
        self.collected_iocs = []
        self.errors = []
        self.warnings = []

        # Configure session with retry logic
        self.session = self._create_session()

        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = self.config.get('min_request_interval', 1.0)  # seconds

        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited': 0
        }

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set headers
        session.headers.update({
            'User-Agent': 'TIP-Collector/1.0',
            'Accept': 'application/json'
        })

        # Set timeout
        session.timeout = self.config.get('timeout', 30)

        return session

    def _rate_limit(self):
        """Implement rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling and rate limiting

        Args:
            url: URL to request
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for requests

        Returns:
            Response object or None on failure
        """
        self._rate_limit()
        self.stats['total_requests'] += 1

        try:
            response = self.session.request(method, url, **kwargs)

            # Check for rate limiting
            if response.status_code == 429:
                self.stats['rate_limited'] += 1
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limit exceeded. Retry after {retry_after}s")
                raise RateLimitError(f"Rate limit exceeded. Retry after {retry_after}s")

            # Check for success
            response.raise_for_status()
            self.stats['successful_requests'] += 1
            return response

        except requests.exceptions.Timeout as e:
            self.stats['failed_requests'] += 1
            self.errors.append(f"Request timeout: {url}")
            logger.error(f"Request timeout: {url}")
            return None

        except requests.exceptions.ConnectionError as e:
            self.stats['failed_requests'] += 1
            self.errors.append(f"Connection error: {url}")
            logger.error(f"Connection error: {url}")
            raise NetworkError(f"Failed to connect to {url}")

        except requests.exceptions.HTTPError as e:
            self.stats['failed_requests'] += 1
            self.errors.append(f"HTTP error {response.status_code}: {url}")
            logger.error(f"HTTP error {response.status_code}: {url}")
            return None

        except Exception as e:
            self.stats['failed_requests'] += 1
            self.errors.append(f"Unexpected error: {str(e)}")
            logger.error(f"Unexpected error during request: {str(e)}")
            return None

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
            'by_confidence': self._count_by_confidence(),
            'statistics': self.stats,
            'errors': len(self.errors),
            'warnings': len(self.warnings)
        }

    def get_errors(self) -> List[str]:
        """Return list of errors encountered"""
        return self.errors

    def get_warnings(self) -> List[str]:
        """Return list of warnings"""
        return self.warnings

    def clear_errors(self):
        """Clear error list"""
        self.errors = []
        self.warnings = []

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
