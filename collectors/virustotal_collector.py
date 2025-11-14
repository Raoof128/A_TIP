"""
VirusTotal Threat Feed Collector
Collects IOCs from VirusTotal's threat intelligence feeds
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from base_collector import BaseCollector, IOC
from typing import List
import logging
import requests
import time

logger = logging.getLogger(__name__)


class VirusTotalCollector(BaseCollector):
    """Collector for VirusTotal threat intelligence"""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.source = "VirusTotal"
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session.headers.update({
            'x-apikey': api_key,
            'Accept': 'application/json'
        })

    def collect(self, limit: int = 100) -> List[IOC]:
        """Collect recent malicious files and URLs from VirusTotal"""
        logger.info(f"Collecting from {self.source}...")

        try:
            # Collect malicious files
            self._collect_malicious_files(limit // 2)

            # Collect malicious URLs
            self._collect_malicious_urls(limit // 2)

            logger.info(f"Collected {len(self.collected_iocs)} IOCs from {self.source}")
            return self.collected_iocs

        except Exception as e:
            logger.error(f"Error collecting from {self.source}: {str(e)}")
            return []

    def _collect_malicious_files(self, limit: int):
        """Collect malicious file hashes"""
        try:
            # Query for recent malicious files
            url = f"{self.base_url}/intelligence/search"
            params = {
                'query': 'type:file positives:5+',
                'limit': limit
            }

            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    attributes = item.get('attributes', {})

                    # Get SHA256 hash
                    sha256 = attributes.get('sha256')
                    if sha256:
                        ioc = IOC(
                            ioc_type='sha256',
                            value=sha256,
                            source=self.source,
                            confidence=85,
                            tags=['malware', 'virustotal']
                        )
                        if self.validate_ioc(ioc):
                            self.collected_iocs.append(ioc)

            elif response.status_code == 403:
                logger.warning("VirusTotal API key may not have Intelligence Search permission")
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")

            time.sleep(1)  # Rate limiting

        except Exception as e:
            logger.error(f"Error collecting malicious files: {str(e)}")

    def _collect_malicious_urls(self, limit: int):
        """Collect malicious URLs"""
        try:
            url = f"{self.base_url}/intelligence/search"
            params = {
                'query': 'type:url positives:5+',
                'limit': limit
            }

            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    attributes = item.get('attributes', {})
                    url_value = attributes.get('url')

                    if url_value:
                        ioc = IOC(
                            ioc_type='url',
                            value=url_value,
                            source=self.source,
                            confidence=85,
                            tags=['malicious_url', 'virustotal']
                        )
                        if self.validate_ioc(ioc):
                            self.collected_iocs.append(ioc)

            time.sleep(1)  # Rate limiting

        except Exception as e:
            logger.error(f"Error collecting malicious URLs: {str(e)}")


# Example usage
if __name__ == "__main__":
    import os
    import json
    from elasticsearch import Elasticsearch

    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        print("ERROR: VT_API_KEY environment variable not set")
        print("Get your API key from: https://www.virustotal.com/gui/my-apikey")
        sys.exit(1)

    collector = VirusTotalCollector(api_key)
    iocs = collector.collect(limit=50)

    # Print metrics
    print("\n=== Collection Metrics ===")
    print(json.dumps(collector.get_metrics(), indent=2))

    # Print sample IOCs
    if iocs:
        print("\n=== Sample IOCs (first 5) ===")
        for ioc in iocs[:5]:
            print(f"  {ioc.ioc_type}: {ioc.value[:60]}... (confidence: {ioc.confidence})")
