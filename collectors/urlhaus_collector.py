"""
URLhaus Threat Feed Collector
Collects malicious URLs from abuse.ch URLhaus
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from base_collector import BaseCollector, IOC
from typing import List
import logging
import requests
import csv
from io import StringIO

logger = logging.getLogger(__name__)


class URLhausCollector(BaseCollector):
    """Collector for URLhaus malicious URLs (no API key required)"""

    def __init__(self):
        super().__init__(api_key=None)
        self.source = "URLhaus"
        self.feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def collect(self, limit: int = 1000) -> List[IOC]:
        """Collect recent malicious URLs from URLhaus"""
        logger.info(f"Collecting from {self.source}...")

        try:
            # Download CSV feed
            response = self.session.get(self.feed_url, timeout=30)
            response.raise_for_status()

            # Parse CSV
            csv_data = response.text
            csv_reader = csv.DictReader(StringIO(csv_data), delimiter=',')

            count = 0
            for row in csv_reader:
                if count >= limit:
                    break

                # Skip comment lines
                if not row or list(row.values())[0].startswith('#'):
                    continue

                try:
                    url_value = row.get('url', '').strip()
                    threat = row.get('threat', 'unknown').strip()
                    tags_str = row.get('tags', '').strip()

                    if url_value:
                        # Parse tags
                        tags = [threat]
                        if tags_str:
                            tags.extend(tags_str.split(','))

                        # Determine confidence based on threat type
                        confidence = self._calculate_confidence(threat)

                        ioc = IOC(
                            ioc_type='url',
                            value=url_value,
                            source=self.source,
                            confidence=confidence,
                            tags=tags
                        )

                        if self.validate_ioc(ioc):
                            self.collected_iocs.append(ioc)
                            count += 1

                except Exception as e:
                    logger.debug(f"Error parsing row: {e}")
                    continue

            logger.info(f"Collected {len(self.collected_iocs)} IOCs from {self.source}")
            return self.collected_iocs

        except Exception as e:
            logger.error(f"Error collecting from {self.source}: {str(e)}")
            return []

    def _calculate_confidence(self, threat: str) -> int:
        """Calculate confidence score based on threat type"""
        threat_scores = {
            'malware_download': 90,
            'ransomware': 95,
            'trojan': 85,
            'botnet': 85,
            'exploit_kit': 90,
            'phishing': 80
        }

        threat_lower = threat.lower()
        for key, score in threat_scores.items():
            if key in threat_lower:
                return score

        return 70  # Default confidence


# Example usage
if __name__ == "__main__":
    import json
    from elasticsearch import Elasticsearch

    collector = URLhausCollector()
    iocs = collector.collect(limit=100)

    # Print metrics
    print("\n=== Collection Metrics ===")
    print(json.dumps(collector.get_metrics(), indent=2))

    # Print sample IOCs
    if iocs:
        print("\n=== Sample IOCs (first 10) ===")
        for ioc in iocs[:10]:
            print(f"  {ioc.value[:80]}")
            print(f"    Tags: {', '.join(ioc.tags[:3])}")
            print(f"    Confidence: {ioc.confidence}")
            print()
