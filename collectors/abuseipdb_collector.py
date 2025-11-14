"""
AbuseIPDB Threat Feed Collector
Collects malicious IP addresses from AbuseIPDB
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


class AbuseIPDBCollector(BaseCollector):
    """Collector for AbuseIPDB malicious IPs"""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.source = "AbuseIPDB"
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session.headers.update({
            'Key': api_key,
            'Accept': 'application/json'
        })

    def collect(self, limit: int = 10000, confidence_minimum: int = 80) -> List[IOC]:
        """Collect blacklisted IPs from AbuseIPDB"""
        logger.info(f"Collecting from {self.source}...")

        try:
            # Get blacklisted IPs
            url = f"{self.base_url}/blacklist"
            params = {
                'confidenceMinimum': confidence_minimum,
                'limit': limit
            }

            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for item in data.get('data', []):
                    ip_address = item.get('ipAddress')
                    abuse_confidence = item.get('abuseConfidenceScore', 0)
                    country_code = item.get('countryCode', 'Unknown')

                    if ip_address:
                        # Map abuse confidence to our confidence scale
                        our_confidence = min(100, int(abuse_confidence))

                        # Determine tags based on confidence
                        tags = ['malicious_ip', f'country:{country_code}']
                        if abuse_confidence >= 90:
                            tags.append('high_risk')
                        elif abuse_confidence >= 75:
                            tags.append('medium_risk')

                        ioc = IOC(
                            ioc_type='ip',
                            value=ip_address,
                            source=self.source,
                            confidence=our_confidence,
                            tags=tags
                        )

                        if self.validate_ioc(ioc):
                            self.collected_iocs.append(ioc)

                logger.info(f"Collected {len(self.collected_iocs)} IOCs from {self.source}")

            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
            else:
                logger.error(f"AbuseIPDB API returned status {response.status_code}")

            return self.collected_iocs

        except Exception as e:
            logger.error(f"Error collecting from {self.source}: {str(e)}")
            return []

    def check_ip(self, ip_address: str) -> dict:
        """Check a specific IP address for abuse reports"""
        try:
            url = f"{self.base_url}/check"
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }

            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json().get('data', {})
            else:
                logger.error(f"Error checking IP {ip_address}: {response.status_code}")
                return {}

        except Exception as e:
            logger.error(f"Error checking IP: {str(e)}")
            return {}


# Example usage
if __name__ == "__main__":
    import os
    import json

    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        print("ERROR: ABUSEIPDB_API_KEY environment variable not set")
        print("Get your free API key from: https://www.abuseipdb.com/api")
        sys.exit(1)

    collector = AbuseIPDBCollector(api_key)
    iocs = collector.collect(limit=100, confidence_minimum=80)

    # Print metrics
    print("\n=== Collection Metrics ===")
    print(json.dumps(collector.get_metrics(), indent=2))

    # Print sample IOCs
    if iocs:
        print("\n=== Sample IOCs (first 10) ===")
        for ioc in iocs[:10]:
            print(f"  {ioc.value} (confidence: {ioc.confidence})")
            print(f"    Tags: {', '.join(ioc.tags)}")

    # Example: Check a specific IP
    if iocs:
        print("\n=== Detailed Check Example ===")
        test_ip = iocs[0].value
        details = collector.check_ip(test_ip)
        print(f"IP: {test_ip}")
        print(f"Abuse Score: {details.get('abuseConfidenceScore', 'N/A')}")
        print(f"Total Reports: {details.get('totalReports', 'N/A')}")
