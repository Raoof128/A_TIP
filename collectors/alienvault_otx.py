"""
AlienVault OTX Threat Feed Collector
Collects IOCs from AlienVault Open Threat Exchange
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from base_collector import BaseCollector, IOC
from typing import List
import logging
import json

logger = logging.getLogger(__name__)


class AlienVaultCollector(BaseCollector):
    """Collector for AlienVault OTX pulses"""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        try:
            from OTXv2 import OTXv2
            self.otx = OTXv2(api_key)
        except ImportError:
            logger.warning("OTXv2 library not installed. Install with: pip install OTXv2")
            self.otx = None
        self.source = "AlienVault OTX"

    def collect(self, limit: int = 100) -> List[IOC]:
        """Collect recent pulses from OTX"""
        logger.info(f"Collecting from {self.source}...")

        if not self.otx:
            logger.error("OTX client not initialized. Cannot collect.")
            return []

        try:
            # Get subscribed pulses
            pulses = self.otx.getall()

            pulse_count = 0
            for pulse in pulses:
                if pulse_count >= limit:
                    break

                pulse_count += 1
                pulse_name = pulse.get('name', 'Unknown')
                tags = pulse.get('tags', [])

                # Extract indicators from pulse
                for indicator in pulse.get('indicators', []):
                    ioc_type = self._map_indicator_type(indicator.get('type'))
                    value = indicator.get('indicator')

                    if ioc_type and value:
                        ioc = IOC(
                            ioc_type=ioc_type,
                            value=value,
                            source=self.source,
                            confidence=70,  # Default confidence for OTX
                            tags=tags + [pulse_name]
                        )

                        if self.validate_ioc(ioc):
                            self.collected_iocs.append(ioc)

            logger.info(f"Collected {len(self.collected_iocs)} IOCs from {self.source}")
            return self.collected_iocs

        except Exception as e:
            logger.error(f"Error collecting from {self.source}: {str(e)}")
            return []

    def _map_indicator_type(self, otx_type: str) -> str:
        """Map OTX indicator types to our IOC types"""
        type_mapping = {
            'IPv4': 'ip',
            'IPv6': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'URL': 'url',
            'FileHash-MD5': 'md5',
            'FileHash-SHA256': 'sha256',
            'email': 'email'
        }
        return type_mapping.get(otx_type)


# Example usage
if __name__ == "__main__":
    import os
    from elasticsearch import Elasticsearch

    # Initialize collector
    api_key = os.getenv('OTX_API_KEY')
    if not api_key:
        print("ERROR: OTX_API_KEY environment variable not set")
        print("Get your free API key from: https://otx.alienvault.com/api")
        sys.exit(1)

    collector = AlienVaultCollector(api_key)

    # Collect IOCs
    iocs = collector.collect(limit=50)

    # Save to Elasticsearch (if available)
    try:
        es = Elasticsearch(['http://localhost:9200'])
        if es.ping():
            collector.save_to_elasticsearch(iocs, es)
        else:
            print("Elasticsearch not available, skipping save")
    except Exception as e:
        print(f"Could not connect to Elasticsearch: {e}")

    # Print metrics
    print("\n=== Collection Metrics ===")
    print(json.dumps(collector.get_metrics(), indent=2))

    # Print sample IOCs
    if iocs:
        print("\n=== Sample IOCs (first 5) ===")
        for ioc in iocs[:5]:
            print(f"  {ioc.ioc_type}: {ioc.value} (confidence: {ioc.confidence})")
