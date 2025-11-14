"""
GeoIP Enrichment Module
Enriches IP addresses with geographic location data
"""

import logging
from typing import Dict, Optional
import requests

logger = logging.getLogger(__name__)


class GeoIPEnricher:
    """Enriches IP addresses with geographic information"""

    def __init__(self, database_path: str = None):
        self.database_path = database_path
        self.use_maxmind = False

        # Try to use MaxMind GeoIP2 if available
        if database_path:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(database_path)
                self.use_maxmind = True
                logger.info("Using MaxMind GeoIP2 database")
            except Exception as e:
                logger.warning(f"Could not load MaxMind database: {e}")
                self.use_maxmind = False

    def enrich_ip(self, ip_address: str) -> Dict:
        """Enrich IP address with geographic data"""
        if self.use_maxmind:
            return self._enrich_with_maxmind(ip_address)
        else:
            return self._enrich_with_free_api(ip_address)

    def _enrich_with_maxmind(self, ip_address: str) -> Dict:
        """Enrich using MaxMind GeoIP2 database"""
        try:
            response = self.reader.city(ip_address)

            enrichment = {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'asn': None  # Would need separate ASN database
            }

            return enrichment

        except Exception as e:
            logger.debug(f"Error enriching IP {ip_address} with MaxMind: {str(e)}")
            return {}

    def _enrich_with_free_api(self, ip_address: str) -> Dict:
        """Enrich using free ip-api.com service"""
        try:
            # Using ip-api.com free tier (no API key required)
            # Limit: 45 requests per minute
            url = f"http://ip-api.com/json/{ip_address}"

            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    enrichment = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'asn': data.get('as'),
                        'org': data.get('org')
                    }

                    return enrichment

        except Exception as e:
            logger.debug(f"Error enriching IP {ip_address} with free API: {str(e)}")

        return {}

    def enrich_ioc(self, ioc: Dict) -> Dict:
        """Enrich IOC if it's an IP address"""
        if ioc['type'] == 'ip':
            geo_data = self.enrich_ip(ioc['value'])
            if geo_data:
                ioc['geoip'] = geo_data

                # Add country tag if not already present
                country_code = geo_data.get('country_code')
                if country_code:
                    country_tag = f"country:{country_code}"
                    if 'tags' not in ioc:
                        ioc['tags'] = []
                    if country_tag not in ioc['tags']:
                        ioc['tags'].append(country_tag)

        return ioc

    def batch_enrich(self, iocs: list) -> list:
        """Enrich multiple IOCs"""
        enriched_iocs = []

        for ioc in iocs:
            if ioc['type'] == 'ip':
                enriched_ioc = self.enrich_ioc(ioc)
                enriched_iocs.append(enriched_ioc)
            else:
                enriched_iocs.append(ioc)

        logger.info(f"GeoIP enriched {len(enriched_iocs)} IOCs")
        return enriched_iocs


# Example usage
if __name__ == "__main__":
    import json

    enricher = GeoIPEnricher()

    # Test IP enrichment
    test_ioc = {
        'type': 'ip',
        'value': '8.8.8.8',  # Google DNS
        'tags': ['test']
    }

    print("Enriching IP address...")
    enriched = enricher.enrich_ioc(test_ioc)

    print("\n=== GeoIP Enrichment Result ===")
    print(json.dumps(enriched, indent=2))

    # Test batch enrichment
    test_batch = [
        {'type': 'ip', 'value': '8.8.8.8'},
        {'type': 'ip', 'value': '1.1.1.1'},  # Cloudflare DNS
        {'type': 'domain', 'value': 'example.com'}  # Should skip
    ]

    print("\n=== Batch Enrichment ===")
    enriched_batch = enricher.batch_enrich(test_batch)
    for ioc in enriched_batch:
        if 'geoip' in ioc:
            print(f"{ioc['value']}: {ioc['geoip'].get('country')} ({ioc['geoip'].get('city')})")
