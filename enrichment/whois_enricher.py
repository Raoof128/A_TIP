"""
WHOIS Enrichment Module
Enriches domains and IPs with WHOIS data
"""

import logging
from typing import Dict, Optional
import socket

logger = logging.getLogger(__name__)


class WHOISEnricher:
    """Enriches IOCs with WHOIS information"""

    def __init__(self, cache_ttl: int = 86400):
        self.cache_ttl = cache_ttl
        self.cache = {}

    def enrich_domain(self, domain: str) -> Dict:
        """Enrich domain with WHOIS data"""
        try:
            # Try to use python-whois if available
            import whois
            w = whois.whois(domain)

            enrichment = {
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date[0]) if hasattr(w, 'creation_date') and w.creation_date else None,
                'expiration_date': str(w.expiration_date[0]) if hasattr(w, 'expiration_date') and w.expiration_date else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
            }

            return enrichment

        except ImportError:
            logger.warning("python-whois not installed. Install with: pip install python-whois")
            return {}
        except Exception as e:
            logger.debug(f"Error enriching domain {domain}: {str(e)}")
            return {}

    def enrich_ip(self, ip_address: str) -> Dict:
        """Enrich IP with WHOIS data (placeholder)"""
        try:
            # Basic reverse DNS lookup
            hostname = socket.gethostbyaddr(ip_address)[0]

            enrichment = {
                'hostname': hostname,
                'reverse_dns': hostname
            }

            return enrichment

        except Exception as e:
            logger.debug(f"Error enriching IP {ip_address}: {str(e)}")
            return {}

    def enrich_ioc(self, ioc: Dict) -> Dict:
        """Enrich IOC based on type"""
        if ioc['type'] == 'domain':
            whois_data = self.enrich_domain(ioc['value'])
            if whois_data:
                ioc['whois'] = whois_data

        elif ioc['type'] == 'ip':
            whois_data = self.enrich_ip(ioc['value'])
            if whois_data:
                ioc['whois'] = whois_data

        return ioc


# Example usage
if __name__ == "__main__":
    enricher = WHOISEnricher()

    # Test domain enrichment
    test_ioc = {
        'type': 'domain',
        'value': 'example.com'
    }

    enriched = enricher.enrich_ioc(test_ioc)
    print(f"Enriched IOC: {enriched}")
