"""
STIX 2.1 Exporter
Exports IOCs to STIX 2.1 format for threat sharing
"""

import logging
from datetime import datetime
from typing import List, Dict
import json
import uuid

logger = logging.getLogger(__name__)


class STIXExporter:
    """Export IOCs to STIX 2.1 format"""

    def __init__(self):
        self.identity = self._create_identity()

    def _create_identity(self) -> Dict:
        """Create STIX Identity object for the organization"""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "name": "Threat Intelligence Platform",
            "identity_class": "system",
            "description": "Automated Threat Intelligence Platform"
        }

    def ioc_to_indicator(self, ioc: Dict) -> Dict:
        """
        Convert IOC to STIX 2.1 Indicator

        Args:
            ioc: IOC dictionary from platform

        Returns:
            STIX 2.1 Indicator object
        """
        # Map IOC type to STIX pattern
        pattern = self._create_pattern(ioc)

        # Map severity to TLP
        tlp = self._map_severity_to_tlp(ioc.get('severity', 'MEDIUM'))

        # Create indicator
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": ioc.get('first_seen', datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
            "modified": ioc.get('last_seen', datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
            "name": f"{ioc['type'].upper()}: {ioc['value']}",
            "description": f"IOC detected from {ioc.get('source', 'Unknown')}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get('first_seen', datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
            "labels": self._create_labels(ioc),
            "confidence": ioc.get('confidence', 50),
            "created_by_ref": self.identity['id']
        }

        # Add optional fields
        if 'threat_score' in ioc:
            indicator['x_threat_score'] = ioc['threat_score']

        if 'sources' in ioc:
            indicator['x_sources'] = ioc['sources']

        if 'sightings' in ioc:
            indicator['x_sightings'] = ioc['sightings']

        return indicator

    def _create_pattern(self, ioc: Dict) -> str:
        """Create STIX pattern from IOC"""
        ioc_type = ioc['type']
        value = ioc['value']

        patterns = {
            'ip': f"[ipv4-addr:value = '{value}']",
            'domain': f"[domain-name:value = '{value}']",
            'url': f"[url:value = '{value}']",
            'md5': f"[file:hashes.MD5 = '{value}']",
            'sha256': f"[file:hashes.'SHA-256' = '{value}']",
            'email': f"[email-addr:value = '{value}']"
        }

        return patterns.get(ioc_type, f"[x-custom:value = '{value}']")

    def _map_severity_to_tlp(self, severity: str) -> str:
        """Map severity to Traffic Light Protocol marking"""
        mapping = {
            'CRITICAL': 'TLP:RED',
            'HIGH': 'TLP:AMBER',
            'MEDIUM': 'TLP:GREEN',
            'LOW': 'TLP:WHITE',
            'INFO': 'TLP:WHITE'
        }
        return mapping.get(severity, 'TLP:WHITE')

    def _create_labels(self, ioc: Dict) -> List[str]:
        """Create STIX labels from IOC tags"""
        labels = ['malicious-activity']

        # Add IOC type
        if ioc['type'] == 'ip':
            labels.append('anomalous-activity')
        elif ioc['type'] in ['md5', 'sha256']:
            labels.append('malware')
        elif ioc['type'] == 'url':
            labels.append('malicious-url')

        # Add tags
        tags = ioc.get('tags', [])
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in ['malware', 'ransomware', 'trojan', 'botnet']:
                if tag_lower not in labels:
                    labels.append(tag_lower)

        return labels

    def create_bundle(self, iocs: List[Dict]) -> Dict:
        """
        Create STIX 2.1 Bundle from multiple IOCs

        Args:
            iocs: List of IOC dictionaries

        Returns:
            STIX 2.1 Bundle
        """
        objects = [self.identity]

        for ioc in iocs:
            try:
                indicator = self.ioc_to_indicator(ioc)
                objects.append(indicator)
            except Exception as e:
                logger.error(f"Error converting IOC to STIX: {str(e)}")
                continue

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

        return bundle

    def export_to_file(self, iocs: List[Dict], filename: str):
        """
        Export IOCs to STIX file

        Args:
            iocs: List of IOC dictionaries
            filename: Output filename
        """
        bundle = self.create_bundle(iocs)

        with open(filename, 'w') as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Exported {len(iocs)} IOCs to {filename}")

    def export_to_json(self, iocs: List[Dict]) -> str:
        """
        Export IOCs to STIX JSON string

        Args:
            iocs: List of IOC dictionaries

        Returns:
            STIX JSON string
        """
        bundle = self.create_bundle(iocs)
        return json.dumps(bundle, indent=2)


class TAXIIServer:
    """
    Simple TAXII 2.1 Server implementation
    For serving threat intelligence via TAXII protocol
    """

    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.collections = {}

    def add_collection(self, collection_id: str, title: str, description: str):
        """Add a TAXII collection"""
        self.collections[collection_id] = {
            "id": collection_id,
            "title": title,
            "description": description,
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"]
        }

    def get_discovery(self) -> Dict:
        """Get TAXII discovery information"""
        return {
            "title": "Threat Intelligence Platform TAXII Server",
            "description": "TAXII 2.1 server for threat intelligence sharing",
            "contact": "admin@tip.local",
            "default": f"http://{self.host}:{self.port}/taxii2/",
            "api_roots": [
                f"http://{self.host}:{self.port}/taxii2/api/"
            ]
        }

    def get_api_root(self) -> Dict:
        """Get API root information"""
        return {
            "title": "TIP API Root",
            "description": "Main API root for threat intelligence",
            "versions": ["taxii-2.1"],
            "max_content_length": 10485760  # 10MB
        }

    def get_collections(self) -> Dict:
        """Get list of collections"""
        return {
            "collections": list(self.collections.values())
        }

    def get_collection(self, collection_id: str) -> Dict:
        """Get specific collection"""
        return self.collections.get(collection_id, {})


# Example usage
if __name__ == "__main__":
    # Example IOCs
    example_iocs = [
        {
            'type': 'ip',
            'value': '192.168.1.100',
            'source': 'AlienVault OTX',
            'confidence': 85,
            'threat_score': 75,
            'severity': 'HIGH',
            'tags': ['malware', 'botnet'],
            'first_seen': '2024-01-01T00:00:00.000Z',
            'last_seen': '2024-01-02T00:00:00.000Z',
            'sightings': 5
        },
        {
            'type': 'domain',
            'value': 'malicious.com',
            'source': 'URLhaus',
            'confidence': 90,
            'threat_score': 85,
            'severity': 'CRITICAL',
            'tags': ['phishing', 'malware'],
            'first_seen': '2024-01-01T00:00:00.000Z',
            'last_seen': '2024-01-02T00:00:00.000Z'
        }
    ]

    # Create exporter
    exporter = STIXExporter()

    # Export to file
    exporter.export_to_file(example_iocs, 'threat_intel.stix.json')
    print("Exported IOCs to threat_intel.stix.json")

    # Export to JSON string
    stix_json = exporter.export_to_json(example_iocs)
    print("\nSTIX Bundle (first 500 chars):")
    print(stix_json[:500] + "...")

    # Example TAXII server
    taxii = TAXIIServer()
    taxii.add_collection(
        "threat-intel",
        "Threat Intelligence",
        "Main threat intelligence collection"
    )

    print("\n\nTAXII Discovery:")
    print(json.dumps(taxii.get_discovery(), indent=2))
