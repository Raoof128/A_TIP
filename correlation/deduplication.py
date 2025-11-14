"""
IOC Deduplication and Correlation Engine
Eliminates duplicates and correlates related IOCs
"""

from typing import List, Dict, Set
from collections import defaultdict
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class DeduplicationEngine:
    """Handles IOC deduplication and correlation"""

    def __init__(self, es_client):
        self.es = es_client
        self.index = 'threat-intel-iocs'

    def deduplicate_batch(self, new_iocs: List[Dict]) -> Dict[str, List]:
        """
        Deduplicate incoming IOCs against existing database
        Returns: {'new': [...], 'updated': [...], 'duplicates': [...]}
        """
        results = {
            'new': [],
            'updated': [],
            'duplicates': []
        }

        for ioc in new_iocs:
            existing = self._find_existing(ioc['type'], ioc['value'])

            if not existing:
                # Completely new IOC
                results['new'].append(ioc)
            elif self._should_update(existing, ioc):
                # Existing IOC needs update (higher confidence, new tags, etc.)
                updated = self._merge_iocs(existing, ioc)
                results['updated'].append(updated)
            else:
                # Duplicate with no new information
                results['duplicates'].append(ioc)

        logger.info(f"Deduplication: {len(results['new'])} new, "
                   f"{len(results['updated'])} updated, "
                   f"{len(results['duplicates'])} duplicates")

        return results

    def _find_existing(self, ioc_type: str, value: str) -> Dict:
        """Search for existing IOC in Elasticsearch"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": ioc_type}},
                        {"term": {"value.keyword": value}}
                    ]
                }
            }
        }

        try:
            result = self.es.search(index=self.index, body=query)
            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_source']
        except Exception as e:
            logger.error(f"Error searching for existing IOC: {str(e)}")

        return None

    def _should_update(self, existing: Dict, new: Dict) -> bool:
        """Determine if existing IOC should be updated"""
        # Update if new IOC has higher confidence
        if new['confidence'] > existing['confidence']:
            return True

        # Update if new IOC has additional tags
        existing_tags = set(existing.get('tags', []))
        new_tags = set(new.get('tags', []))
        if new_tags - existing_tags:
            return True

        # Update if seen from new source
        if new['source'] != existing['source']:
            return True

        return False

    def _merge_iocs(self, existing: Dict, new: Dict) -> Dict:
        """Merge information from existing and new IOC"""
        merged = existing.copy()

        # Update confidence to higher value
        merged['confidence'] = max(existing['confidence'], new['confidence'])

        # Merge tags
        all_tags = set(existing.get('tags', [])) | set(new.get('tags', []))
        merged['tags'] = list(all_tags)

        # Add source correlation
        if 'sources' not in merged:
            merged['sources'] = [existing['source']]
        if new['source'] not in merged['sources']:
            merged['sources'].append(new['source'])

        # Update last_seen timestamp
        merged['last_seen'] = datetime.utcnow().isoformat()

        # Increment sighting count
        merged['sightings'] = merged.get('sightings', 1) + 1

        return merged

    def correlate_related_iocs(self, ioc: Dict) -> List[Dict]:
        """Find IOCs related to given IOC"""
        related = []

        if ioc['type'] == 'ip':
            # Find domains resolving to this IP
            related.extend(self._find_by_relationship('domain', 'resolves_to', ioc['value']))

        elif ioc['type'] == 'domain':
            # Find URLs on this domain
            related.extend(self._find_urls_for_domain(ioc['value']))
            # Find IP addresses for this domain
            related.extend(self._find_by_relationship('ip', 'resolved_by', ioc['value']))

        elif ioc['type'] in ['md5', 'sha256']:
            # Find related hashes (same malware family)
            related.extend(self._find_by_tags(ioc.get('tags', [])))

        return related

    def _find_by_relationship(self, ioc_type: str, relation: str, value: str) -> List[Dict]:
        """Find IOCs by relationship"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": ioc_type}},
                        {"term": {f"relationships.{relation}.keyword": value}}
                    ]
                }
            }
        }

        try:
            result = self.es.search(index=self.index, body=query, size=100)
            return [hit['_source'] for hit in result['hits']['hits']]
        except Exception as e:
            logger.error(f"Error finding related IOCs: {str(e)}")
            return []

    def _find_urls_for_domain(self, domain: str) -> List[Dict]:
        """Find URLs containing specific domain"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": "url"}},
                        {"wildcard": {"value": f"*{domain}*"}}
                    ]
                }
            }
        }

        try:
            result = self.es.search(index=self.index, body=query, size=50)
            return [hit['_source'] for hit in result['hits']['hits']]
        except Exception as e:
            logger.error(f"Error finding URLs for domain: {str(e)}")
            return []

    def _find_by_tags(self, tags: List[str]) -> List[Dict]:
        """Find IOCs with overlapping tags"""
        if not tags:
            return []

        query = {
            "query": {
                "bool": {
                    "should": [{"term": {"tags": tag}} for tag in tags],
                    "minimum_should_match": 2  # At least 2 matching tags
                }
            }
        }

        try:
            result = self.es.search(index=self.index, body=query, size=50)
            return [hit['_source'] for hit in result['hits']['hits']]
        except Exception as e:
            logger.error(f"Error finding by tags: {str(e)}")
            return []

    def create_index_if_not_exists(self):
        """Create Elasticsearch index with proper mapping"""
        mapping = {
            "mappings": {
                "properties": {
                    "ioc_id": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "source": {"type": "keyword"},
                    "sources": {"type": "keyword"},
                    "confidence": {"type": "integer"},
                    "threat_score": {"type": "integer"},
                    "severity": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "sightings": {"type": "integer"}
                }
            }
        }

        try:
            if not self.es.indices.exists(index=self.index):
                self.es.indices.create(index=self.index, body=mapping)
                logger.info(f"Created index: {self.index}")
        except Exception as e:
            logger.error(f"Error creating index: {str(e)}")


# Example usage
if __name__ == "__main__":
    from elasticsearch import Elasticsearch

    # Connect to Elasticsearch
    es = Elasticsearch(['http://localhost:9200'])

    # Initialize deduplication engine
    dedup = DeduplicationEngine(es)

    # Create index if needed
    dedup.create_index_if_not_exists()

    # Example IOCs
    test_iocs = [
        {
            'ioc_id': 'test1',
            'type': 'ip',
            'value': '192.168.1.100',
            'source': 'TestSource1',
            'confidence': 75,
            'tags': ['malware', 'test']
        },
        {
            'ioc_id': 'test2',
            'type': 'ip',
            'value': '192.168.1.100',  # Duplicate
            'source': 'TestSource2',
            'confidence': 85,  # Higher confidence
            'tags': ['botnet', 'test']
        }
    ]

    # Deduplicate
    results = dedup.deduplicate_batch(test_iocs)

    print(f"New: {len(results['new'])}")
    print(f"Updated: {len(results['updated'])}")
    print(f"Duplicates: {len(results['duplicates'])}")
