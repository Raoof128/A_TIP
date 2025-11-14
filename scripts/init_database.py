#!/usr/bin/env python3
"""
Threat Intelligence Platform - Database Initialization Script
Initializes Elasticsearch indices with proper mappings and settings
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DatabaseInitializer:
    """Initialize and manage Elasticsearch database"""

    def __init__(self, es_url: str = "http://localhost:9200"):
        """
        Initialize database manager

        Args:
            es_url: Elasticsearch URL
        """
        self.es_url = es_url.rstrip('/')
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with retry logic"""
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def check_connection(self) -> bool:
        """Check if Elasticsearch is reachable"""
        try:
            response = self.session.get(f"{self.es_url}/_cluster/health", timeout=10)
            if response.status_code == 200:
                health = response.json()
                print(f"✓ Connected to Elasticsearch (status: {health.get('status', 'unknown')})")
                return True
            else:
                print(f"✗ Elasticsearch returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Cannot connect to Elasticsearch: {e}")
            return False

    def get_ioc_index_mapping(self) -> Dict:
        """
        Get the mapping definition for IOC index

        Returns:
            Index mapping configuration
        """
        return {
            "settings": {
                "number_of_shards": 3,
                "number_of_replicas": 1,
                "refresh_interval": "30s",
                "index": {
                    "max_result_window": 50000,
                    "lifecycle": {
                        "name": "threat-intel-policy",
                        "rollover_alias": "threat-intel-iocs"
                    }
                },
                "analysis": {
                    "analyzer": {
                        "lowercase_keyword": {
                            "type": "custom",
                            "tokenizer": "keyword",
                            "filter": ["lowercase"]
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    "value": {
                        "type": "keyword",
                        "normalizer": "lowercase"
                    },
                    "type": {
                        "type": "keyword"
                    },
                    "source": {
                        "type": "keyword"
                    },
                    "first_seen": {
                        "type": "date"
                    },
                    "last_seen": {
                        "type": "date"
                    },
                    "threat_score": {
                        "type": "float"
                    },
                    "confidence": {
                        "type": "integer"
                    },
                    "severity": {
                        "type": "keyword"
                    },
                    "tags": {
                        "type": "keyword"
                    },
                    "description": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "references": {
                        "type": "keyword"
                    },
                    "enrichment": {
                        "properties": {
                            "whois": {
                                "properties": {
                                    "registrar": {"type": "keyword"},
                                    "creation_date": {"type": "date"},
                                    "expiration_date": {"type": "date"},
                                    "registrant": {"type": "text"}
                                }
                            },
                            "geolocation": {
                                "properties": {
                                    "country": {"type": "keyword"},
                                    "country_code": {"type": "keyword"},
                                    "city": {"type": "keyword"},
                                    "latitude": {"type": "float"},
                                    "longitude": {"type": "float"},
                                    "asn": {"type": "keyword"},
                                    "as_org": {"type": "text"}
                                }
                            },
                            "reputation": {
                                "properties": {
                                    "score": {"type": "integer"},
                                    "reports": {"type": "integer"},
                                    "last_reported": {"type": "date"}
                                }
                            }
                        }
                    },
                    "correlation": {
                        "properties": {
                            "related_iocs": {"type": "keyword"},
                            "campaign_id": {"type": "keyword"},
                            "threat_actor": {"type": "keyword"},
                            "malware_family": {"type": "keyword"}
                        }
                    },
                    "metadata": {
                        "properties": {
                            "created_at": {"type": "date"},
                            "updated_at": {"type": "date"},
                            "version": {"type": "integer"},
                            "source_url": {"type": "keyword"},
                            "analyst_notes": {"type": "text"}
                        }
                    }
                }
            }
        }

    def create_index(self, index_name: str, mapping: Dict, force: bool = False) -> bool:
        """
        Create an index with the given mapping

        Args:
            index_name: Name of the index to create
            mapping: Index mapping and settings
            force: If True, delete existing index first

        Returns:
            True if successful, False otherwise
        """
        # Check if index exists
        check_response = self.session.head(f"{self.es_url}/{index_name}")

        if check_response.status_code == 200:
            if force:
                print(f"⚠ Index '{index_name}' exists, deleting...")
                delete_response = self.session.delete(f"{self.es_url}/{index_name}")
                if delete_response.status_code not in [200, 404]:
                    print(f"✗ Failed to delete index: {delete_response.text}")
                    return False
                print(f"✓ Index deleted")
            else:
                print(f"⚠ Index '{index_name}' already exists (use --force to recreate)")
                return False

        # Create index
        print(f"Creating index '{index_name}'...")
        response = self.session.put(
            f"{self.es_url}/{index_name}",
            json=mapping,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code in [200, 201]:
            print(f"✓ Index '{index_name}' created successfully")
            return True
        else:
            print(f"✗ Failed to create index: {response.text}")
            return False

    def create_lifecycle_policy(self) -> bool:
        """Create index lifecycle management policy"""
        policy = {
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "rollover": {
                                "max_age": "90d",
                                "max_size": "50gb"
                            },
                            "set_priority": {
                                "priority": 100
                            }
                        }
                    },
                    "warm": {
                        "min_age": "30d",
                        "actions": {
                            "forcemerge": {
                                "max_num_segments": 1
                            },
                            "set_priority": {
                                "priority": 50
                            }
                        }
                    },
                    "cold": {
                        "min_age": "90d",
                        "actions": {
                            "set_priority": {
                                "priority": 0
                            }
                        }
                    },
                    "delete": {
                        "min_age": "365d",
                        "actions": {
                            "delete": {}
                        }
                    }
                }
            }
        }

        print("Creating lifecycle policy...")
        response = self.session.put(
            f"{self.es_url}/_ilm/policy/threat-intel-policy",
            json=policy,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code in [200, 201]:
            print("✓ Lifecycle policy created")
            return True
        else:
            print(f"⚠ Lifecycle policy creation issue: {response.text}")
            return False

    def create_index_template(self) -> bool:
        """Create index template for automatic index creation"""
        template = {
            "index_patterns": ["threat-intel-*"],
            "template": {
                "settings": {
                    "number_of_shards": 3,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": "threat-intel-policy"
                }
            },
            "priority": 500,
            "version": 1,
            "_meta": {
                "description": "Template for threat intelligence indices"
            }
        }

        print("Creating index template...")
        response = self.session.put(
            f"{self.es_url}/_index_template/threat-intel-template",
            json=template,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code in [200, 201]:
            print("✓ Index template created")
            return True
        else:
            print(f"⚠ Template creation issue: {response.text}")
            return False

    def verify_index(self, index_name: str) -> Dict:
        """
        Verify index configuration and health

        Args:
            index_name: Name of the index to verify

        Returns:
            Dictionary with verification results
        """
        results = {
            "exists": False,
            "doc_count": 0,
            "size": "0b",
            "health": "unknown",
            "shards": {"total": 0, "successful": 0, "failed": 0}
        }

        # Check existence
        check_response = self.session.head(f"{self.es_url}/{index_name}")
        if check_response.status_code != 200:
            return results

        results["exists"] = True

        # Get stats
        stats_response = self.session.get(f"{self.es_url}/{index_name}/_stats")
        if stats_response.status_code == 200:
            stats = stats_response.json()
            indices_stats = stats.get("indices", {}).get(index_name, {})

            results["doc_count"] = indices_stats.get("primaries", {}).get("docs", {}).get("count", 0)
            size_bytes = indices_stats.get("primaries", {}).get("store", {}).get("size_in_bytes", 0)
            results["size"] = self._format_bytes(size_bytes)

        # Get health
        health_response = self.session.get(f"{self.es_url}/_cluster/health/{index_name}")
        if health_response.status_code == 200:
            health = health_response.json()
            results["health"] = health.get("status", "unknown")
            results["shards"] = {
                "total": health.get("active_shards", 0),
                "successful": health.get("active_primary_shards", 0),
                "failed": health.get("unassigned_shards", 0)
            }

        return results

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f}PB"

    def initialize_all(self, force: bool = False) -> bool:
        """
        Initialize all required indices and configurations

        Args:
            force: If True, recreate existing indices

        Returns:
            True if all initialization succeeded
        """
        print("\n" + "="*80)
        print("THREAT INTELLIGENCE PLATFORM - DATABASE INITIALIZATION")
        print("="*80 + "\n")

        # Check connection
        if not self.check_connection():
            print("\n✗ Initialization failed: Cannot connect to Elasticsearch")
            print("Make sure Elasticsearch is running: make start")
            return False

        print()

        # Create lifecycle policy
        self.create_lifecycle_policy()
        print()

        # Create index template
        self.create_index_template()
        print()

        # Create main IOC index
        mapping = self.get_ioc_index_mapping()
        success = self.create_index("threat-intel-iocs", mapping, force=force)
        print()

        if success:
            # Verify index
            print("Verifying index...")
            results = self.verify_index("threat-intel-iocs")

            print(f"  Status: {results['health']}")
            print(f"  Documents: {results['doc_count']}")
            print(f"  Size: {results['size']}")
            print(f"  Shards: {results['shards']['total']} total, {results['shards']['successful']} active")
            print()

        print("="*80)
        if success:
            print("✓ Database initialization completed successfully!")
            print("\nYou can now start collecting threat intelligence:")
            print("  - Run DAG: make trigger-dag")
            print("  - Test collectors: python scripts/test_collectors.py")
        else:
            print("✗ Database initialization failed")
            print("\nCheck the logs for more information")
        print("="*80 + "\n")

        return success


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Initialize Threat Intelligence Platform database"
    )
    parser.add_argument(
        "--es-url",
        default=os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"),
        help="Elasticsearch URL (default: http://localhost:9200)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force recreate indices (deletes existing data)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify existing indices, don't create"
    )

    args = parser.parse_args()

    # Initialize
    initializer = DatabaseInitializer(es_url=args.es_url)

    if args.verify_only:
        # Verification mode
        print("\n" + "="*80)
        print("DATABASE VERIFICATION")
        print("="*80 + "\n")

        if not initializer.check_connection():
            sys.exit(1)

        print("\nVerifying threat-intel-iocs index...")
        results = initializer.verify_index("threat-intel-iocs")

        if results["exists"]:
            print(f"✓ Index exists")
            print(f"  Health: {results['health']}")
            print(f"  Documents: {results['doc_count']}")
            print(f"  Size: {results['size']}")
            print(f"  Shards: {results['shards']['total']} total")
        else:
            print("✗ Index does not exist")
            print("\nRun without --verify-only to create the index")
            sys.exit(1)

        print("\n" + "="*80 + "\n")
    else:
        # Full initialization
        if args.force:
            print("\n⚠️  WARNING: --force flag will DELETE existing indices and data!")
            response = input("Are you sure you want to continue? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(0)

        success = initializer.initialize_all(force=args.force)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
