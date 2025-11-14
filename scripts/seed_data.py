#!/usr/bin/env python3
"""
Threat Intelligence Platform - Seed Data Script
Populates the database with sample threat intelligence data for testing and demos
"""

import os
import sys
import json
import random
from datetime import datetime, timedelta
from typing import List, Dict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DataSeeder:
    """Seed sample data for testing"""

    def __init__(self, es_url: str = "http://localhost:9200"):
        """
        Initialize data seeder

        Args:
            es_url: Elasticsearch URL
        """
        self.es_url = es_url.rstrip('/')
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with retry logic"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _generate_sample_iocs(self, count: int = 100) -> List[Dict]:
        """
        Generate sample IOC data

        Args:
            count: Number of IOCs to generate

        Returns:
            List of IOC dictionaries
        """
        iocs = []
        now = datetime.utcnow()

        # Sample data pools
        malicious_ips = [
            "192.0.2.1", "198.51.100.23", "203.0.113.45",
            "192.0.2.100", "198.51.100.200", "203.0.113.150"
        ]

        malicious_domains = [
            "evil-phishing-site.example", "malware-download.test",
            "c2-server.invalid", "phishing-bank.example",
            "trojan-dropper.test", "ransomware-c2.invalid"
        ]

        malicious_urls = [
            "http://evil-phishing-site.example/login.php",
            "https://malware-download.test/payload.exe",
            "http://c2-server.invalid/beacon",
            "https://phishing-bank.example/secure/verify.html",
            "http://trojan-dropper.test/update.bin"
        ]

        malicious_hashes = [
            "5d41402abc4b2a76b9719d911017c592",  # MD5
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
            "098f6bcd4621d373cade4e832627b4f6",
            "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
        ]

        threat_actors = ["APT28", "Lazarus Group", "FIN7", "Cobalt Group", "OceanLotus"]
        malware_families = ["Emotet", "TrickBot", "Ryuk", "Dridex", "Zeus", "Mirai"]
        tags_pool = ["phishing", "malware", "ransomware", "c2", "botnet", "exploit", "trojan"]

        sources = ["AlienVault OTX", "URLhaus", "AbuseIPDB", "PhishTank", "Internal Analysis"]
        severities = ["critical", "high", "medium", "low"]

        for i in range(count):
            # Random IOC type
            ioc_type = random.choice(["ip", "domain", "url", "md5", "sha256"])

            if ioc_type == "ip":
                value = random.choice(malicious_ips)
            elif ioc_type == "domain":
                value = random.choice(malicious_domains)
            elif ioc_type == "url":
                value = random.choice(malicious_urls)
            elif ioc_type == "md5":
                value = random.choice(malicious_hashes[:2])
            else:  # sha256
                value = random.choice(malicious_hashes[2:])

            # Random dates
            days_ago = random.randint(1, 90)
            first_seen = now - timedelta(days=days_ago)
            last_seen = first_seen + timedelta(days=random.randint(0, days_ago))

            # Random scoring
            threat_score = round(random.uniform(0.3, 0.95), 2)
            confidence = random.randint(60, 100)

            severity = random.choice(severities)
            num_tags = random.randint(1, 4)
            tags = random.sample(tags_pool, num_tags)

            ioc = {
                "value": value,
                "type": ioc_type,
                "source": random.choice(sources),
                "first_seen": first_seen.isoformat() + "Z",
                "last_seen": last_seen.isoformat() + "Z",
                "threat_score": threat_score,
                "confidence": confidence,
                "severity": severity,
                "tags": tags,
                "description": f"Sample {ioc_type} IOC detected in {random.choice(['APT campaign', 'phishing operation', 'malware distribution', 'botnet activity'])}",
                "references": [
                    f"https://example.com/report/{random.randint(1000, 9999)}"
                ]
            }

            # Add enrichment data for some IOCs
            if random.random() > 0.5:
                ioc["enrichment"] = {}

                if ioc_type == "ip":
                    ioc["enrichment"]["geolocation"] = {
                        "country": random.choice(["Russia", "China", "North Korea", "Iran", "Unknown"]),
                        "country_code": random.choice(["RU", "CN", "KP", "IR", "XX"]),
                        "city": random.choice(["Moscow", "Beijing", "Pyongyang", "Tehran", "Unknown"]),
                        "asn": f"AS{random.randint(1000, 99999)}",
                        "as_org": random.choice(["Hostile Hosting LLC", "Malicious Networks", "Bulletproof ISP"])
                    }

                    ioc["enrichment"]["reputation"] = {
                        "score": random.randint(20, 80),
                        "reports": random.randint(5, 500),
                        "last_reported": (now - timedelta(days=random.randint(1, 30))).isoformat() + "Z"
                    }

                if ioc_type in ["domain", "url"]:
                    ioc["enrichment"]["whois"] = {
                        "registrar": random.choice(["Suspicious Registrar", "Anonymous Domains Inc."]),
                        "creation_date": (now - timedelta(days=random.randint(30, 365))).isoformat() + "Z"
                    }

            # Add correlation data for some IOCs
            if random.random() > 0.6:
                ioc["correlation"] = {
                    "threat_actor": random.choice(threat_actors),
                    "malware_family": random.choice(malware_families),
                    "campaign_id": f"CAMP-{random.randint(1000, 9999)}"
                }

            # Add metadata
            ioc["metadata"] = {
                "created_at": first_seen.isoformat() + "Z",
                "updated_at": last_seen.isoformat() + "Z",
                "version": 1,
                "source_url": f"https://example.com/ioc/{random.randint(10000, 99999)}"
            }

            iocs.append(ioc)

        return iocs

    def _generate_bulk_operations(self, iocs: List[Dict], index_name: str) -> str:
        """
        Generate bulk API operations

        Args:
            iocs: List of IOCs
            index_name: Target index name

        Returns:
            Bulk operations string
        """
        operations = []
        for ioc in iocs:
            # Index operation
            operations.append(json.dumps({
                "index": {
                    "_index": index_name
                }
            }))
            # Document
            operations.append(json.dumps(ioc))

        return "\n".join(operations) + "\n"

    def seed(self, count: int = 100, index_name: str = "threat-intel-iocs") -> bool:
        """
        Seed data into Elasticsearch

        Args:
            count: Number of IOCs to generate
            index_name: Target index name

        Returns:
            True if successful
        """
        print("\n" + "="*80)
        print("THREAT INTELLIGENCE PLATFORM - SEED DATA")
        print("="*80 + "\n")

        # Check connection
        try:
            response = self.session.get(f"{self.es_url}/_cluster/health", timeout=10)
            if response.status_code != 200:
                print("✗ Cannot connect to Elasticsearch")
                return False
            print("✓ Connected to Elasticsearch\n")
        except requests.exceptions.RequestException as e:
            print(f"✗ Connection error: {e}")
            return False

        # Check if index exists
        check_response = self.session.head(f"{self.es_url}/{index_name}")
        if check_response.status_code != 200:
            print(f"✗ Index '{index_name}' does not exist")
            print("Run: python scripts/init_database.py")
            return False

        print(f"Generating {count} sample IOCs...")
        iocs = self._generate_sample_iocs(count)
        print(f"✓ Generated {len(iocs)} IOCs\n")

        # Prepare bulk operations
        print("Preparing bulk import...")
        bulk_data = self._generate_bulk_operations(iocs, index_name)

        # Import
        print("Importing data...")
        response = self.session.post(
            f"{self.es_url}/_bulk",
            data=bulk_data,
            headers={"Content-Type": "application/x-ndjson"}
        )

        if response.status_code in [200, 201]:
            result = response.json()
            errors = result.get("errors", False)

            if not errors:
                imported = len(result.get("items", []))
                print(f"✓ Successfully imported {imported} IOCs\n")

                # Show statistics
                print("IOC Distribution:")
                type_counts = {}
                severity_counts = {}

                for ioc in iocs:
                    ioc_type = ioc["type"]
                    type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

                    severity = ioc["severity"]
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                print("\n  By Type:")
                for ioc_type, count in sorted(type_counts.items()):
                    print(f"    {ioc_type}: {count}")

                print("\n  By Severity:")
                for severity, count in sorted(severity_counts.items(), reverse=True):
                    print(f"    {severity}: {count}")

                print("\n" + "="*80)
                print("✓ Data seeding completed successfully!")
                print("\nYou can now:")
                print("  - View data: curl http://localhost:9200/threat-intel-iocs/_search?size=10")
                print("  - Open Grafana: http://localhost:3000")
                print("="*80 + "\n")

                return True
            else:
                error_count = sum(1 for item in result.get("items", []) if "error" in item.get("index", {}))
                print(f"⚠ Import completed with {error_count} errors")
                return False
        else:
            print(f"✗ Bulk import failed: {response.text}")
            return False

    def clear(self, index_name: str = "threat-intel-iocs") -> bool:
        """
        Clear all data from index

        Args:
            index_name: Index to clear

        Returns:
            True if successful
        """
        print(f"\n⚠️  WARNING: This will delete ALL data in index '{index_name}'")
        response = input("Are you sure? [y/N]: ")

        if response.lower() != 'y':
            print("Aborted")
            return False

        print("\nDeleting all documents...")
        delete_query = {"query": {"match_all": {}}}

        response = self.session.post(
            f"{self.es_url}/{index_name}/_delete_by_query",
            json=delete_query,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            deleted = result.get("deleted", 0)
            print(f"✓ Deleted {deleted} documents\n")
            return True
        else:
            print(f"✗ Delete failed: {response.text}")
            return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed sample data for Threat Intelligence Platform"
    )
    parser.add_argument(
        "--es-url",
        default=os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"),
        help="Elasticsearch URL"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of IOCs to generate (default: 100)"
    )
    parser.add_argument(
        "--index",
        default="threat-intel-iocs",
        help="Target index name"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing data before seeding"
    )

    args = parser.parse_args()

    seeder = DataSeeder(es_url=args.es_url)

    if args.clear:
        if not seeder.clear(index_name=args.index):
            sys.exit(1)

    success = seeder.seed(count=args.count, index_name=args.index)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
