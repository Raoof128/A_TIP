#!/usr/bin/env python3
"""
Threat Intelligence Platform - Database Migration Script
Handles schema migrations and data transformations
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Migration:
    """Base class for database migrations"""

    def __init__(self, version: str, description: str):
        """
        Initialize migration

        Args:
            version: Migration version (e.g., "1.0.0", "1.1.0")
            description: Human-readable description
        """
        self.version = version
        self.description = description
        self.timestamp = datetime.utcnow()

    def up(self, db_manager) -> bool:
        """
        Apply migration (upgrade)

        Args:
            db_manager: DatabaseMigrationManager instance

        Returns:
            True if successful
        """
        raise NotImplementedError("Subclasses must implement up()")

    def down(self, db_manager) -> bool:
        """
        Rollback migration (downgrade)

        Args:
            db_manager: DatabaseMigrationManager instance

        Returns:
            True if successful
        """
        raise NotImplementedError("Subclasses must implement down()")


class AddMetadataFieldsMigration(Migration):
    """Add metadata fields to existing IOCs"""

    def __init__(self):
        super().__init__(
            version="1.1.0",
            description="Add metadata.created_at and metadata.updated_at fields"
        )

    def up(self, db_manager) -> bool:
        """Add metadata fields to all documents"""
        print(f"  Applying migration: {self.description}")

        # Update all documents to add metadata fields if missing
        update_query = {
            "script": {
                "source": """
                if (ctx._source.metadata == null) {
                    ctx._source.metadata = [:];
                }
                if (ctx._source.metadata.created_at == null) {
                    ctx._source.metadata.created_at = ctx._source.first_seen;
                }
                if (ctx._source.metadata.updated_at == null) {
                    ctx._source.metadata.updated_at = params.now;
                }
                if (ctx._source.metadata.version == null) {
                    ctx._source.metadata.version = 1;
                }
                """,
                "lang": "painless",
                "params": {
                    "now": datetime.utcnow().isoformat()
                }
            },
            "query": {
                "bool": {
                    "should": [
                        {"bool": {"must_not": {"exists": {"field": "metadata"}}}},
                        {"bool": {"must_not": {"exists": {"field": "metadata.created_at"}}}},
                        {"bool": {"must_not": {"exists": {"field": "metadata.updated_at"}}}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }

        response = db_manager.session.post(
            f"{db_manager.es_url}/threat-intel-iocs/_update_by_query?conflicts=proceed",
            json=update_query,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            updated = result.get("updated", 0)
            print(f"    ✓ Updated {updated} documents")
            return True
        else:
            print(f"    ✗ Failed: {response.text}")
            return False

    def down(self, db_manager) -> bool:
        """Remove metadata fields"""
        print(f"  Rolling back migration: {self.description}")

        # This is destructive, so we just log it
        print("    ⚠ Rollback would remove metadata fields (not implemented for safety)")
        return True


class NormalizeIOCValuesMigration(Migration):
    """Normalize IOC values to lowercase"""

    def __init__(self):
        super().__init__(
            version="1.2.0",
            description="Normalize all IOC values to lowercase"
        )

    def up(self, db_manager) -> bool:
        """Normalize IOC values"""
        print(f"  Applying migration: {self.description}")

        update_query = {
            "script": {
                "source": "ctx._source.value = ctx._source.value.toLowerCase()",
                "lang": "painless"
            },
            "query": {
                "match_all": {}
            }
        }

        response = db_manager.session.post(
            f"{db_manager.es_url}/threat-intel-iocs/_update_by_query?conflicts=proceed",
            json=update_query,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            updated = result.get("updated", 0)
            print(f"    ✓ Updated {updated} documents")
            return True
        else:
            print(f"    ✗ Failed: {response.text}")
            return False

    def down(self, db_manager) -> bool:
        """Cannot rollback normalization"""
        print(f"  Rolling back migration: {self.description}")
        print("    ⚠ Cannot rollback value normalization (original values lost)")
        return True


class AddCorrelationFieldsMigration(Migration):
    """Add correlation tracking fields"""

    def __init__(self):
        super().__init__(
            version="1.3.0",
            description="Add correlation fields for threat tracking"
        )

    def up(self, db_manager) -> bool:
        """Add correlation fields"""
        print(f"  Applying migration: {self.description}")

        update_query = {
            "script": {
                "source": """
                if (ctx._source.correlation == null) {
                    ctx._source.correlation = [:];
                    ctx._source.correlation.related_iocs = [];
                }
                """,
                "lang": "painless"
            },
            "query": {
                "bool": {
                    "must_not": {
                        "exists": {"field": "correlation"}
                    }
                }
            }
        }

        response = db_manager.session.post(
            f"{db_manager.es_url}/threat-intel-iocs/_update_by_query?conflicts=proceed",
            json=update_query,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            updated = result.get("updated", 0)
            print(f"    ✓ Updated {updated} documents")
            return True
        else:
            print(f"    ✗ Failed: {response.text}")
            return False

    def down(self, db_manager) -> bool:
        """Remove correlation fields"""
        print(f"  Rolling back migration: {self.description}")
        print("    ⚠ Rollback would remove correlation data (not implemented for safety)")
        return True


class DatabaseMigrationManager:
    """Manages database migrations"""

    MIGRATIONS_INDEX = "tip-migrations"

    def __init__(self, es_url: str = "http://localhost:9200"):
        """
        Initialize migration manager

        Args:
            es_url: Elasticsearch URL
        """
        self.es_url = es_url.rstrip('/')
        self.session = self._create_session()
        self.migrations = self._get_available_migrations()

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

    def _get_available_migrations(self) -> List[Migration]:
        """Get list of available migrations in order"""
        return [
            AddMetadataFieldsMigration(),
            NormalizeIOCValuesMigration(),
            AddCorrelationFieldsMigration(),
        ]

    def check_connection(self) -> bool:
        """Check if Elasticsearch is reachable"""
        try:
            response = self.session.get(f"{self.es_url}/_cluster/health", timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _ensure_migrations_index(self):
        """Ensure migrations tracking index exists"""
        mapping = {
            "mappings": {
                "properties": {
                    "version": {"type": "keyword"},
                    "description": {"type": "text"},
                    "applied_at": {"type": "date"},
                    "rolled_back_at": {"type": "date"},
                    "status": {"type": "keyword"}
                }
            }
        }

        check_response = self.session.head(f"{self.es_url}/{self.MIGRATIONS_INDEX}")
        if check_response.status_code == 404:
            self.session.put(
                f"{self.es_url}/{self.MIGRATIONS_INDEX}",
                json=mapping,
                headers={"Content-Type": "application/json"}
            )

    def _get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions"""
        self._ensure_migrations_index()

        query = {
            "query": {
                "term": {"status": "applied"}
            },
            "size": 100,
            "sort": [{"applied_at": "asc"}]
        }

        response = self.session.post(
            f"{self.es_url}/{self.MIGRATIONS_INDEX}/_search",
            json=query,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            hits = response.json().get("hits", {}).get("hits", [])
            return [hit["_source"]["version"] for hit in hits]
        return []

    def _record_migration(self, migration: Migration, status: str):
        """Record migration in tracking index"""
        doc = {
            "version": migration.version,
            "description": migration.description,
            "applied_at": datetime.utcnow().isoformat() if status == "applied" else None,
            "rolled_back_at": datetime.utcnow().isoformat() if status == "rolled_back" else None,
            "status": status
        }

        self.session.post(
            f"{self.es_url}/{self.MIGRATIONS_INDEX}/_doc",
            json=doc,
            headers={"Content-Type": "application/json"}
        )

    def migrate_up(self, target_version: Optional[str] = None) -> bool:
        """
        Apply pending migrations

        Args:
            target_version: Target version to migrate to (None = latest)

        Returns:
            True if all migrations succeeded
        """
        print("\n" + "="*80)
        print("DATABASE MIGRATION - UPGRADE")
        print("="*80 + "\n")

        if not self.check_connection():
            print("✗ Cannot connect to Elasticsearch")
            return False

        applied = self._get_applied_migrations()
        print(f"Applied migrations: {len(applied)}")

        pending = [m for m in self.migrations if m.version not in applied]

        if target_version:
            pending = [m for m in pending if m.version <= target_version]

        if not pending:
            print("\n✓ No pending migrations")
            return True

        print(f"Pending migrations: {len(pending)}\n")

        success = True
        for migration in pending:
            print(f"[{migration.version}] {migration.description}")
            try:
                if migration.up(self):
                    self._record_migration(migration, "applied")
                    print(f"  ✓ Migration {migration.version} applied\n")
                else:
                    print(f"  ✗ Migration {migration.version} failed\n")
                    success = False
                    break
            except Exception as e:
                print(f"  ✗ Migration {migration.version} error: {e}\n")
                success = False
                break

        print("="*80)
        if success:
            print("✓ All migrations applied successfully")
        else:
            print("✗ Migration failed")
        print("="*80 + "\n")

        return success

    def migrate_down(self, target_version: str) -> bool:
        """
        Rollback migrations to target version

        Args:
            target_version: Version to rollback to

        Returns:
            True if rollback succeeded
        """
        print("\n" + "="*80)
        print("DATABASE MIGRATION - ROLLBACK")
        print("="*80 + "\n")

        if not self.check_connection():
            print("✗ Cannot connect to Elasticsearch")
            return False

        applied = self._get_applied_migrations()
        to_rollback = [m for m in self.migrations if m.version in applied and m.version > target_version]
        to_rollback.reverse()  # Rollback in reverse order

        if not to_rollback:
            print("✓ No migrations to rollback")
            return True

        print(f"⚠️  WARNING: Rolling back {len(to_rollback)} migration(s)")
        print("This may cause data loss!\n")

        response = input("Continue? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted")
            return False

        success = True
        for migration in to_rollback:
            print(f"\n[{migration.version}] {migration.description}")
            try:
                if migration.down(self):
                    self._record_migration(migration, "rolled_back")
                    print(f"  ✓ Migration {migration.version} rolled back")
                else:
                    print(f"  ✗ Migration {migration.version} rollback failed")
                    success = False
                    break
            except Exception as e:
                print(f"  ✗ Migration {migration.version} error: {e}")
                success = False
                break

        print("\n" + "="*80)
        if success:
            print("✓ Rollback completed")
        else:
            print("✗ Rollback failed")
        print("="*80 + "\n")

        return success

    def status(self):
        """Print migration status"""
        print("\n" + "="*80)
        print("DATABASE MIGRATION STATUS")
        print("="*80 + "\n")

        if not self.check_connection():
            print("✗ Cannot connect to Elasticsearch")
            return

        applied = self._get_applied_migrations()

        print(f"Total migrations available: {len(self.migrations)}")
        print(f"Applied migrations: {len(applied)}\n")

        print("Migration Status:")
        print("-"*80)

        for migration in self.migrations:
            status = "✓ Applied" if migration.version in applied else "⏳ Pending"
            print(f"  [{migration.version}] {status} - {migration.description}")

        print("\n" + "="*80 + "\n")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage Threat Intelligence Platform database migrations"
    )
    parser.add_argument(
        "--es-url",
        default=os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"),
        help="Elasticsearch URL"
    )

    subparsers = parser.add_subparsers(dest="command", help="Migration command")

    # Status command
    subparsers.add_parser("status", help="Show migration status")

    # Up command
    up_parser = subparsers.add_parser("up", help="Apply pending migrations")
    up_parser.add_argument(
        "--target",
        help="Target version to migrate to"
    )

    # Down command
    down_parser = subparsers.add_parser("down", help="Rollback migrations")
    down_parser.add_argument(
        "target",
        help="Target version to rollback to"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    manager = DatabaseMigrationManager(es_url=args.es_url)

    if args.command == "status":
        manager.status()
    elif args.command == "up":
        success = manager.migrate_up(target_version=args.target)
        sys.exit(0 if success else 1)
    elif args.command == "down":
        success = manager.migrate_down(target_version=args.target)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
