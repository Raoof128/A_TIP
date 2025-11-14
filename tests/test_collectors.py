"""
Unit tests for threat intelligence collectors
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add collectors to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'collectors'))

from base_collector import IOC, BaseCollector
from alienvault_otx import AlienVaultCollector
from urlhaus_collector import URLhausCollector
from abuseipdb_collector import AbuseIPDBCollector


class TestIOC:
    """Test IOC data structure"""

    def test_ioc_creation(self):
        """Test IOC object creation"""
        ioc = IOC(
            ioc_type="ip",
            value="192.168.1.1",
            source="Test",
            confidence=75
        )

        assert ioc.ioc_type == "ip"
        assert ioc.value == "192.168.1.1"
        assert ioc.source == "Test"
        assert ioc.confidence == 75
        assert len(ioc.ioc_id) == 16  # SHA256 truncated to 16 chars
        assert isinstance(ioc.tags, list)

    def test_ioc_with_tags(self):
        """Test IOC with tags"""
        ioc = IOC(
            ioc_type="domain",
            value="malicious.com",
            source="Test",
            tags=["malware", "c2"]
        )

        assert len(ioc.tags) == 2
        assert "malware" in ioc.tags
        assert "c2" in ioc.tags

    def test_ioc_to_dict(self):
        """Test IOC serialization to dictionary"""
        ioc = IOC(
            ioc_type="domain",
            value="malicious.com",
            source="Test",
            tags=["malware", "c2"]
        )

        ioc_dict = ioc.to_dict()

        assert 'ioc_id' in ioc_dict
        assert ioc_dict['type'] == "domain"
        assert ioc_dict['value'] == "malicious.com"
        assert len(ioc_dict['tags']) == 2
        assert 'first_seen' in ioc_dict
        assert 'last_seen' in ioc_dict

    def test_ioc_unique_id(self):
        """Test that identical IOCs get same ID"""
        ioc1 = IOC("ip", "1.2.3.4", "Source1")
        ioc2 = IOC("ip", "1.2.3.4", "Source1")

        assert ioc1.ioc_id == ioc2.ioc_id

    def test_ioc_different_sources_different_id(self):
        """Test that same IOC from different sources gets different ID"""
        ioc1 = IOC("ip", "1.2.3.4", "Source1")
        ioc2 = IOC("ip", "1.2.3.4", "Source2")

        assert ioc1.ioc_id != ioc2.ioc_id


class TestBaseCollector:
    """Test base collector functionality"""

    def test_validate_ioc_ip_valid(self):
        """Test IP validation with valid IPs"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        valid_ips = ["192.168.1.1", "8.8.8.8", "10.0.0.1", "172.16.0.1"]
        for ip in valid_ips:
            ioc = IOC("ip", ip, "Test")
            assert collector.validate_ioc(ioc) == True

    def test_validate_ioc_ip_invalid(self):
        """Test IP validation with invalid IPs"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        invalid_ips = ["999.999.999.999", "192.168.1", "not.an.ip", "192.168.1.1.1"]
        for ip in invalid_ips:
            ioc = IOC("ip", ip, "Test")
            assert collector.validate_ioc(ioc) == False

    def test_validate_ioc_domain_valid(self):
        """Test domain validation with valid domains"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        valid_domains = ["example.com", "sub.example.com", "test-site.org", "my-domain.co.uk"]
        for domain in valid_domains:
            ioc = IOC("domain", domain, "Test")
            assert collector.validate_ioc(ioc) == True

    def test_validate_ioc_domain_invalid(self):
        """Test domain validation with invalid domains"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        invalid_domains = ["not..valid..domain", "-invalid.com", "invalid-.com", ""]
        for domain in invalid_domains:
            ioc = IOC("domain", domain, "Test")
            assert collector.validate_ioc(ioc) == False

    def test_validate_ioc_hash_md5(self):
        """Test MD5 hash validation"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        valid_md5 = "5d41402abc4b2a76b9719d911017c592"
        ioc = IOC("md5", valid_md5, "Test")
        assert collector.validate_ioc(ioc) == True

        invalid_md5 = "not_a_valid_md5_hash"
        ioc = IOC("md5", invalid_md5, "Test")
        assert collector.validate_ioc(ioc) == False

    def test_validate_ioc_hash_sha256(self):
        """Test SHA256 hash validation"""
        collector = Mock(spec=BaseCollector)
        collector.validate_ioc = BaseCollector.validate_ioc.__get__(collector)

        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc = IOC("sha256", valid_sha256, "Test")
        assert collector.validate_ioc(ioc) == True

        invalid_sha256 = "too_short"
        ioc = IOC("sha256", invalid_sha256, "Test")
        assert collector.validate_ioc(ioc) == False

    def test_metrics_calculation(self):
        """Test metrics calculation"""
        collector = Mock(spec=BaseCollector)
        collector.collected_iocs = [
            IOC("ip", "1.2.3.4", "Test1", 80),
            IOC("ip", "5.6.7.8", "Test2", 60),
            IOC("domain", "evil.com", "Test1", 90)
        ]
        collector.get_metrics = BaseCollector.get_metrics.__get__(collector)
        collector._count_by_type = BaseCollector._count_by_type.__get__(collector)
        collector._count_by_confidence = BaseCollector._count_by_confidence.__get__(collector)

        metrics = collector.get_metrics()

        assert metrics['total_collected'] == 3
        assert metrics['by_type']['ip'] == 2
        assert metrics['by_type']['domain'] == 1
        assert 'by_confidence' in metrics


class TestAlienVaultCollector:
    """Test AlienVault OTX collector"""

    @patch('alienvault_otx.OTXv2')
    def test_collect_success(self, mock_otx):
        """Test successful collection from OTX"""
        # Mock OTX API response
        mock_otx_instance = MagicMock()
        mock_otx.return_value = mock_otx_instance
        mock_otx_instance.getall.return_value = [
            {
                'name': 'Test Pulse',
                'tags': ['malware', 'test'],
                'indicators': [
                    {
                        'type': 'IPv4',
                        'indicator': '1.2.3.4'
                    },
                    {
                        'type': 'domain',
                        'indicator': 'badguy.com'
                    }
                ]
            }
        ]

        collector = AlienVaultCollector(api_key="test_key")
        iocs = collector.collect(limit=1)

        assert len(iocs) == 2
        assert iocs[0].ioc_type == "ip"
        assert iocs[0].value == "1.2.3.4"
        assert iocs[1].ioc_type == "domain"
        assert iocs[1].value == "badguy.com"

    def test_map_indicator_type(self):
        """Test indicator type mapping"""
        collector = AlienVaultCollector(api_key="test_key")

        assert collector._map_indicator_type('IPv4') == 'ip'
        assert collector._map_indicator_type('IPv6') == 'ip'
        assert collector._map_indicator_type('domain') == 'domain'
        assert collector._map_indicator_type('hostname') == 'domain'
        assert collector._map_indicator_type('URL') == 'url'
        assert collector._map_indicator_type('FileHash-MD5') == 'md5'
        assert collector._map_indicator_type('FileHash-SHA256') == 'sha256'
        assert collector._map_indicator_type('email') == 'email'
        assert collector._map_indicator_type('unknown_type') is None


class TestURLhausCollector:
    """Test URLhaus collector"""

    def test_collector_initialization(self):
        """Test URLhaus collector initialization"""
        collector = URLhausCollector()

        assert collector.source == "URLhaus"
        assert collector.feed_url == "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def test_calculate_confidence(self):
        """Test confidence calculation"""
        collector = URLhausCollector()

        assert collector._calculate_confidence('malware_download') == 90
        assert collector._calculate_confidence('ransomware') == 95
        assert collector._calculate_confidence('trojan') == 85
        assert collector._calculate_confidence('unknown_threat') == 70


class TestAbuseIPDBCollector:
    """Test AbuseIPDB collector"""

    def test_collector_initialization(self):
        """Test AbuseIPDB collector initialization"""
        collector = AbuseIPDBCollector(api_key="test_key")

        assert collector.source == "AbuseIPDB"
        assert collector.base_url == "https://api.abuseipdb.com/api/v2"
        assert collector.session.headers['Key'] == "test_key"


# Fixtures
@pytest.fixture
def sample_iocs():
    """Fixture providing sample IOCs for testing"""
    return [
        IOC("ip", "1.2.3.4", "Test1", 80, ["malware"]),
        IOC("ip", "5.6.7.8", "Test2", 60, ["spam"]),
        IOC("domain", "evil.com", "Test1", 90, ["c2", "botnet"])
    ]


def test_sample_iocs_fixture(sample_iocs):
    """Test the sample IOCs fixture"""
    assert len(sample_iocs) == 3
    assert sample_iocs[0].ioc_type == "ip"
    assert sample_iocs[2].ioc_type == "domain"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
