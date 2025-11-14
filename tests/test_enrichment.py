"""
Unit tests for enrichment engines
"""

import pytest
import sys
import os
from datetime import datetime, timedelta

# Add enrichment to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enrichment'))

from threat_score_engine import ThreatScoreEngine


class TestThreatScoreEngine:
    """Test threat scoring engine"""

    def test_scorer_initialization(self):
        """Test scorer initialization"""
        scorer = ThreatScoreEngine()

        assert scorer.source_scores['AlienVault OTX'] == 75
        assert scorer.source_scores['VirusTotal'] == 85
        assert scorer.source_scores['AbuseIPDB'] == 80

    def test_score_source(self):
        """Test source credibility scoring"""
        scorer = ThreatScoreEngine()

        assert scorer._score_source('VirusTotal') == 85
        assert scorer._score_source('AlienVault OTX') == 75
        assert scorer._score_source('Unknown Source') == 50

    def test_score_sightings(self):
        """Test sighting frequency scoring"""
        scorer = ThreatScoreEngine()

        assert scorer._score_sightings(10) == 100
        assert scorer._score_sightings(5) == 80
        assert scorer._score_sightings(3) == 60
        assert scorer._score_sightings(2) == 40
        assert scorer._score_sightings(1) == 20

    def test_score_age_fresh(self):
        """Test age scoring for fresh IOCs"""
        scorer = ThreatScoreEngine()

        # Very fresh (today)
        fresh_date = datetime.utcnow().isoformat()
        assert scorer._score_age(fresh_date) == 100

    def test_score_age_old(self):
        """Test age scoring for old IOCs"""
        scorer = ThreatScoreEngine()

        # Old (100 days ago)
        old_date = (datetime.utcnow() - timedelta(days=100)).isoformat()
        score = scorer._score_age(old_date)
        assert score == 20

    def test_score_correlation(self):
        """Test multi-source correlation scoring"""
        scorer = ThreatScoreEngine()

        assert scorer._score_correlation(['Source1', 'Source2', 'Source3', 'Source4', 'Source5']) == 100
        assert scorer._score_correlation(['Source1', 'Source2', 'Source3']) == 80
        assert scorer._score_correlation(['Source1', 'Source2']) == 60
        assert scorer._score_correlation(['Source1']) == 30

    def test_score_tags_high_severity(self):
        """Test tag-based severity scoring for high severity tags"""
        scorer = ThreatScoreEngine()

        assert scorer._score_tags(['ransomware']) == 100
        assert scorer._score_tags(['apt']) == 95
        assert scorer._score_tags(['malware']) == 90
        assert scorer._score_tags(['botnet']) == 85

    def test_score_tags_multiple(self):
        """Test tag scoring with multiple tags (should take max)"""
        scorer = ThreatScoreEngine()

        score = scorer._score_tags(['spam', 'ransomware', 'phishing'])
        assert score == 100  # Maximum of the three

    def test_score_tags_empty(self):
        """Test tag scoring with no tags"""
        scorer = ThreatScoreEngine()

        assert scorer._score_tags([]) == 50

    def test_get_severity_level(self):
        """Test severity level categorization"""
        scorer = ThreatScoreEngine()

        assert scorer.get_severity_level(85) == "CRITICAL"
        assert scorer.get_severity_level(70) == "HIGH"
        assert scorer.get_severity_level(55) == "MEDIUM"
        assert scorer.get_severity_level(35) == "LOW"
        assert scorer.get_severity_level(15) == "INFO"

    def test_calculate_score(self):
        """Test comprehensive score calculation"""
        scorer = ThreatScoreEngine()

        test_ioc = {
            'value': '192.168.1.100',
            'source': 'VirusTotal',
            'confidence': 85,
            'tags': ['malware', 'botnet'],
            'first_seen': datetime.utcnow().isoformat(),
            'sightings': 5,
            'sources': ['VirusTotal', 'AbuseIPDB', 'AlienVault OTX']
        }

        score = scorer.calculate_score(test_ioc)

        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_enrich_ioc_with_score(self):
        """Test IOC enrichment with score"""
        scorer = ThreatScoreEngine()

        test_ioc = {
            'value': '1.2.3.4',
            'source': 'VirusTotal',
            'tags': ['ransomware'],
            'first_seen': datetime.utcnow().isoformat(),
            'sightings': 10,
            'sources': ['VirusTotal', 'AbuseIPDB']
        }

        enriched = scorer.enrich_ioc_with_score(test_ioc)

        assert 'threat_score' in enriched
        assert 'severity' in enriched
        assert 'scored_at' in enriched
        assert enriched['threat_score'] > 0
        assert enriched['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

    def test_batch_score(self):
        """Test batch scoring"""
        scorer = ThreatScoreEngine()

        test_iocs = [
            {
                'value': '1.2.3.4',
                'source': 'VirusTotal',
                'tags': ['ransomware'],
                'first_seen': datetime.utcnow().isoformat(),
                'sightings': 10,
                'sources': ['VirusTotal']
            },
            {
                'value': '5.6.7.8',
                'source': 'AlienVault OTX',
                'tags': ['spam'],
                'first_seen': datetime.utcnow().isoformat(),
                'sightings': 1,
                'sources': ['AlienVault OTX']
            }
        ]

        scored_iocs = scorer.batch_score(test_iocs)

        assert len(scored_iocs) == 2
        assert all('threat_score' in ioc for ioc in scored_iocs)
        assert all('severity' in ioc for ioc in scored_iocs)

    def test_get_score_distribution(self):
        """Test score distribution calculation"""
        scorer = ThreatScoreEngine()

        test_iocs = [
            {'severity': 'CRITICAL'},
            {'severity': 'CRITICAL'},
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'LOW'}
        ]

        distribution = scorer.get_score_distribution(test_iocs)

        assert distribution['CRITICAL'] == 2
        assert distribution['HIGH'] == 1
        assert distribution['MEDIUM'] == 1
        assert distribution['LOW'] == 1
        assert distribution['INFO'] == 0


class TestGeoIPEnricher:
    """Test GeoIP enrichment"""

    def test_enricher_initialization(self):
        """Test GeoIP enricher initialization"""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enrichment'))
        from geoip_enricher import GeoIPEnricher

        enricher = GeoIPEnricher()
        assert enricher is not None

    def test_enrich_ioc_ip(self):
        """Test IP enrichment (integration test - requires network)"""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enrichment'))
        from geoip_enricher import GeoIPEnricher

        enricher = GeoIPEnricher()

        test_ioc = {
            'type': 'ip',
            'value': '8.8.8.8',
            'tags': []
        }

        # This is an integration test that requires network
        # In production, you'd mock the API response
        enriched = enricher.enrich_ioc(test_ioc)

        assert 'type' in enriched
        # GeoIP data may or may not be added depending on network availability


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
