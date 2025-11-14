"""
Threat Scoring Engine
Calculates risk scores based on multiple factors
"""

import logging
from typing import Dict, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatScoreEngine:
    """Calculate comprehensive threat scores for IOCs"""

    def __init__(self):
        # Source credibility scores (0-100)
        self.source_scores = {
            'AlienVault OTX': 75,
            'VirusTotal': 85,
            'AbuseIPDB': 80,
            'URLhaus': 70,
            'PhishTank': 75,
            'ThreatFox': 80,
            'EmergingThreats': 90,
            'Malware Bazaar': 85,
            'Feodo Tracker': 85,
            'SSLBlacklist': 70,
            'OpenPhish': 70,
            'Ransomware Tracker': 85
        }

    def calculate_score(self, ioc: Dict) -> int:
        """
        Calculate comprehensive threat score (0-100)
        Higher score = higher threat
        """
        score = 0
        factors = []

        # Factor 1: Source credibility (40% weight)
        source_score = self._score_source(ioc.get('source'))
        score += source_score * 0.4
        factors.append(f"Source: {source_score}")

        # Factor 2: Sighting frequency (25% weight)
        sighting_score = self._score_sightings(ioc.get('sightings', 1))
        score += sighting_score * 0.25
        factors.append(f"Sightings: {sighting_score}")

        # Factor 3: Age/Freshness (15% weight)
        age_score = self._score_age(ioc.get('first_seen'))
        score += age_score * 0.15
        factors.append(f"Age: {age_score}")

        # Factor 4: Multi-source correlation (10% weight)
        correlation_score = self._score_correlation(ioc.get('sources', []))
        score += correlation_score * 0.10
        factors.append(f"Correlation: {correlation_score}")

        # Factor 5: Tag-based severity (10% weight)
        tag_score = self._score_tags(ioc.get('tags', []))
        score += tag_score * 0.10
        factors.append(f"Tags: {tag_score}")

        final_score = int(score)
        logger.debug(f"IOC {ioc.get('value')} score: {final_score} ({', '.join(factors)})")

        return final_score

    def _score_source(self, source: str) -> int:
        """Score based on source credibility"""
        return self.source_scores.get(source, 50)  # Default 50 for unknown sources

    def _score_sightings(self, sightings: int) -> int:
        """Score based on number of sightings"""
        # More sightings = higher confidence
        if sightings >= 10:
            return 100
        elif sightings >= 5:
            return 80
        elif sightings >= 3:
            return 60
        elif sightings >= 2:
            return 40
        else:
            return 20

    def _score_age(self, first_seen: str) -> int:
        """Score based on IOC age (newer = higher score)"""
        try:
            first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            age_days = (datetime.utcnow() - first_seen_dt.replace(tzinfo=None)).days

            if age_days <= 1:
                return 100  # Very fresh
            elif age_days <= 7:
                return 80   # Recent
            elif age_days <= 30:
                return 60   # Moderately recent
            elif age_days <= 90:
                return 40   # Aging
            else:
                return 20   # Old
        except:
            return 50  # Unknown age

    def _score_correlation(self, sources: List[str]) -> int:
        """Score based on multi-source correlation"""
        # More sources reporting same IOC = higher confidence
        num_sources = len(sources) if sources else 1

        if num_sources >= 5:
            return 100
        elif num_sources >= 3:
            return 80
        elif num_sources >= 2:
            return 60
        else:
            return 30

    def _score_tags(self, tags: List[str]) -> int:
        """Score based on tag severity"""
        high_severity_tags = {
            'ransomware': 100,
            'apt': 95,
            'malware': 90,
            'trojan': 85,
            'botnet': 85,
            'c2': 90,
            'command_and_control': 90,
            'exploit': 80,
            'phishing': 75,
            'spam': 50,
            'suspicious': 60,
            'malicious_ip': 75,
            'malicious_url': 75,
            'malware_download': 85,
            'high_risk': 90,
            'medium_risk': 70
        }

        if not tags:
            return 50  # Neutral score if no tags

        # Take highest severity tag
        max_score = max(
            (high_severity_tags.get(tag.lower(), 50) for tag in tags),
            default=50
        )

        return max_score

    def get_severity_level(self, score: int) -> str:
        """Convert numerical score to severity level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 65:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 30:
            return "LOW"
        else:
            return "INFO"

    def enrich_ioc_with_score(self, ioc: Dict) -> Dict:
        """Add threat score and severity to IOC"""
        score = self.calculate_score(ioc)
        severity = self.get_severity_level(score)

        ioc['threat_score'] = score
        ioc['severity'] = severity
        ioc['scored_at'] = datetime.utcnow().isoformat()

        return ioc

    def batch_score(self, iocs: List[Dict]) -> List[Dict]:
        """Score multiple IOCs at once"""
        scored_iocs = []
        for ioc in iocs:
            scored_ioc = self.enrich_ioc_with_score(ioc)
            scored_iocs.append(scored_ioc)

        logger.info(f"Scored {len(scored_iocs)} IOCs")
        return scored_iocs

    def get_score_distribution(self, iocs: List[Dict]) -> Dict[str, int]:
        """Get distribution of severity levels"""
        distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for ioc in iocs:
            severity = ioc.get('severity', 'INFO')
            if severity in distribution:
                distribution[severity] += 1

        return distribution


# Example usage
if __name__ == "__main__":
    import json

    # Initialize scoring engine
    scorer = ThreatScoreEngine()

    # Example IOC
    test_ioc = {
        'type': 'ip',
        'value': '192.168.1.100',
        'source': 'AlienVault OTX',
        'confidence': 85,
        'tags': ['malware', 'botnet', 'c2'],
        'first_seen': datetime.utcnow().isoformat(),
        'sightings': 5,
        'sources': ['AlienVault OTX', 'AbuseIPDB', 'VirusTotal']
    }

    # Score the IOC
    scored_ioc = scorer.enrich_ioc_with_score(test_ioc)

    print("\n=== Threat Scoring Example ===")
    print(f"IOC: {scored_ioc['value']}")
    print(f"Type: {scored_ioc['type']}")
    print(f"Threat Score: {scored_ioc['threat_score']}/100")
    print(f"Severity: {scored_ioc['severity']}")
    print(f"Sources: {', '.join(scored_ioc['sources'])}")
    print(f"Tags: {', '.join(scored_ioc['tags'])}")

    # Test batch scoring
    test_batch = [
        {
            'value': '1.2.3.4',
            'source': 'VirusTotal',
            'tags': ['ransomware'],
            'first_seen': datetime.utcnow().isoformat(),
            'sightings': 10,
            'sources': ['VirusTotal', 'AbuseIPDB']
        },
        {
            'value': 'test.com',
            'source': 'URLhaus',
            'tags': ['phishing'],
            'first_seen': (datetime.utcnow() - timedelta(days=30)).isoformat(),
            'sightings': 2,
            'sources': ['URLhaus']
        }
    ]

    scored_batch = scorer.batch_score(test_batch)
    distribution = scorer.get_score_distribution(scored_batch)

    print("\n=== Batch Scoring Results ===")
    print(json.dumps(distribution, indent=2))
