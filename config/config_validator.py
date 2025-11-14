"""
Configuration Validator for Threat Intelligence Platform
Validates configuration files and environment variables
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import yaml


class ConfigurationError(Exception):
    """Custom exception for configuration errors"""
    pass


class ConfigValidator:
    """Validates TIP configuration"""

    REQUIRED_ENV_VARS = {
        'collectors': {
            'alienvault_otx': ['OTX_API_KEY'],
            'abuseipdb': ['ABUSEIPDB_API_KEY'],
            'virustotal': ['VT_API_KEY']
        }
    }

    OPTIONAL_ENV_VARS = [
        'MISP_API_KEY',
        'SECURITYTRAILS_API_KEY',
        'SHODAN_API_KEY',
        'PHISHTANK_API_KEY'
    ]

    def __init__(self, config_path: str = None):
        """
        Initialize configuration validator

        Args:
            config_path: Path to config.yaml file
        """
        self.config_path = config_path or Path(__file__).parent / "config.yaml"
        self.config = None
        self.errors = []
        self.warnings = []

    def load_config(self) -> Dict:
        """Load configuration file"""
        try:
            if not Path(self.config_path).exists():
                raise ConfigurationError(f"Configuration file not found: {self.config_path}")

            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)

            return self.config

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {e}")

    def validate_api_keys(self) -> List[str]:
        """
        Validate that required API keys are present

        Returns:
            List of missing API keys
        """
        missing_keys = []

        if not self.config:
            self.load_config()

        # Check each enabled collector
        collectors_config = self.config.get('collectors', {})

        for collector, env_vars in self.REQUIRED_ENV_VARS['collectors'].items():
            collector_config = collectors_config.get(collector, {})

            # Only check if collector is enabled
            if collector_config.get('enabled', False):
                for env_var in env_vars:
                    if not os.getenv(env_var):
                        missing_keys.append(env_var)
                        self.errors.append(
                            f"Missing API key: {env_var} (required for {collector})"
                        )

        return missing_keys

    def validate_elasticsearch_config(self) -> bool:
        """Validate Elasticsearch configuration"""
        if not self.config:
            self.load_config()

        es_config = self.config.get('elasticsearch', {})

        if not es_config.get('host'):
            self.errors.append("Elasticsearch host not configured")
            return False

        if not es_config.get('port'):
            self.warnings.append("Elasticsearch port not configured, using default 9200")

        return len(self.errors) == 0

    def validate_scoring_config(self) -> bool:
        """Validate threat scoring configuration"""
        if not self.config:
            self.load_config()

        scoring_config = self.config.get('scoring', {})
        weights = scoring_config.get('weights', {})

        # Check if weights sum to 1.0 (with tolerance)
        total_weight = sum(weights.values())
        if abs(total_weight - 1.0) > 0.01:
            self.errors.append(
                f"Scoring weights must sum to 1.0, got {total_weight}"
            )
            return False

        # Check required weight components
        required_weights = [
            'source_credibility',
            'sighting_frequency',
            'age_freshness',
            'multi_source',
            'tag_severity'
        ]

        for weight in required_weights:
            if weight not in weights:
                self.errors.append(f"Missing scoring weight: {weight}")

        return len(self.errors) == 0

    def validate_collectors_config(self) -> bool:
        """Validate collectors configuration"""
        if not self.config:
            self.load_config()

        collectors_config = self.config.get('collectors', {})

        if not collectors_config:
            self.warnings.append("No collectors configured")
            return True

        # Check that at least one collector is enabled
        enabled_collectors = [
            name for name, config in collectors_config.items()
            if config.get('enabled', False)
        ]

        if not enabled_collectors:
            self.warnings.append("No collectors are enabled")

        # Validate collection limits
        for collector, config in collectors_config.items():
            limit = config.get('collection_limit', 0)
            if limit < 0:
                self.errors.append(
                    f"{collector}: collection_limit must be positive"
                )
            elif limit > 100000:
                self.warnings.append(
                    f"{collector}: collection_limit is very high ({limit})"
                )

        return len(self.errors) == 0

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Run all validations

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []

        try:
            self.load_config()

            # Run all validations
            self.validate_api_keys()
            self.validate_elasticsearch_config()
            self.validate_scoring_config()
            self.validate_collectors_config()

            is_valid = len(self.errors) == 0

            return is_valid, self.errors, self.warnings

        except ConfigurationError as e:
            self.errors.append(str(e))
            return False, self.errors, self.warnings

    def print_report(self):
        """Print validation report"""
        is_valid, errors, warnings = self.validate_all()

        print("="*80)
        print("THREAT INTELLIGENCE PLATFORM - CONFIGURATION VALIDATION")
        print("="*80)

        if is_valid:
            print("\n✓ Configuration is VALID\n")
        else:
            print("\n✗ Configuration has ERRORS\n")

        if errors:
            print("ERRORS:")
            print("-"*80)
            for i, error in enumerate(errors, 1):
                print(f"  {i}. {error}")
            print()

        if warnings:
            print("WARNINGS:")
            print("-"*80)
            for i, warning in enumerate(warnings, 1):
                print(f"  {i}. {warning}")
            print()

        print("="*80)

        return is_valid

    def create_sample_env_file(self, output_path: str = None):
        """Create a sample .env file with all required variables"""
        if output_path is None:
            output_path = Path(__file__).parent / "api_keys.env.generated"

        lines = [
            "# Threat Intelligence Platform - Generated API Keys Configuration",
            "# Please fill in your actual API keys",
            "",
            "# REQUIRED API KEYS (get free keys from the URLs below)",
            ""
        ]

        if not self.config:
            self.load_config()

        collectors_config = self.config.get('collectors', {})

        for collector, env_vars in self.REQUIRED_ENV_VARS['collectors'].items():
            if collectors_config.get(collector, {}).get('enabled', False):
                lines.append(f"# {collector.replace('_', ' ').title()}")
                for env_var in env_vars:
                    lines.append(f"{env_var}=your_key_here")
                lines.append("")

        lines.append("# OPTIONAL API KEYS")
        lines.append("")
        for env_var in self.OPTIONAL_ENV_VARS:
            lines.append(f"# {env_var}=your_key_here")

        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))

        print(f"Sample environment file created: {output_path}")


def validate_environment() -> bool:
    """Quick validation of environment variables"""
    missing = []

    # Check for at least one collector API key
    if not os.getenv('OTX_API_KEY'):
        missing.append('OTX_API_KEY')

    if missing:
        print("WARNING: Missing API keys:", ", ".join(missing))
        print("Get your free API keys from:")
        print("  - AlienVault OTX: https://otx.alienvault.com/api")
        return False

    return True


if __name__ == "__main__":
    # Run validation
    validator = ConfigValidator()

    is_valid = validator.print_report()

    if not is_valid:
        print("\n⚠️  Please fix the errors before running the platform")
        sys.exit(1)
    else:
        print("\n✓ Configuration validated successfully!")

        # Check environment variables
        if not validate_environment():
            print("\n⚠️  Some API keys are missing")
            print("   Run: cp config/api_keys.env.example config/api_keys.env")
            print("   Then edit config/api_keys.env with your API keys")
            sys.exit(1)

        print("\n✓ Ready to start the Threat Intelligence Platform!")
        sys.exit(0)
