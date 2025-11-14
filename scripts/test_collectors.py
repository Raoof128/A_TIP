#!/usr/bin/env python3
"""
Standalone Collector Test Script
Test collectors without needing the full platform
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "collectors"))

import argparse
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import json

console = Console()


def test_urlhaus():
    """Test URLhaus collector (no API key needed)"""
    console.print("\n[bold blue]Testing URLhaus Collector[/bold blue]")
    console.print("=" * 60)

    try:
        from urlhaus_collector import URLhausCollector

        collector = URLhausCollector()
        console.print("[green]✓[/green] Collector initialized")

        console.print("\n[yellow]Collecting IOCs (limit: 10)...[/yellow]")
        iocs = collector.collect(limit=10)

        if iocs:
            console.print(f"[green]✓[/green] Collected {len(iocs)} IOCs")

            # Display first few
            table = Table(title="Sample IOCs from URLhaus")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="magenta", max_width=60)
            table.add_column("Confidence", style="green")

            for ioc in iocs[:5]:
                table.add_row(
                    ioc.ioc_type,
                    ioc.value[:60] + "..." if len(ioc.value) > 60 else ioc.value,
                    str(ioc.confidence)
                )

            console.print(table)

            # Metrics
            metrics = collector.get_metrics()
            console.print("\n[bold]Metrics:[/bold]")
            console.print(json.dumps(metrics, indent=2))

            return True, f"Collected {len(iocs)} IOCs successfully"
        else:
            return False, "No IOCs collected"

    except Exception as e:
        return False, f"Error: {str(e)}"


def test_alienvault(api_key):
    """Test AlienVault OTX collector"""
    console.print("\n[bold blue]Testing AlienVault OTX Collector[/bold blue]")
    console.print("=" * 60)

    if not api_key:
        return False, "API key required. Set OTX_API_KEY environment variable or use --otx-key"

    try:
        from alienvault_otx import AlienVaultCollector

        collector = AlienVaultCollector(api_key=api_key)
        console.print("[green]✓[/green] Collector initialized with API key")

        console.print("\n[yellow]Collecting IOCs (limit: 10)...[/yellow]")
        iocs = collector.collect(limit=10)

        if iocs:
            console.print(f"[green]✓[/green] Collected {len(iocs)} IOCs")

            # Display first few
            table = Table(title="Sample IOCs from AlienVault OTX")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Confidence", style="green")
            table.add_column("Tags", style="yellow")

            for ioc in iocs[:5]:
                table.add_row(
                    ioc.ioc_type,
                    ioc.value[:40] + "..." if len(ioc.value) > 40 else ioc.value,
                    str(ioc.confidence),
                    ", ".join(ioc.tags[:2])
                )

            console.print(table)

            # Metrics
            metrics = collector.get_metrics()
            console.print("\n[bold]Metrics:[/bold]")
            console.print(json.dumps(metrics, indent=2))

            return True, f"Collected {len(iocs)} IOCs successfully"
        else:
            return False, "No IOCs collected"

    except ImportError as e:
        return False, f"Missing dependency: {str(e)}. Run: pip install OTXv2"
    except Exception as e:
        return False, f"Error: {str(e)}"


def test_abuseipdb(api_key):
    """Test AbuseIPDB collector"""
    console.print("\n[bold blue]Testing AbuseIPDB Collector[/bold blue]")
    console.print("=" * 60)

    if not api_key:
        return False, "API key required. Set ABUSEIPDB_API_KEY environment variable or use --abuseipdb-key"

    try:
        from abuseipdb_collector import AbuseIPDBCollector

        collector = AbuseIPDBCollector(api_key=api_key)
        console.print("[green]✓[/green] Collector initialized with API key")

        console.print("\n[yellow]Collecting IOCs (limit: 10)...[/yellow]")
        iocs = collector.collect(limit=10, confidence_minimum=80)

        if iocs:
            console.print(f"[green]✓[/green] Collected {len(iocs)} IOCs")

            # Display all
            table = Table(title="Sample IOCs from AbuseIPDB")
            table.add_column("IP Address", style="cyan")
            table.add_column("Confidence", style="green")
            table.add_column("Tags", style="yellow")

            for ioc in iocs[:10]:
                table.add_row(
                    ioc.value,
                    str(ioc.confidence),
                    ", ".join(ioc.tags)
                )

            console.print(table)

            # Metrics
            metrics = collector.get_metrics()
            console.print("\n[bold]Metrics:[/bold]")
            console.print(json.dumps(metrics, indent=2))

            return True, f"Collected {len(iocs)} IOCs successfully"
        else:
            return False, "No IOCs collected"

    except Exception as e:
        return False, f"Error: {str(e)}"


def main():
    parser = argparse.ArgumentParser(
        description="Test Threat Intelligence Collectors",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test URLhaus (no API key needed)
  python test_collectors.py --urlhaus

  # Test AlienVault OTX (API key from environment)
  export OTX_API_KEY="your_key"
  python test_collectors.py --otx

  # Test AlienVault OTX (API key as argument)
  python test_collectors.py --otx --otx-key YOUR_API_KEY

  # Test all collectors
  python test_collectors.py --all

API Keys:
  Get your free API keys from:
  - AlienVault OTX: https://otx.alienvault.com/api
  - AbuseIPDB:      https://www.abuseipdb.com/api
  - VirusTotal:     https://www.virustotal.com/gui/my-apikey
        """
    )

    parser.add_argument('--urlhaus', action='store_true',
                       help='Test URLhaus collector')
    parser.add_argument('--otx', action='store_true',
                       help='Test AlienVault OTX collector')
    parser.add_argument('--abuseipdb', action='store_true',
                       help='Test AbuseIPDB collector')
    parser.add_argument('--all', action='store_true',
                       help='Test all collectors')

    parser.add_argument('--otx-key', help='AlienVault OTX API key')
    parser.add_argument('--abuseipdb-key', help='AbuseIPDB API key')

    args = parser.parse_args()

    # Get API keys from arguments or environment
    otx_key = args.otx_key or os.getenv('OTX_API_KEY')
    abuseipdb_key = args.abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')

    console.print("\n[bold green]Threat Intelligence Platform - Collector Tests[/bold green]")
    console.print("=" * 60)

    results = []

    # Determine what to test
    test_all = args.all or not (args.urlhaus or args.otx or args.abuseipdb)

    # Test URLhaus (always available, no API key needed)
    if test_all or args.urlhaus:
        success, message = test_urlhaus()
        results.append(("URLhaus", success, message))

    # Test AlienVault OTX
    if test_all or args.otx:
        success, message = test_alienvault(otx_key)
        results.append(("AlienVault OTX", success, message))

    # Test AbuseIPDB
    if test_all or args.abuseipdb:
        success, message = test_abuseipdb(abuseipdb_key)
        results.append(("AbuseIPDB", success, message))

    # Summary
    console.print("\n" + "=" * 60)
    console.print("[bold]Test Summary[/bold]")
    console.print("=" * 60)

    table = Table()
    table.add_column("Collector", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Message")

    for name, success, message in results:
        status = "[green]✓ PASS[/green]" if success else "[red]✗ FAIL[/red]"
        table.add_row(name, status, message)

    console.print(table)

    # Exit code
    all_passed = all(success for _, success, _ in results)
    console.print()

    if all_passed:
        console.print("[bold green]✓ All tests passed![/bold green]")
        sys.exit(0)
    else:
        console.print("[bold yellow]⚠ Some tests failed[/bold yellow]")
        console.print("\nTroubleshooting:")
        console.print("  - Check your API keys are correct")
        console.print("  - Ensure you have internet connection")
        console.print("  - Install required packages: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n\n[red]Unexpected error: {str(e)}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)
