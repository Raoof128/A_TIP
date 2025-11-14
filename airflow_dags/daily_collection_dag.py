"""
Daily Threat Intelligence Collection DAG
Runs collectors every 6 hours and processes IOCs
"""

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from datetime import timedelta
import sys
import os

# Add project paths to Python path
sys.path.insert(0, '/opt/airflow/collectors')
sys.path.insert(0, '/opt/airflow/correlation')
sys.path.insert(0, '/opt/airflow/enrichment')

import logging

logger = logging.getLogger(__name__)

# Default arguments
default_args = {
    'owner': 'security-team',
    'depends_on_past': False,
    'email': ['security@example.com'],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
}

# Initialize DAG
dag = DAG(
    'threat_intel_collection',
    default_args=default_args,
    description='Collect and process threat intelligence IOCs',
    schedule_interval='0 */6 * * *',  # Every 6 hours
    start_date=days_ago(1),
    catchup=False,
    tags=['security', 'threat-intel'],
)


def collect_alienvault(**context):
    """Collect IOCs from AlienVault OTX"""
    logger.info("Starting AlienVault OTX collection...")

    try:
        from alienvault_otx import AlienVaultCollector

        api_key = os.getenv('OTX_API_KEY')
        if not api_key:
            logger.warning("OTX_API_KEY not set, skipping AlienVault collection")
            return 0

        collector = AlienVaultCollector(api_key)
        iocs = collector.collect(limit=500)

        # Store in XCom for next task
        context['ti'].xcom_push(key='alienvault_iocs', value=[ioc.to_dict() for ioc in iocs])

        logger.info(f"Collected {len(iocs)} IOCs from AlienVault OTX")
        return len(iocs)

    except Exception as e:
        logger.error(f"Error in AlienVault collection: {str(e)}")
        return 0


def collect_urlhaus(**context):
    """Collect IOCs from URLhaus"""
    logger.info("Starting URLhaus collection...")

    try:
        from urlhaus_collector import URLhausCollector

        collector = URLhausCollector()
        iocs = collector.collect(limit=1000)

        # Store in XCom for next task
        context['ti'].xcom_push(key='urlhaus_iocs', value=[ioc.to_dict() for ioc in iocs])

        logger.info(f"Collected {len(iocs)} IOCs from URLhaus")
        return len(iocs)

    except Exception as e:
        logger.error(f"Error in URLhaus collection: {str(e)}")
        return 0


def collect_abuseipdb(**context):
    """Collect IOCs from AbuseIPDB"""
    logger.info("Starting AbuseIPDB collection...")

    try:
        from abuseipdb_collector import AbuseIPDBCollector

        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            logger.warning("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB collection")
            return 0

        collector = AbuseIPDBCollector(api_key)
        iocs = collector.collect(limit=1000, confidence_minimum=80)

        # Store in XCom for next task
        context['ti'].xcom_push(key='abuseipdb_iocs', value=[ioc.to_dict() for ioc in iocs])

        logger.info(f"Collected {len(iocs)} IOCs from AbuseIPDB")
        return len(iocs)

    except Exception as e:
        logger.error(f"Error in AbuseIPDB collection: {str(e)}")
        return 0


def deduplicate_iocs(**context):
    """Deduplicate collected IOCs"""
    logger.info("Starting deduplication...")

    try:
        from elasticsearch import Elasticsearch
        from deduplication import DeduplicationEngine

        # Get IOCs from all collectors
        ti = context['ti']
        alienvault_iocs = ti.xcom_pull(key='alienvault_iocs', task_ids='collect_alienvault') or []
        urlhaus_iocs = ti.xcom_pull(key='urlhaus_iocs', task_ids='collect_urlhaus') or []
        abuseipdb_iocs = ti.xcom_pull(key='abuseipdb_iocs', task_ids='collect_abuseipdb') or []

        all_iocs = alienvault_iocs + urlhaus_iocs + abuseipdb_iocs

        logger.info(f"Total IOCs to process: {len(all_iocs)}")

        # Initialize deduplication engine
        es = Elasticsearch(['http://tip-elasticsearch:9200'])

        # Wait for Elasticsearch to be ready
        if not es.ping():
            logger.error("Elasticsearch not available")
            return {'new': [], 'updated': [], 'duplicates': []}

        dedup_engine = DeduplicationEngine(es)

        # Create index if it doesn't exist
        dedup_engine.create_index_if_not_exists()

        # Deduplicate
        results = dedup_engine.deduplicate_batch(all_iocs)

        # Store results
        ti.xcom_push(key='new_iocs', value=results['new'])
        ti.xcom_push(key='updated_iocs', value=results['updated'])

        logger.info(f"Deduplication complete: {len(results['new'])} new, {len(results['updated'])} updated")
        return results

    except Exception as e:
        logger.error(f"Error in deduplication: {str(e)}")
        return {'new': [], 'updated': [], 'duplicates': []}


def enrich_iocs(**context):
    """Enrich IOCs with additional data"""
    logger.info("Starting enrichment...")

    try:
        from threat_score_engine import ThreatScoreEngine
        from geoip_enricher import GeoIPEnricher

        ti = context['ti']
        new_iocs = ti.xcom_pull(key='new_iocs', task_ids='deduplicate_iocs') or []

        if not new_iocs:
            logger.info("No new IOCs to enrich")
            return 0

        # Initialize enrichment engines
        scorer = ThreatScoreEngine()
        geoip_enricher = GeoIPEnricher()

        # Enrich each IOC
        enriched_iocs = []
        for ioc in new_iocs:
            # Add threat score
            enriched = scorer.enrich_ioc_with_score(ioc)

            # Add GeoIP data for IPs
            if enriched['type'] == 'ip':
                enriched = geoip_enricher.enrich_ioc(enriched)

            enriched_iocs.append(enriched)

        ti.xcom_push(key='enriched_iocs', value=enriched_iocs)

        logger.info(f"Enriched {len(enriched_iocs)} IOCs")
        return len(enriched_iocs)

    except Exception as e:
        logger.error(f"Error in enrichment: {str(e)}")
        return 0


def save_to_elasticsearch(**context):
    """Save processed IOCs to Elasticsearch"""
    logger.info("Saving to Elasticsearch...")

    try:
        from elasticsearch import Elasticsearch, helpers

        ti = context['ti']
        enriched_iocs = ti.xcom_pull(key='enriched_iocs', task_ids='enrich_iocs') or []

        if not enriched_iocs:
            logger.info("No IOCs to save")
            return 0

        es = Elasticsearch(['http://tip-elasticsearch:9200'])

        actions = [
            {
                '_index': 'threat-intel-iocs',
                '_id': ioc['ioc_id'],
                '_source': ioc
            }
            for ioc in enriched_iocs
        ]

        success, failed = helpers.bulk(es, actions, raise_on_error=False)

        logger.info(f"Saved {success} IOCs to Elasticsearch, {failed} failed")
        return success

    except Exception as e:
        logger.error(f"Error saving to Elasticsearch: {str(e)}")
        return 0


def generate_daily_report(**context):
    """Generate daily collection report"""
    logger.info("Generating daily report...")

    ti = context['ti']

    # Get all metrics
    alienvault_count = ti.xcom_pull(task_ids='collect_alienvault') or 0
    urlhaus_count = ti.xcom_pull(task_ids='collect_urlhaus') or 0
    abuseipdb_count = ti.xcom_pull(task_ids='collect_abuseipdb') or 0
    dedup_results = ti.xcom_pull(task_ids='deduplicate_iocs') or {'new': [], 'updated': [], 'duplicates': []}
    enriched_count = ti.xcom_pull(task_ids='enrich_iocs') or 0
    saved_count = ti.xcom_pull(task_ids='save_to_elasticsearch') or 0

    report = f"""
=================================
Threat Intelligence Daily Report
{context['ds']}
=================================

Collection:
- AlienVault OTX: {alienvault_count} IOCs
- URLhaus: {urlhaus_count} IOCs
- AbuseIPDB: {abuseipdb_count} IOCs
- TOTAL COLLECTED: {alienvault_count + urlhaus_count + abuseipdb_count} IOCs

Deduplication:
- New IOCs: {len(dedup_results.get('new', []))}
- Updated IOCs: {len(dedup_results.get('updated', []))}
- Duplicates: {len(dedup_results.get('duplicates', []))}

Processing:
- Enriched: {enriched_count} IOCs
- Saved: {saved_count} IOCs

=================================
    """

    logger.info(report)
    print(report)

    return report


# Define tasks
task_collect_alienvault = PythonOperator(
    task_id='collect_alienvault',
    python_callable=collect_alienvault,
    dag=dag,
)

task_collect_urlhaus = PythonOperator(
    task_id='collect_urlhaus',
    python_callable=collect_urlhaus,
    dag=dag,
)

task_collect_abuseipdb = PythonOperator(
    task_id='collect_abuseipdb',
    python_callable=collect_abuseipdb,
    dag=dag,
)

task_deduplicate = PythonOperator(
    task_id='deduplicate_iocs',
    python_callable=deduplicate_iocs,
    dag=dag,
)

task_enrich = PythonOperator(
    task_id='enrich_iocs',
    python_callable=enrich_iocs,
    dag=dag,
)

task_save = PythonOperator(
    task_id='save_to_elasticsearch',
    python_callable=save_to_elasticsearch,
    dag=dag,
)

task_report = PythonOperator(
    task_id='generate_daily_report',
    python_callable=generate_daily_report,
    dag=dag,
)

# Define task dependencies
# Collect from all sources in parallel, then deduplicate, enrich, save, and report
[task_collect_alienvault, task_collect_urlhaus, task_collect_abuseipdb] >> task_deduplicate >> task_enrich >> task_save >> task_report
