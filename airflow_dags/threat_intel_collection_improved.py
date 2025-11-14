"""
Enhanced Threat Intelligence Collection DAG
Runs collectors every 6 hours with comprehensive error handling,
monitoring, and recovery mechanisms.
"""

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from airflow.exceptions import AirflowException, AirflowFailException
from datetime import timedelta, datetime
import sys
import os
import logging
import time
import traceback
from typing import Dict, List, Any, Optional
from functools import wraps

# Add project paths to Python path
sys.path.insert(0, '/opt/airflow/collectors')
sys.path.insert(0, '/opt/airflow/correlation')
sys.path.insert(0, '/opt/airflow/enrichment')

logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================

DEFAULT_ARGS = {
    'owner': 'security-team',
    'depends_on_past': False,
    'email': ['security@example.com'],
    'email_on_failure': True,
    'email_on_retry': True,
    'retries': 3,
    'retry_delay': timedelta(minutes=5),
    'retry_exponential_backoff': True,
    'max_retry_delay': timedelta(minutes=30),
    'sla': timedelta(hours=2),  # Task must complete within 2 hours
    'execution_timeout': timedelta(hours=1),  # Max execution time per task
}

# Collector-specific configurations
COLLECTOR_CONFIGS = {
    'alienvault': {
        'limit': 500,
        'timeout': 300,
        'retry_attempts': 3,
    },
    'urlhaus': {
        'limit': 1000,
        'timeout': 180,
        'retry_attempts': 3,
    },
    'abuseipdb': {
        'limit': 1000,
        'confidence_minimum': 80,
        'timeout': 300,
        'retry_attempts': 3,
    }
}

# ==================== UTILITY FUNCTIONS ====================

class CollectionMetrics:
    """Track collection metrics for monitoring"""

    def __init__(self):
        self.metrics = {
            'start_time': datetime.utcnow(),
            'collectors': {},
            'processing': {},
            'errors': []
        }

    def record_collector(self, name: str, count: int, duration: float, errors: int = 0):
        """Record collector metrics"""
        self.metrics['collectors'][name] = {
            'count': count,
            'duration': duration,
            'errors': errors,
            'timestamp': datetime.utcnow().isoformat()
        }

    def record_processing(self, stage: str, count: int, duration: float):
        """Record processing stage metrics"""
        self.metrics['processing'][stage] = {
            'count': count,
            'duration': duration,
            'timestamp': datetime.utcnow().isoformat()
        }

    def add_error(self, stage: str, error: str, details: str = None):
        """Record an error"""
        self.metrics['errors'].append({
            'stage': stage,
            'error': error,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })

    def to_dict(self) -> Dict:
        """Export metrics as dictionary"""
        self.metrics['end_time'] = datetime.utcnow()
        self.metrics['total_duration'] = (
            self.metrics['end_time'] - self.metrics['start_time']
        ).total_seconds()
        return self.metrics


def retry_with_backoff(max_attempts: int = 3, base_delay: float = 2.0):
    """Decorator for retry with exponential backoff"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {str(e)}. "
                        f"Retrying in {delay}s..."
                    )
                    time.sleep(delay)

        return wrapper

    return decorator


def validate_xcom_data(data: Any, expected_type: type, min_length: int = 0) -> bool:
    """Validate XCom data"""
    if data is None:
        return False
    if not isinstance(data, expected_type):
        logger.error(f"XCom data type mismatch. Expected {expected_type}, got {type(data)}")
        return False
    if isinstance(data, (list, dict)) and len(data) < min_length:
        logger.warning(f"XCom data length {len(data)} below minimum {min_length}")
    return True


def check_elasticsearch_health(es_client, max_retries: int = 5) -> bool:
    """Check Elasticsearch health with retries"""
    for attempt in range(max_retries):
        try:
            if es_client.ping():
                health = es_client.cluster.health()
                status = health['status']
                if status in ['green', 'yellow']:
                    logger.info(f"Elasticsearch cluster is {status}")
                    return True
                else:
                    logger.warning(f"Elasticsearch cluster status is {status}")
                    time.sleep(5 * (attempt + 1))
            else:
                logger.warning(f"Elasticsearch ping failed (attempt {attempt + 1}/{max_retries})")
                time.sleep(5 * (attempt + 1))
        except Exception as e:
            logger.warning(f"Elasticsearch health check failed: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(5 * (attempt + 1))
            else:
                raise

    return False


def task_failure_callback(context):
    """Callback executed when a task fails"""
    task_instance = context['task_instance']
    exception = context.get('exception')

    error_msg = f"""
    ===============================================
    TASK FAILURE ALERT
    ===============================================
    Task: {task_instance.task_id}
    DAG: {task_instance.dag_id}
    Execution Date: {context['execution_date']}
    Try Number: {task_instance.try_number}
    Max Tries: {task_instance.max_tries}

    Exception: {exception}

    Logs: {task_instance.log_url}
    ===============================================
    """

    logger.error(error_msg)

    # Could send to monitoring system here
    # send_to_monitoring_system(error_msg)


def task_success_callback(context):
    """Callback executed when a task succeeds"""
    task_instance = context['task_instance']
    logger.info(f"Task {task_instance.task_id} completed successfully")


def sla_miss_callback(dag, task_list, blocking_task_list, slas, blocking_tis):
    """Callback executed when SLA is missed"""
    logger.error(
        f"SLA MISSED for tasks: {[task.task_id for task in task_list]}"
    )
    # Send alert to monitoring system


# ==================== COLLECTION TASKS ====================

def collect_alienvault(**context):
    """Collect IOCs from AlienVault OTX with comprehensive error handling"""
    logger.info("="*60)
    logger.info("Starting AlienVault OTX collection...")
    start_time = time.time()

    try:
        from alienvault_otx import AlienVaultCollector
        from base_collector import APIKeyError, RateLimitError, NetworkError

        api_key = os.getenv('OTX_API_KEY')
        if not api_key:
            logger.warning("OTX_API_KEY not set, skipping AlienVault collection")
            context['ti'].xcom_push(key='alienvault_iocs', value=[])
            context['ti'].xcom_push(key='alienvault_metrics', value={
                'count': 0,
                'skipped': True,
                'reason': 'API key not configured'
            })
            return 0

        config = COLLECTOR_CONFIGS['alienvault']

        # Initialize collector
        collector = AlienVaultCollector(api_key)

        # Collect with retry
        @retry_with_backoff(max_attempts=config['retry_attempts'])
        def collect_with_retry():
            return collector.collect(limit=config['limit'])

        iocs = collect_with_retry()

        # Validate results
        if not iocs:
            logger.warning("No IOCs collected from AlienVault OTX")

        # Convert to dict for XCom
        iocs_dict = [ioc.to_dict() for ioc in iocs]

        # Store in XCom
        context['ti'].xcom_push(key='alienvault_iocs', value=iocs_dict)

        # Store metrics
        duration = time.time() - start_time
        metrics = {
            'count': len(iocs),
            'duration': duration,
            'errors': len(collector.errors),
            'warnings': len(collector.warnings),
            'rate_limited': collector.stats.get('rate_limited', 0)
        }
        context['ti'].xcom_push(key='alienvault_metrics', value=metrics)

        logger.info(f"✓ Collected {len(iocs)} IOCs from AlienVault OTX in {duration:.2f}s")
        logger.info(f"  Errors: {metrics['errors']}, Warnings: {metrics['warnings']}")
        logger.info("="*60)

        return len(iocs)

    except APIKeyError as e:
        logger.error(f"API Key error: {str(e)}")
        context['ti'].xcom_push(key='alienvault_iocs', value=[])
        return 0

    except RateLimitError as e:
        logger.error(f"Rate limit exceeded: {str(e)}")
        # Don't fail the task, just return 0
        context['ti'].xcom_push(key='alienvault_iocs', value=[])
        return 0

    except NetworkError as e:
        logger.error(f"Network error: {str(e)}")
        # Retry will be handled by Airflow
        raise AirflowException(f"Network error in AlienVault collection: {str(e)}")

    except Exception as e:
        logger.error(f"Unexpected error in AlienVault collection: {str(e)}")
        logger.error(traceback.format_exc())
        context['ti'].xcom_push(key='alienvault_iocs', value=[])
        # Don't fail the entire DAG for one collector
        return 0


def collect_urlhaus(**context):
    """Collect IOCs from URLhaus with comprehensive error handling"""
    logger.info("="*60)
    logger.info("Starting URLhaus collection...")
    start_time = time.time()

    try:
        from urlhaus_collector import URLhausCollector

        config = COLLECTOR_CONFIGS['urlhaus']

        # Initialize collector
        collector = URLhausCollector()

        # Collect with retry
        @retry_with_backoff(max_attempts=config['retry_attempts'])
        def collect_with_retry():
            return collector.collect(limit=config['limit'])

        iocs = collect_with_retry()

        # Validate results
        if not iocs:
            logger.warning("No IOCs collected from URLhaus")

        # Convert to dict for XCom
        iocs_dict = [ioc.to_dict() for ioc in iocs]

        # Store in XCom
        context['ti'].xcom_push(key='urlhaus_iocs', value=iocs_dict)

        # Store metrics
        duration = time.time() - start_time
        metrics = {
            'count': len(iocs),
            'duration': duration,
            'errors': len(collector.errors),
            'warnings': len(collector.warnings),
        }
        context['ti'].xcom_push(key='urlhaus_metrics', value=metrics)

        logger.info(f"✓ Collected {len(iocs)} IOCs from URLhaus in {duration:.2f}s")
        logger.info("="*60)

        return len(iocs)

    except Exception as e:
        logger.error(f"Error in URLhaus collection: {str(e)}")
        logger.error(traceback.format_exc())
        context['ti'].xcom_push(key='urlhaus_iocs', value=[])
        return 0


def collect_abuseipdb(**context):
    """Collect IOCs from AbuseIPDB with comprehensive error handling"""
    logger.info("="*60)
    logger.info("Starting AbuseIPDB collection...")
    start_time = time.time()

    try:
        from abuseipdb_collector import AbuseIPDBCollector
        from base_collector import APIKeyError, RateLimitError

        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            logger.warning("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB collection")
            context['ti'].xcom_push(key='abuseipdb_iocs', value=[])
            return 0

        config = COLLECTOR_CONFIGS['abuseipdb']

        # Initialize collector
        collector = AbuseIPDBCollector(api_key)

        # Collect with retry
        @retry_with_backoff(max_attempts=config['retry_attempts'])
        def collect_with_retry():
            return collector.collect(
                limit=config['limit'],
                confidence_minimum=config['confidence_minimum']
            )

        iocs = collect_with_retry()

        # Validate results
        if not iocs:
            logger.warning("No IOCs collected from AbuseIPDB")

        # Convert to dict for XCom
        iocs_dict = [ioc.to_dict() for ioc in iocs]

        # Store in XCom
        context['ti'].xcom_push(key='abuseipdb_iocs', value=iocs_dict)

        # Store metrics
        duration = time.time() - start_time
        metrics = {
            'count': len(iocs),
            'duration': duration,
            'errors': len(collector.errors),
            'warnings': len(collector.warnings),
            'rate_limited': collector.stats.get('rate_limited', 0)
        }
        context['ti'].xcom_push(key='abuseipdb_metrics', value=metrics)

        logger.info(f"✓ Collected {len(iocs)} IOCs from AbuseIPDB in {duration:.2f}s")
        logger.info("="*60)

        return len(iocs)

    except APIKeyError as e:
        logger.error(f"API Key error: {str(e)}")
        context['ti'].xcom_push(key='abuseipdb_iocs', value=[])
        return 0

    except RateLimitError as e:
        logger.error(f"Rate limit exceeded: {str(e)}")
        context['ti'].xcom_push(key='abuseipdb_iocs', value=[])
        return 0

    except Exception as e:
        logger.error(f"Error in AbuseIPDB collection: {str(e)}")
        logger.error(traceback.format_exc())
        context['ti'].xcom_push(key='abuseipdb_iocs', value=[])
        return 0


# ==================== PROCESSING TASKS ====================

def deduplicate_iocs(**context):
    """Deduplicate collected IOCs with enhanced error handling"""
    logger.info("="*60)
    logger.info("Starting deduplication...")
    start_time = time.time()

    try:
        from elasticsearch import Elasticsearch
        from deduplication import DeduplicationEngine

        ti = context['ti']

        # Get IOCs from all collectors with validation
        alienvault_iocs = ti.xcom_pull(key='alienvault_iocs', task_ids='collect_alienvault') or []
        urlhaus_iocs = ti.xcom_pull(key='urlhaus_iocs', task_ids='collect_urlhaus') or []
        abuseipdb_iocs = ti.xcom_pull(key='abuseipdb_iocs', task_ids='collect_abuseipdb') or []

        # Validate XCom data
        validate_xcom_data(alienvault_iocs, list)
        validate_xcom_data(urlhaus_iocs, list)
        validate_xcom_data(abuseipdb_iocs, list)

        all_iocs = alienvault_iocs + urlhaus_iocs + abuseipdb_iocs

        logger.info(f"Total IOCs to process: {len(all_iocs)}")
        logger.info(f"  AlienVault: {len(alienvault_iocs)}")
        logger.info(f"  URLhaus: {len(urlhaus_iocs)}")
        logger.info(f"  AbuseIPDB: {len(abuseipdb_iocs)}")

        if not all_iocs:
            logger.warning("No IOCs to deduplicate")
            empty_results = {'new': [], 'updated': [], 'duplicates': []}
            ti.xcom_push(key='dedup_results', value=empty_results)
            return empty_results

        # Initialize Elasticsearch with retry
        es = Elasticsearch(
            ['http://tip-elasticsearch:9200'],
            retry_on_timeout=True,
            max_retries=3
        )

        # Health check
        if not check_elasticsearch_health(es):
            raise AirflowFailException("Elasticsearch is not healthy")

        # Initialize deduplication engine
        dedup_engine = DeduplicationEngine(es)

        # Ensure index exists
        dedup_engine.create_index_if_not_exists()

        # Deduplicate with retry
        @retry_with_backoff(max_attempts=3)
        def deduplicate_with_retry():
            return dedup_engine.deduplicate_batch(all_iocs)

        results = deduplicate_with_retry()

        # Store results
        ti.xcom_push(key='dedup_results', value=results)
        ti.xcom_push(key='new_iocs', value=results['new'])
        ti.xcom_push(key='updated_iocs', value=results['updated'])

        duration = time.time() - start_time

        logger.info(f"✓ Deduplication complete in {duration:.2f}s:")
        logger.info(f"  New IOCs: {len(results['new'])}")
        logger.info(f"  Updated IOCs: {len(results['updated'])}")
        logger.info(f"  Duplicates: {len(results['duplicates'])}")
        logger.info(f"  Deduplication rate: {(len(results['duplicates'])/len(all_iocs)*100):.1f}%")
        logger.info("="*60)

        return results

    except Exception as e:
        logger.error(f"Error in deduplication: {str(e)}")
        logger.error(traceback.format_exc())
        raise AirflowFailException(f"Deduplication failed: {str(e)}")


def enrich_iocs(**context):
    """Enrich IOCs with additional data"""
    logger.info("="*60)
    logger.info("Starting enrichment...")
    start_time = time.time()

    try:
        from threat_score_engine import ThreatScoreEngine
        from geoip_enricher import GeoIPEnricher

        ti = context['ti']
        new_iocs = ti.xcom_pull(key='new_iocs', task_ids='deduplicate_iocs') or []

        if not validate_xcom_data(new_iocs, list):
            logger.warning("Invalid or missing IOC data for enrichment")
            ti.xcom_push(key='enriched_iocs', value=[])
            return 0

        if not new_iocs:
            logger.info("No new IOCs to enrich")
            ti.xcom_push(key='enriched_iocs', value=[])
            return 0

        logger.info(f"Enriching {len(new_iocs)} IOCs...")

        # Initialize enrichment engines with error handling
        try:
            scorer = ThreatScoreEngine()
            geoip_enricher = GeoIPEnricher()
        except Exception as e:
            logger.error(f"Failed to initialize enrichment engines: {str(e)}")
            raise AirflowFailException("Enrichment initialization failed")

        # Enrich each IOC
        enriched_iocs = []
        failed_iocs = []

        for i, ioc in enumerate(new_iocs):
            try:
                # Add threat score
                enriched = scorer.enrich_ioc_with_score(ioc)

                # Add GeoIP data for IPs
                if enriched.get('type') == 'ip':
                    enriched = geoip_enricher.enrich_ioc(enriched)

                enriched_iocs.append(enriched)

                # Log progress every 100 IOCs
                if (i + 1) % 100 == 0:
                    logger.info(f"  Progress: {i + 1}/{len(new_iocs)} IOCs enriched")

            except Exception as e:
                logger.warning(f"Failed to enrich IOC {ioc.get('value', 'unknown')}: {str(e)}")
                failed_iocs.append(ioc)
                # Continue with next IOC

        ti.xcom_push(key='enriched_iocs', value=enriched_iocs)
        ti.xcom_push(key='failed_enrichments', value=failed_iocs)

        duration = time.time() - start_time

        logger.info(f"✓ Enrichment complete in {duration:.2f}s:")
        logger.info(f"  Successfully enriched: {len(enriched_iocs)}")
        logger.info(f"  Failed: {len(failed_iocs)}")
        logger.info("="*60)

        return len(enriched_iocs)

    except AirflowFailException:
        raise
    except Exception as e:
        logger.error(f"Error in enrichment: {str(e)}")
        logger.error(traceback.format_exc())
        raise AirflowFailException(f"Enrichment failed: {str(e)}")


def save_to_elasticsearch(**context):
    """Save processed IOCs to Elasticsearch with bulk operations"""
    logger.info("="*60)
    logger.info("Saving to Elasticsearch...")
    start_time = time.time()

    try:
        from elasticsearch import Elasticsearch, helpers

        ti = context['ti']
        enriched_iocs = ti.xcom_pull(key='enriched_iocs', task_ids='enrich_iocs') or []

        if not validate_xcom_data(enriched_iocs, list):
            logger.warning("Invalid or missing enriched IOC data")
            return 0

        if not enriched_iocs:
            logger.info("No IOCs to save")
            return 0

        logger.info(f"Preparing to save {len(enriched_iocs)} IOCs...")

        # Initialize Elasticsearch
        es = Elasticsearch(
            ['http://tip-elasticsearch:9200'],
            retry_on_timeout=True,
            max_retries=3,
            timeout=30
        )

        # Health check
        if not check_elasticsearch_health(es):
            raise AirflowFailException("Elasticsearch is not healthy")

        # Prepare bulk actions
        actions = []
        for ioc in enriched_iocs:
            action = {
                '_index': 'threat-intel-iocs',
                '_id': ioc.get('ioc_id'),
                '_source': ioc
            }
            actions.append(action)

        # Bulk insert with retry
        @retry_with_backoff(max_attempts=3)
        def bulk_insert():
            return helpers.bulk(
                es,
                actions,
                raise_on_error=False,
                request_timeout=60
            )

        success, errors = bulk_insert()

        # Process errors
        if errors:
            logger.warning(f"Bulk operation had {len(errors)} errors")
            for error in errors[:10]:  # Log first 10 errors
                logger.warning(f"  Error: {error}")

        duration = time.time() - start_time

        logger.info(f"✓ Save complete in {duration:.2f}s:")
        logger.info(f"  Successfully saved: {success}")
        logger.info(f"  Failed: {len(errors) if errors else 0}")
        logger.info("="*60)

        # Store metrics
        ti.xcom_push(key='save_metrics', value={
            'success': success,
            'failed': len(errors) if errors else 0,
            'duration': duration
        })

        return success

    except Exception as e:
        logger.error(f"Error saving to Elasticsearch: {str(e)}")
        logger.error(traceback.format_exc())
        raise AirflowFailException(f"Save operation failed: {str(e)}")


def generate_comprehensive_report(**context):
    """Generate comprehensive collection report with all metrics"""
    logger.info("="*60)
    logger.info("Generating comprehensive report...")

    ti = context['ti']

    # Gather all metrics
    alienvault_metrics = ti.xcom_pull(key='alienvault_metrics', task_ids='collect_alienvault') or {}
    urlhaus_metrics = ti.xcom_pull(key='urlhaus_metrics', task_ids='collect_urlhaus') or {}
    abuseipdb_metrics = ti.xcom_pull(key='abuseipdb_metrics', task_ids='collect_abuseipdb') or {}
    dedup_results = ti.xcom_pull(key='dedup_results', task_ids='deduplicate_iocs') or {}
    save_metrics = ti.xcom_pull(key='save_metrics', task_ids='save_to_elasticsearch') or {}

    # Calculate totals
    total_collected = (
        alienvault_metrics.get('count', 0) +
        urlhaus_metrics.get('count', 0) +
        abuseipdb_metrics.get('count', 0)
    )

    total_errors = (
        alienvault_metrics.get('errors', 0) +
        urlhaus_metrics.get('errors', 0) +
        abuseipdb_metrics.get('errors', 0)
    )

    # Generate report
    report = f"""
{'='*70}
    THREAT INTELLIGENCE PLATFORM - COLLECTION REPORT
    Execution Date: {context['ds']}
    Run ID: {context['run_id']}
{'='*70}

COLLECTION SUMMARY:
  AlienVault OTX:  {alienvault_metrics.get('count', 0):>6} IOCs  ({alienvault_metrics.get('duration', 0):.1f}s)
  URLhaus:         {urlhaus_metrics.get('count', 0):>6} IOCs  ({urlhaus_metrics.get('duration', 0):.1f}s)
  AbuseIPDB:       {abuseipdb_metrics.get('count', 0):>6} IOCs  ({abuseipdb_metrics.get('duration', 0):.1f}s)
  {'─'*68}
  TOTAL COLLECTED: {total_collected:>6} IOCs

DEDUPLICATION:
  New IOCs:        {len(dedup_results.get('new', [])):>6}
  Updated IOCs:    {len(dedup_results.get('updated', [])):>6}
  Duplicates:      {len(dedup_results.get('duplicates', [])):>6}
  Dedup Rate:      {(len(dedup_results.get('duplicates', []))/max(total_collected, 1)*100):>5.1f}%

STORAGE:
  Saved:           {save_metrics.get('success', 0):>6} IOCs
  Failed:          {save_metrics.get('failed', 0):>6} IOCs
  Duration:        {save_metrics.get('duration', 0):>5.1f}s

ERROR SUMMARY:
  Collection Errors: {total_errors}
  Rate Limited:      {alienvault_metrics.get('rate_limited', 0) + abuseipdb_metrics.get('rate_limited', 0)}

PERFORMANCE:
  Total Duration:  {sum([
      alienvault_metrics.get('duration', 0),
      urlhaus_metrics.get('duration', 0),
      abuseipdb_metrics.get('duration', 0),
      save_metrics.get('duration', 0)
  ]):.1f}s

STATUS: {'✓ SUCCESS' if total_errors == 0 else '⚠ COMPLETED WITH ERRORS'}

{'='*70}
    """

    logger.info(report)
    print(report)

    # Store report
    ti.xcom_push(key='collection_report', value=report)

    logger.info("="*60)

    return report


# ==================== DAG DEFINITION ====================

dag = DAG(
    'threat_intel_collection_improved',
    default_args=DEFAULT_ARGS,
    description='Enhanced threat intelligence collection with comprehensive error handling',
    schedule_interval='0 */6 * * *',  # Every 6 hours
    start_date=days_ago(1),
    catchup=False,
    tags=['security', 'threat-intel', 'production'],
    sla_miss_callback=sla_miss_callback,
    max_active_runs=1,  # Prevent overlapping runs
)

# Define tasks with callbacks
task_collect_alienvault = PythonOperator(
    task_id='collect_alienvault',
    python_callable=collect_alienvault,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_collect_urlhaus = PythonOperator(
    task_id='collect_urlhaus',
    python_callable=collect_urlhaus,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_collect_abuseipdb = PythonOperator(
    task_id='collect_abuseipdb',
    python_callable=collect_abuseipdb,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_deduplicate = PythonOperator(
    task_id='deduplicate_iocs',
    python_callable=deduplicate_iocs,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_enrich = PythonOperator(
    task_id='enrich_iocs',
    python_callable=enrich_iocs,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_save = PythonOperator(
    task_id='save_to_elasticsearch',
    python_callable=save_to_elasticsearch,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    dag=dag,
)

task_report = PythonOperator(
    task_id='generate_comprehensive_report',
    python_callable=generate_comprehensive_report,
    on_failure_callback=task_failure_callback,
    on_success_callback=task_success_callback,
    trigger_rule='all_done',  # Run even if upstream tasks fail
    dag=dag,
)

# Define task dependencies
# Collectors run in parallel, then sequential processing
[task_collect_alienvault, task_collect_urlhaus, task_collect_abuseipdb] >> \
    task_deduplicate >> task_enrich >> task_save >> task_report
