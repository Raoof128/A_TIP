# Threat Intelligence Platform - Monitoring & Alerting Guide

This guide covers the monitoring and alerting setup for the Threat Intelligence Platform (TIP).

## Table of Contents

- [Overview](#overview)
- [Components](#components)
- [Configuration](#configuration)
- [Alert Rules](#alert-rules)
- [Setting Up Notifications](#setting-up-notifications)
- [Custom Metrics](#custom-metrics)
- [Troubleshooting](#troubleshooting)

## Overview

The TIP monitoring stack includes:

- **Prometheus**: Metrics collection and storage
- **Alertmanager**: Alert routing and notification
- **Grafana**: Visualization and dashboards
- **Node Exporter**: System-level metrics
- **cAdvisor**: Container metrics

### Architecture

```
┌─────────────┐
│  Services   │ (Elasticsearch, Airflow, etc.)
└──────┬──────┘
       │ metrics
       ▼
┌─────────────┐     ┌──────────────┐
│ Prometheus  │────▶│ Alertmanager │
└──────┬──────┘     └──────┬───────┘
       │                   │
       │ queries           │ alerts
       ▼                   ▼
┌─────────────┐     ┌──────────────┐
│   Grafana   │     │ Email/Slack  │
└─────────────┘     │  /PagerDuty  │
                    └──────────────┘
```

## Components

### Prometheus

**Purpose**: Scrapes and stores metrics from all services

**Configuration**: `config/prometheus.yml`

**Key Features**:
- 30-second scrape interval
- Automatic service discovery
- Alert rule evaluation
- Long-term metric storage

**Access**: http://localhost:9090

### Alertmanager

**Purpose**: Routes and manages alerts from Prometheus

**Configuration**: `config/alertmanager.yml`

**Key Features**:
- Alert grouping and deduplication
- Multiple notification channels
- Alert inhibition rules
- Flexible routing

**Access**: http://localhost:9093

### Grafana

**Purpose**: Visualizes metrics and manages dashboards

**Configuration**: `dashboards/grafana/`

**Key Features**:
- Pre-built dashboards
- Alert visualization
- Custom queries
- Role-based access

**Access**: http://localhost:3000

**Default Credentials**: admin/admin

## Configuration

### 1. Prometheus Setup

The Prometheus configuration defines which services to monitor:

```yaml
# config/prometheus.yml
scrape_configs:
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']

  - job_name: 'airflow'
    static_configs:
      - targets: ['airflow:8125']
```

**Customization**:
- Adjust `scrape_interval` for more/less frequent checks
- Add custom endpoints in `scrape_configs`
- Modify `retention` for metric storage duration

### 2. Alert Rules Configuration

Alert rules are defined in `config/alert_rules.yml`:

```yaml
groups:
  - name: threat_intelligence_platform
    rules:
      - alert: ElasticsearchDown
        expr: up{job="elasticsearch"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Elasticsearch is down"
```

**Rule Components**:
- `expr`: PromQL query that triggers the alert
- `for`: Duration before firing (prevents flapping)
- `labels`: Metadata for routing
- `annotations`: Human-readable descriptions

### 3. Alertmanager Configuration

Configure notification channels in `config/alertmanager.yml`:

```yaml
receivers:
  - name: 'team-email'
    email_configs:
      - to: 'tip-team@example.com'
        headers:
          Subject: '[TIP] {{ .GroupLabels.alertname }}'
```

## Alert Rules

### Service Health Alerts

| Alert Name | Severity | Trigger Condition | Duration |
|------------|----------|-------------------|----------|
| ServiceDown | Critical | Service unreachable | 2 minutes |
| ElasticsearchDown | Critical | ES unreachable | 1 minute |
| AirflowDown | High | Airflow unreachable | 5 minutes |

### Resource Alerts

| Alert Name | Severity | Trigger Condition | Duration |
|------------|----------|-------------------|----------|
| HighCPUUsage | Warning | CPU > 80% | 10 minutes |
| HighMemoryUsage | Warning | Memory > 85% | 5 minutes |
| DiskSpaceLow | High | Disk < 10% free | 5 minutes |
| ElasticsearchLowDiskSpace | High | ES disk < 10% | 10 minutes |

### Data Quality Alerts

| Alert Name | Severity | Trigger Condition | Duration |
|------------|----------|-------------------|----------|
| NoRecentIOCs | Warning | No IOCs in 6 hours | 6 hours |
| HighIndexingLatency | Warning | Indexing > 1s/doc | 10 minutes |
| AirflowDAGFailed | High | DAG run failed | 5 minutes |

### Security Alerts

| Alert Name | Severity | Trigger Condition | Duration |
|------------|----------|-------------------|----------|
| UnauthorizedAccessAttempt | High | >10 401s per minute | 2 minutes |
| SuspiciousActivityDetected | Warning | >5 403s per minute | 5 minutes |

## Setting Up Notifications

### Email Notifications

1. **Configure SMTP** in `config/alertmanager.yml`:

```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'tip-alerts@example.com'
  smtp_auth_username: 'tip-alerts@example.com'
  smtp_auth_password: 'your-app-password'
  smtp_require_tls: true
```

2. **Add email receiver**:

```yaml
receivers:
  - name: 'team-email'
    email_configs:
      - to: 'team@example.com'
        send_resolved: true
```

### Slack Notifications

1. **Create Slack Webhook**:
   - Go to https://api.slack.com/apps
   - Create new app → Incoming Webhooks
   - Copy webhook URL

2. **Configure in Alertmanager**:

```yaml
receivers:
  - name: 'slack-critical'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#tip-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

### PagerDuty Integration

1. **Get Integration Key**:
   - PagerDuty → Services → Add Integration
   - Select "Prometheus" integration
   - Copy integration key

2. **Configure in Alertmanager**:

```yaml
receivers:
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'your-integration-key'
        description: '{{ .Annotations.summary }}'
```

### Webhook Notifications

For custom integrations:

```yaml
receivers:
  - name: 'webhook-custom'
    webhook_configs:
      - url: 'http://your-service/alerts'
        send_resolved: true
        http_config:
          basic_auth:
            username: 'alertmanager'
            password: 'secure-password'
```

## Custom Metrics

### Adding Custom Application Metrics

1. **Expose metrics endpoint** in your application:

```python
from prometheus_client import Counter, Histogram, generate_latest

# Define metrics
ioc_processed = Counter('tip_iocs_processed_total', 'Total IOCs processed')
processing_time = Histogram('tip_processing_seconds', 'IOC processing time')

# Instrument your code
@processing_time.time()
def process_ioc(ioc):
    # Process IOC
    ioc_processed.inc()
```

2. **Add to Prometheus config**:

```yaml
scrape_configs:
  - job_name: 'tip-custom'
    static_configs:
      - targets: ['tip-api:8000']
    metrics_path: '/metrics'
```

### Metric Types

- **Counter**: Monotonically increasing value (e.g., total requests)
- **Gauge**: Value that can go up or down (e.g., queue size)
- **Histogram**: Observations in buckets (e.g., response times)
- **Summary**: Similar to histogram with quantiles

## Dashboard Access

### Pre-built Dashboards

The platform includes several pre-configured Grafana dashboards:

1. **TIP Overview**
   - Service health status
   - IOC collection metrics
   - System resource usage
   - Recent alerts

2. **Threat Intelligence Dashboard**
   - IOC trends over time
   - Severity distribution
   - Source breakdown
   - Top threat actors

3. **System Performance**
   - CPU, Memory, Disk usage
   - Network I/O
   - Container metrics
   - Elasticsearch performance

4. **Airflow Monitoring**
   - DAG run status
   - Task success/failure rates
   - Execution times
   - Queue sizes

### Creating Custom Dashboards

1. **Access Grafana**: http://localhost:3000
2. **Click "+"** → "Create Dashboard"
3. **Add Panel** → Select data source
4. **Write query**:
   - For Prometheus: Use PromQL
   - For Elasticsearch: Use Lucene query
5. **Configure visualization**
6. **Save dashboard**

## Troubleshooting

### Prometheus Not Scraping Metrics

**Symptoms**: No data in Grafana, targets down in Prometheus

**Solutions**:
1. Check target status: http://localhost:9090/targets
2. Verify service is exposing metrics:
   ```bash
   curl http://localhost:9200/_prometheus/metrics
   ```
3. Check network connectivity:
   ```bash
   docker exec tip-prometheus wget -O- elasticsearch:9200
   ```

### Alerts Not Firing

**Symptoms**: Conditions met but no alerts sent

**Solutions**:
1. Check alert status in Prometheus: http://localhost:9090/alerts
2. Verify alert rules are loaded:
   ```bash
   docker logs tip-prometheus | grep "Loading configuration"
   ```
3. Check Alertmanager logs:
   ```bash
   docker logs tip-alertmanager
   ```

### Email Notifications Not Working

**Symptoms**: Alerts fire but emails not received

**Solutions**:
1. Verify SMTP configuration in Alertmanager
2. Check Alertmanager logs for SMTP errors:
   ```bash
   docker logs tip-alertmanager | grep -i smtp
   ```
3. Test SMTP connectivity:
   ```bash
   docker exec tip-alertmanager telnet smtp.example.com 587
   ```
4. Check spam folder
5. Verify firewall rules allow outbound SMTP

### High Memory Usage

**Symptoms**: Prometheus consuming excessive memory

**Solutions**:
1. Reduce retention period:
   ```yaml
   # config/prometheus.yml
   global:
     retention: 15d  # Reduce from 30d
   ```
2. Adjust scrape intervals
3. Use recording rules for frequently-used queries
4. Increase container memory limit

### Grafana Dashboard Not Loading Data

**Symptoms**: Empty panels or "No data" errors

**Solutions**:
1. Verify data source connection in Grafana
2. Test query in Prometheus directly
3. Check time range selection
4. Verify index exists in Elasticsearch:
   ```bash
   curl http://localhost:9200/_cat/indices?v
   ```

## Best Practices

### Alert Tuning

1. **Start Conservative**: Begin with higher thresholds and longer durations
2. **Monitor Alert Fatigue**: Track alert frequency and adjust
3. **Use Inhibition Rules**: Prevent cascading alerts
4. **Regular Review**: Audit alerts monthly for relevance

### Metric Collection

1. **Label Cardinality**: Avoid high-cardinality labels (IDs, timestamps)
2. **Metric Naming**: Use consistent naming conventions
3. **Documentation**: Comment complex queries
4. **Performance**: Balance scrape frequency with load

### Dashboard Design

1. **User-Focused**: Design for your audience (ops, security, management)
2. **Clear Labels**: Use descriptive titles and units
3. **Consistent Colors**: Standardize severity colors
4. **Threshold Lines**: Add visual indicators for limits

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Alertmanager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)
- [Grafana Alerts](https://grafana.com/docs/grafana/latest/alerting/)
- [PromQL Basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)

## Support

For monitoring issues:

1. Check logs: `make logs`
2. Run health checks: `make health`
3. Consult troubleshooting guide
4. Contact platform team

---

**Next Steps**:
- Configure notification channels
- Customize alert thresholds
- Create custom dashboards
- Set up on-call rotations
