# Threat Intelligence Platform - Troubleshooting Guide

This guide helps you diagnose and fix common issues with the TIP.

## Table of Contents
1. [Quick Diagnostics](#quick-diagnostics)
2. [Docker Issues](#docker-issues)
3. [Service-Specific Issues](#service-specific-issues)
4. [Collector Issues](#collector-issues)
5. [Data Issues](#data-issues)
6. [Performance Issues](#performance-issues)

---

## Quick Diagnostics

### Step 1: Run Health Check
```bash
make health
# OR
bash scripts/health_check.sh
```

### Step 2: Check Service Status
```bash
make status
# OR
cd docker && docker-compose ps
```

### Step 3: View Logs
```bash
# All services
make logs

# Specific service
make logs-airflow
make logs-es
docker logs tip-elasticsearch
```

---

## Docker Issues

### Issue: "Cannot connect to the Docker daemon"

**Symptoms:**
- `docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock`

**Solutions:**
1. Start Docker daemon:
   ```bash
   sudo systemctl start docker    # Linux
   # OR start Docker Desktop on macOS/Windows
   ```

2. Add user to docker group:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

### Issue: "Port already in use"

**Symptoms:**
- `Error starting userland proxy: listen tcp4 0.0.0.0:9200: bind: address already in use`

**Solutions:**
1. Find what's using the port:
   ```bash
   sudo lsof -i :9200
   # OR
   netstat -tuln | grep 9200
   ```

2. Stop the conflicting service or change port in `docker/docker-compose.yml`

### Issue: "No space left on device"

**Symptoms:**
- `docker: no space left on device`

**Solutions:**
1. Clean up Docker:
   ```bash
   docker system prune -a
   docker volume prune
   ```

2. Check disk space:
   ```bash
   df -h
   ```

---

## Service-Specific Issues

### Elasticsearch

#### Issue: "Elasticsearch won't start"

**Symptoms:**
- Container exits immediately
- `max virtual memory areas vm.max_map_count [65530] is too low`

**Solutions:**
1. Increase vm.max_map_count:
   ```bash
   # Linux
   sudo sysctl -w vm.max_map_count=262144
   echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

   # macOS/Windows with Docker Desktop
   # In Docker Desktop → Preferences → Resources → Advanced
   # Increase memory to at least 4GB
   ```

2. Reduce memory requirements:
   Edit `docker/docker-compose.yml`:
   ```yaml
   elasticsearch:
     environment:
       - "ES_JAVA_OPTS=-Xms1g -Xmx1g"  # Instead of 2g
   ```

#### Issue: "Elasticsearch is slow"

**Solutions:**
1. Check resource usage:
   ```bash
   curl "http://localhost:9200/_nodes/stats"
   ```

2. Increase heap size in `docker-compose.yml`

3. Add more nodes (advanced)

### Airflow

#### Issue: "Airflow web UI not loading"

**Symptoms:**
- `502 Bad Gateway`
- Container keeps restarting

**Solutions:**
1. Check Airflow logs:
   ```bash
   docker logs tip-airflow
   ```

2. Check if database is ready:
   ```bash
   docker logs tip-postgres
   ```

3. Restart Airflow:
   ```bash
   docker restart tip-airflow
   ```

4. Re-initialize database:
   ```bash
   docker exec -it tip-airflow airflow db reset
   docker exec -it tip-airflow airflow db init
   ```

#### Issue: "DAG not showing up"

**Symptoms:**
- DAG doesn't appear in Airflow UI

**Solutions:**
1. Check for Python errors:
   ```bash
   docker exec -it tip-airflow python /opt/airflow/dags/daily_collection_dag.py
   ```

2. Check DAG folder permissions:
   ```bash
   docker exec -it tip-airflow ls -la /opt/airflow/dags
   ```

3. Refresh DAGs:
   - In Airflow UI, click the refresh button
   - Wait 30 seconds for scheduler to pick up changes

### Grafana

#### Issue: "Cannot connect to Elasticsearch datasource"

**Symptoms:**
- "Bad Gateway" error in Grafana

**Solutions:**
1. Use container name instead of localhost:
   ```
   URL: http://tip-elasticsearch:9200
   ```

2. Check Elasticsearch is accessible:
   ```bash
   docker exec -it tip-grafana curl http://tip-elasticsearch:9200
   ```

3. Restart Grafana:
   ```bash
   docker restart tip-grafana
   ```

---

## Collector Issues

### Issue: "No IOCs being collected"

**Symptoms:**
- Airflow DAG runs but collects 0 IOCs
- Manual collection fails

**Solutions:**
1. Check API keys:
   ```bash
   cat config/api_keys.env | grep -v "^#"
   ```

2. Test collectors standalone:
   ```bash
   make test-collectors
   # OR
   python3 scripts/test_collectors.py --urlhaus
   python3 scripts/test_collectors.py --otx --otx-key YOUR_KEY
   ```

3. Check for rate limiting:
   ```bash
   docker logs tip-airflow | grep "rate limit"
   ```

4. Verify internet connectivity:
   ```bash
   docker exec -it tip-airflow curl https://otx.alienvault.com
   ```

### Issue: "API key invalid"

**Symptoms:**
- `403 Forbidden`
- `401 Unauthorized`

**Solutions:**
1. Verify API key is correct:
   - Check for extra spaces
   - Ensure no quotes around the key
   - Regenerate key from provider

2. Test API key manually:
   ```bash
   # AlienVault OTX
   curl -H "X-OTX-API-KEY: YOUR_KEY" https://otx.alienvault.com/api/v1/pulses/subscribed

   # AbuseIPDB
   curl -H "Key: YOUR_KEY" https://api.abuseipdb.com/api/v2/blacklist
   ```

### Issue: "Collector timeout"

**Symptoms:**
- `Request timeout`
- Collector hangs

**Solutions:**
1. Increase timeout in `config/config.yaml`:
   ```yaml
   collectors:
     timeout: 60  # Increase from 30
   ```

2. Check network:
   ```bash
   docker exec -it tip-airflow ping 8.8.8.8
   ```

---

## Data Issues

### Issue: "IOC index not created"

**Symptoms:**
- `index_not_found_exception`

**Solutions:**
1. Create index manually:
   ```bash
   curl -X PUT "http://localhost:9200/threat-intel-iocs"
   ```

2. Run DAG once to create index automatically

3. Check Elasticsearch logs:
   ```bash
   docker logs tip-elasticsearch
   ```

### Issue: "Duplicate IOCs"

**Symptoms:**
- Same IOC appearing multiple times

**Solutions:**
1. Check deduplication logic is running:
   ```bash
   docker logs tip-airflow | grep "Deduplication"
   ```

2. Verify IOC ID generation:
   ```python
   python3 -c "from collectors.base_collector import IOC; \
   ioc = IOC('ip', '1.2.3.4', 'Test'); print(ioc.ioc_id)"
   ```

### Issue: "Old IOCs not being removed"

**Solutions:**
1. Check retention policy in `config/config.yaml`:
   ```yaml
   elasticsearch:
     retention_days: 90
   ```

2. Manually delete old IOCs:
   ```bash
   curl -X POST "http://localhost:9200/threat-intel-iocs/_delete_by_query" \
     -H 'Content-Type: application/json' \
     -d '{"query": {"range": {"first_seen": {"lt": "now-90d"}}}}'
   ```

---

## Performance Issues

### Issue: "Platform is slow"

**Symptoms:**
- High CPU/memory usage
- Services responding slowly

**Solutions:**
1. Check resource usage:
   ```bash
   docker stats
   ```

2. Reduce collection limits in `config/config.yaml`:
   ```yaml
   collectors:
     alienvault_otx:
       collection_limit: 100  # Reduce from 500
   ```

3. Increase Docker resources:
   - Docker Desktop → Preferences → Resources
   - Allocate more CPU and RAM

4. Scale down services:
   ```bash
   # Temporarily stop MISP if not needed
   docker stop tip-misp tip-misp-db
   ```

### Issue: "Airflow scheduler using too much CPU"

**Solutions:**
1. Increase scheduler interval:
   ```yaml
   airflow:
     environment:
       - AIRFLOW__SCHEDULER__SCHEDULER_HEARTBEAT_SEC=10
   ```

2. Reduce DAG parsing frequency:
   ```yaml
   - AIRFLOW__SCHEDULER__MIN_FILE_PROCESS_INTERVAL=120
   ```

---

## Common Error Messages

### "Connection refused"
- **Cause**: Service not started or not ready
- **Fix**: Wait for service to start, check with `make health`

### "Permission denied"
- **Cause**: File ownership or Docker permissions
- **Fix**: Check file permissions, add user to docker group

### "Out of memory"
- **Cause**: Insufficient RAM allocated to Docker
- **Fix**: Increase Docker memory allocation

### "Network timeout"
- **Cause**: Firewall, no internet, or slow connection
- **Fix**: Check firewall, test connectivity

---

## Getting Additional Help

### Debug Mode

Enable debug logging:
```bash
# In docker-compose.override.yml
services:
  airflow:
    environment:
      - AIRFLOW__LOGGING__LOGGING_LEVEL=DEBUG
```

### Collect Diagnostic Information

```bash
# System info
uname -a
docker --version
docker-compose --version

# Service status
docker-compose ps

# Resource usage
docker stats --no-stream

# Recent logs
docker logs --tail 100 tip-airflow > airflow.log
docker logs --tail 100 tip-elasticsearch > elasticsearch.log
```

### Report an Issue

If you can't resolve the issue:

1. Run diagnostic commands above
2. Collect relevant logs
3. Open an issue at: https://github.com/Raoof128/A_TIP/issues
4. Include:
   - OS and Docker version
   - Error messages
   - Steps to reproduce
   - Relevant logs

---

## Prevention Tips

### Regular Maintenance

1. **Monitor disk space**:
   ```bash
   df -h
   docker system df
   ```

2. **Clean up periodically**:
   ```bash
   # Every week
   docker system prune

   # Every month
   docker volume prune
   ```

3. **Update images**:
   ```bash
   cd docker
   docker-compose pull
   docker-compose up -d
   ```

### Best Practices

1. **Start with small collection limits**
2. **Monitor resource usage regularly**
3. **Keep API keys secure and backed up**
4. **Test changes in development first**
5. **Back up Elasticsearch data regularly**

---

## Quick Reference Commands

```bash
# Initialization
make init                    # Run initialization checks
make validate                # Validate configuration

# Service Management
make start                   # Start all services
make stop                    # Stop all services
make restart                 # Restart all services
make health                  # Health check

# Debugging
make logs                    # View all logs
make logs-airflow            # View Airflow logs
make logs-es                 # View Elasticsearch logs
make status                  # Service status

# Testing
make test                    # Run unit tests
make test-collectors         # Test collectors

# Data Management
make count-iocs              # Count IOCs
make view-recent             # View recent IOCs
make clean-data              # Clean all data

# Maintenance
make clean                   # Clean temporary files
docker system prune          # Clean Docker
```

---

**Still having issues?**

1. Check the [SETUP_GUIDE.md](SETUP_GUIDE.md) for detailed setup instructions
2. Review the [README.md](README.md) for architecture and features
3. Open an issue on GitHub with diagnostic information

Happy Threat Hunting! 🛡️
