# Threat Intelligence Platform - Setup Guide

This guide will walk you through setting up the Threat Intelligence Platform from scratch.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Getting API Keys](#getting-api-keys)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Starting the Platform](#starting-the-platform)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- **OS**: Linux, macOS, or Windows (with WSL2)
- **RAM**: 16GB minimum (8GB may work but not recommended)
- **Disk**: 20GB free space
- **CPU**: 4 cores recommended

### Software Requirements
- **Docker**: Version 20.10 or later
- **Docker Compose**: Version 2.0 or later
- **Python**: Version 3.11 or later (for development)
- **Git**: Latest version

### Installing Docker

#### Ubuntu/Debian
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

#### macOS
Download and install [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop)

#### Windows
Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)

## Getting API Keys

### 1. AlienVault OTX (Required)
1. Go to https://otx.alienvault.com/
2. Create a free account
3. Navigate to Settings → API Integration
4. Copy your API key

### 2. AbuseIPDB (Recommended)
1. Go to https://www.abuseipdb.com/
2. Create a free account
3. Navigate to Account → API
4. Generate API key (Free tier: 1,000 requests/day)

### 3. VirusTotal (Optional)
1. Go to https://www.virustotal.com/
2. Create account
3. Navigate to Profile → API Key
4. Copy your API key (Free tier: 500 requests/day)

### 4. URLhaus (No API Key Required)
URLhaus is completely free and doesn't require an API key!

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/Raoof128/A_TIP.git
cd A_TIP
```

### Step 2: Create Configuration File
```bash
cp config/api_keys.env.example config/api_keys.env
```

### Step 3: Edit API Keys
Open `config/api_keys.env` in your favorite editor:
```bash
nano config/api_keys.env
# OR
vim config/api_keys.env
```

Add your API keys:
```bash
OTX_API_KEY=your_actual_otx_api_key_here
ABUSEIPDB_API_KEY=your_actual_abuseipdb_key_here
VT_API_KEY=your_actual_virustotal_key_here  # Optional
```

### Step 4: Install Python Dependencies (Optional for Development)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

### Customize Settings (Optional)

Edit `config/config.yaml` to customize:

```yaml
collectors:
  alienvault_otx:
    collection_limit: 500  # Adjust based on your needs

  abuseipdb:
    confidence_threshold: 80  # Minimum confidence score
```

## Starting the Platform

### Option 1: Using Make (Recommended)
```bash
make start
```

### Option 2: Using Docker Compose Directly
```bash
cd docker
docker-compose up -d
```

### Option 3: First-Time Setup
```bash
make dev
```

This will:
1. Copy configuration files
2. Install dependencies
3. Start all services
4. Display access URLs

## Verification

### Step 1: Check Service Status
```bash
make status
# OR
cd docker && docker-compose ps
```

All services should show "Up" status:
```
NAME                COMMAND             STATUS
tip-airflow         ...                 Up
tip-elasticsearch   ...                 Up
tip-grafana         ...                 Up
tip-misp            ...                 Up
tip-misp-db         ...                 Up
tip-postgres        ...                 Up
```

### Step 2: Access Web Interfaces

#### Airflow (Workflow Automation)
1. Open: http://localhost:8081
2. Login: `admin` / `admin`
3. You should see the `threat_intel_collection` DAG

#### Grafana (Dashboards)
1. Open: http://localhost:3000
2. Login: `admin` / `admin`
3. Navigate to Dashboards

#### Elasticsearch (Storage)
1. Open: http://localhost:9200
2. You should see JSON response with cluster info

### Step 3: Run Manual Collection Test

```bash
# Test AlienVault OTX collector
export OTX_API_KEY="your_key_here"
python collectors/alienvault_otx.py

# Test URLhaus collector (no API key needed)
python collectors/urlhaus_collector.py
```

### Step 4: Check Elasticsearch for IOCs

```bash
# Check IOC count
make count-iocs
# OR
curl "http://localhost:9200/threat-intel-iocs/_count"
```

### Step 5: Trigger Airflow DAG Manually

1. Go to http://localhost:8081
2. Find `threat_intel_collection` DAG
3. Toggle it "ON"
4. Click the "Play" button → "Trigger DAG"
5. Watch the tasks execute in the Graph view

## Troubleshooting

### Issue: Docker Compose Fails to Start

**Error**: "Cannot connect to Docker daemon"
```bash
# Solution: Start Docker service
sudo systemctl start docker

# Or on macOS/Windows: Start Docker Desktop
```

**Error**: "Port already in use"
```bash
# Solution: Check what's using the port
sudo lsof -i :9200  # For Elasticsearch
sudo lsof -i :8081  # For Airflow

# Kill the process or change ports in docker-compose.yml
```

### Issue: Elasticsearch Won't Start

**Error**: "max virtual memory areas vm.max_map_count [65530] is too low"
```bash
# Solution (Linux):
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Solution (macOS with Docker Desktop):
# In Docker Desktop settings, increase memory to at least 4GB
```

**Error**: "Elasticsearch died shortly after startup"
```bash
# Solution: Check memory allocation
# Reduce ES heap size in docker-compose.yml:
# ES_JAVA_OPTS=-Xms1g -Xmx1g  # Instead of 2g
```

### Issue: Airflow DAG Not Showing

1. Check Airflow logs:
```bash
make logs-airflow
```

2. Look for Python import errors
3. Ensure all dependencies are installed in Airflow container

4. Restart Airflow:
```bash
docker restart tip-airflow
```

### Issue: No IOCs Being Collected

1. **Check API keys** in `config/api_keys.env`
2. **View Airflow task logs**:
   - Go to http://localhost:8081
   - Click on the failed task
   - View logs

3. **Test collectors manually**:
```bash
export OTX_API_KEY="your_key"
python collectors/alienvault_otx.py
```

4. **Check API rate limits**:
   - Free tiers have limited requests
   - Wait and try again

### Issue: Grafana Dashboard Empty

1. **Add Elasticsearch datasource**:
   - Go to Configuration → Data Sources
   - Add Elasticsearch
   - URL: http://tip-elasticsearch:9200
   - Index: threat-intel-iocs

2. **Check if IOCs exist**:
```bash
curl "http://localhost:9200/threat-intel-iocs/_count"
```

## Next Steps

Once everything is running:

1. **Explore Airflow**: http://localhost:8081
   - View DAG execution history
   - Check task logs
   - Schedule custom runs

2. **View Dashboards**: http://localhost:3000
   - IOC collection trends
   - Severity distribution
   - Geographic analysis

3. **Query IOCs**:
```bash
# Recent critical IOCs
curl -X POST "http://localhost:9200/threat-intel-iocs/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"severity": "CRITICAL"}}, "size": 10}'
```

4. **Customize Collections**:
   - Edit `config/config.yaml`
   - Adjust collection limits
   - Enable/disable sources
   - Modify schedules

## Getting Help

- **Documentation**: See README.md
- **Issues**: https://github.com/Raoof128/A_TIP/issues
- **Logs**: `make logs` or `docker-compose logs`

## Quick Reference Commands

```bash
# Start platform
make start

# Stop platform
make stop

# View logs
make logs

# Run tests
make test

# Count IOCs
make count-iocs

# View recent IOCs
make view-recent

# Clean data
make clean-data

# Check status
make status
```

---

**Congratulations!** You now have a fully functional Threat Intelligence Platform running.

For advanced usage and development, see the main [README.md](README.md).
