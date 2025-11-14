#!/bin/bash
# Threat Intelligence Platform - One-Command Quickstart
# Gets the platform running with minimal setup

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      ████████╗██╗██████╗     ██████╗ ██╗   ██╗██╗ ██████╗██╗  ██╗ ║
║      ╚══██╔══╝██║██╔══██╗   ██╔═══██╗██║   ██║██║██╔════╝██║ ██╔╝ ║
║         ██║   ██║██████╔╝   ██║   ██║██║   ██║██║██║     █████╔╝  ║
║         ██║   ██║██╔═══╝    ██║▄▄ ██║██║   ██║██║██║     ██╔═██╗  ║
║         ██║   ██║██║        ╚██████╔╝╚██████╔╝██║╚██████╗██║  ██╗ ║
║         ╚═╝   ╚═╝╚═╝         ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝╚═╝  ╚═╝ ║
║                                                                  ║
║           Threat Intelligence Platform - Quickstart             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}Welcome to the TIP Quickstart!${NC}"
echo -e "This script will get your Threat Intelligence Platform running in minutes."
echo ""

# Check if running from project root
if [ ! -f "README.md" ]; then
    echo -e "${RED}Error: Please run this script from the project root directory${NC}"
    exit 1
fi

# Step 1: Check prerequisites
echo -e "${BLUE}[1/8]${NC} Checking prerequisites..."
sleep 1

if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found${NC}"
    echo "  Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker installed"

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose not found${NC}"
    echo "  Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker Compose installed"

if ! docker info &> /dev/null; then
    echo -e "${RED}✗ Docker daemon not running${NC}"
    echo "  Please start Docker and try again"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker daemon running"

# Step 2: Setup directories
echo -e "${BLUE}[2/8]${NC} Creating directories..."
mkdir -p logs backups data scripts
echo -e "${GREEN}✓${NC} Directories created"

# Step 3: Configure API keys
echo -e "${BLUE}[3/8]${NC} Configuring API keys..."

if [ ! -f "config/api_keys.env" ]; then
    cp config/api_keys.env.example config/api_keys.env
    echo -e "${GREEN}✓${NC} Created config/api_keys.env"

    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  API KEYS REQUIRED${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "To collect threat intelligence, you'll need FREE API keys from:"
    echo ""
    echo -e "  ${CYAN}1. AlienVault OTX${NC} (Recommended)"
    echo "     → https://otx.alienvault.com/api"
    echo "     → Sign up and get your key from Settings → API Integration"
    echo ""
    echo -e "  ${CYAN}2. AbuseIPDB${NC} (Optional)"
    echo "     → https://www.abuseipdb.com/api"
    echo "     → Free tier: 1,000 requests/day"
    echo ""
    echo -e "  ${CYAN}3. VirusTotal${NC} (Optional)"
    echo "     → https://www.virustotal.com/gui/my-apikey"
    echo "     → Free tier: 500 requests/day"
    echo ""
    echo -e "${YELLOW}NOTE: URLhaus requires NO API key and will work immediately!${NC}"
    echo ""

    read -p "Do you want to configure API keys now? [y/N] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Please enter your API keys (press Enter to skip):"
        echo ""

        read -p "AlienVault OTX API Key: " OTX_KEY
        if [ ! -z "$OTX_KEY" ]; then
            sed -i "s/OTX_API_KEY=.*/OTX_API_KEY=$OTX_KEY/" config/api_keys.env
            echo -e "${GREEN}✓${NC} AlienVault OTX key saved"
        fi

        read -p "AbuseIPDB API Key (optional): " ABUSE_KEY
        if [ ! -z "$ABUSE_KEY" ]; then
            sed -i "s/ABUSEIPDB_API_KEY=.*/ABUSEIPDB_API_KEY=$ABUSE_KEY/" config/api_keys.env
            echo -e "${GREEN}✓${NC} AbuseIPDB key saved"
        fi

        read -p "VirusTotal API Key (optional): " VT_KEY
        if [ ! -z "$VT_KEY" ]; then
            sed -i "s/VT_API_KEY=.*/VT_API_KEY=$VT_KEY/" config/api_keys.env
            echo -e "${GREEN}✓${NC} VirusTotal key saved"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  You can add API keys later by editing: ${CYAN}config/api_keys.env${NC}"
    fi
else
    echo -e "${GREEN}✓${NC} API keys file already exists"
fi

# Step 4: Check system resources
echo -e "${BLUE}[4/8]${NC} Checking system resources..."

TOTAL_MEM=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}' || echo "unknown")
if [ "$TOTAL_MEM" != "unknown" ] && [ "$TOTAL_MEM" -lt 8 ]; then
    echo -e "${YELLOW}⚠${NC}  System has less than 8GB RAM (${TOTAL_MEM}GB available)"
    echo "  Platform will work but may be slower"
else
    echo -e "${GREEN}✓${NC} Sufficient memory available"
fi

AVAIL_DISK=$(df -h . | awk 'NR==2 {print $4}')
echo -e "${GREEN}✓${NC} Available disk space: $AVAIL_DISK"

# Step 5: Pull Docker images
echo -e "${BLUE}[5/8]${NC} Pulling Docker images (this may take a few minutes)..."
cd docker
docker-compose pull --quiet
echo -e "${GREEN}✓${NC} Docker images pulled"

# Step 6: Start services
echo -e "${BLUE}[6/8]${NC} Starting services..."
echo "  This will take 2-3 minutes for all services to become healthy..."
docker-compose up -d

# Wait for services to be healthy
echo -e "${CYAN}Waiting for services to start...${NC}"
sleep 10

# Check Elasticsearch
echo -n "  Waiting for Elasticsearch... "
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Check Airflow
echo -n "  Waiting for Airflow... "
for i in {1..30}; do
    if curl -s http://localhost:8081/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

cd ..

# Step 7: Initialize Elasticsearch index
echo -e "${BLUE}[7/8]${NC} Initializing Elasticsearch..."
curl -X PUT "http://localhost:9200/threat-intel-iocs" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "ioc_id": {"type": "keyword"},
      "type": {"type": "keyword"},
      "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
      "source": {"type": "keyword"},
      "confidence": {"type": "integer"},
      "threat_score": {"type": "integer"},
      "severity": {"type": "keyword"},
      "tags": {"type": "keyword"},
      "first_seen": {"type": "date"},
      "last_seen": {"type": "date"}
    }
  }
}' >/dev/null 2>&1 || echo -e "${YELLOW}⚠${NC}  Index may already exist"

echo -e "${GREEN}✓${NC} Elasticsearch initialized"

# Step 8: Run health check
echo -e "${BLUE}[8/8]${NC} Running health check..."
sleep 2

# Simple health check
SERVICES_UP=0
SERVICES_TOTAL=6

docker ps --format '{{.Names}}' | grep -q "tip-elasticsearch" && SERVICES_UP=$((SERVICES_UP + 1))
docker ps --format '{{.Names}}' | grep -q "tip-airflow" && SERVICES_UP=$((SERVICES_UP + 1))
docker ps --format '{{.Names}}' | grep -q "tip-postgres" && SERVICES_UP=$((SERVICES_UP + 1))
docker ps --format '{{.Names}}' | grep -q "tip-grafana" && SERVICES_UP=$((SERVICES_UP + 1))
docker ps --format '{{.Names}}' | grep -q "tip-misp" && SERVICES_UP=$((SERVICES_UP + 1))
docker ps --format '{{.Names}}' | grep -q "tip-misp-db" && SERVICES_UP=$((SERVICES_UP + 1))

if [ $SERVICES_UP -eq $SERVICES_TOTAL ]; then
    echo -e "${GREEN}✓${NC} All services are running ($SERVICES_UP/$SERVICES_TOTAL)"
else
    echo -e "${YELLOW}⚠${NC}  Some services may still be starting ($SERVICES_UP/$SERVICES_TOTAL)"
    echo "  Run '${CYAN}make health${NC}' in a few minutes to verify"
fi

# Success!
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ✓ SETUP COMPLETE!                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Your Threat Intelligence Platform is now running!${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  ACCESS YOUR SERVICES${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}Apache Airflow${NC} (Workflow Management)"
echo -e "  → ${GREEN}http://localhost:8081${NC}"
echo -e "  → Username: ${YELLOW}admin${NC}"
echo -e "  → Password: ${YELLOW}admin${NC}"
echo ""
echo -e "  ${CYAN}Grafana${NC} (Dashboards & Visualization)"
echo -e "  → ${GREEN}http://localhost:3000${NC}"
echo -e "  → Username: ${YELLOW}admin${NC}"
echo -e "  → Password: ${YELLOW}admin${NC}"
echo ""
echo -e "  ${CYAN}Elasticsearch${NC} (Data Storage)"
echo -e "  → ${GREEN}http://localhost:9200${NC}"
echo ""
echo -e "  ${CYAN}MISP${NC} (Threat Sharing)"
echo -e "  → ${GREEN}https://localhost:8443${NC}"
echo -e "  → Username: ${YELLOW}admin@tip.local${NC}"
echo -e "  → Password: ${YELLOW}admin123${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  NEXT STEPS${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  1. Go to Airflow and enable the 'threat_intel_collection' DAG"
echo "     ${CYAN}http://localhost:8081${NC}"
echo ""
echo "  2. Trigger a manual run to collect your first IOCs"
echo "     (Click the play button on the DAG)"
echo ""
echo "  3. View your IOCs in Elasticsearch:"
echo "     ${CYAN}curl http://localhost:9200/threat-intel-iocs/_count${NC}"
echo ""
echo "  4. Set up Grafana dashboards:"
echo "     ${CYAN}http://localhost:3000${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  USEFUL COMMANDS${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  ${CYAN}make health${NC}          Check service health"
echo "  ${CYAN}make logs${NC}            View all logs"
echo "  ${CYAN}make test-collectors${NC} Test threat feed collectors"
echo "  ${CYAN}make stop${NC}            Stop all services"
echo "  ${CYAN}make restart${NC}         Restart all services"
echo "  ${CYAN}make help${NC}            Show all commands"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}For detailed documentation, see:${NC}"
echo "  • README.md - Platform overview"
echo "  • SETUP_GUIDE.md - Detailed setup instructions"
echo "  • TROUBLESHOOTING.md - Common issues and solutions"
echo ""
echo -e "${GREEN}Happy Threat Hunting! 🛡️${NC}"
echo ""

exit 0
