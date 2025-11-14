#!/bin/bash
# Threat Intelligence Platform - Health Check Script
# Checks the health status of all services

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║    Threat Intelligence Platform - Health Check          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Function to check service health
check_service() {
    local service_name=$1
    local url=$2
    local expected_code=${3:-200}

    echo -n "Checking $service_name... "

    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    if [ "$response" -eq "$expected_code" ] || [ "$response" -eq 200 ] || [ "$response" -eq 302 ]; then
        echo -e "${GREEN}✓ Healthy${NC} (HTTP $response)"
        return 0
    else
        echo -e "${RED}✗ Unhealthy${NC} (HTTP $response)"
        return 1
    fi
}

# Function to check Docker container
check_container() {
    local container_name=$1

    echo -n "Checking container $container_name... "

    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        status=$(docker inspect --format='{{.State.Status}}' "$container_name")
        health=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null)

        if [ "$status" == "running" ]; then
            if [ "$health" == "healthy" ] || [ "$health" == "" ]; then
                echo -e "${GREEN}✓ Running${NC}"
                return 0
            else
                echo -e "${YELLOW}⚠ Running but health check: $health${NC}"
                return 1
            fi
        else
            echo -e "${RED}✗ Status: $status${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Not running${NC}"
        return 1
    fi
}

# Track failures
FAILURES=0

# Check Docker containers
echo -e "${BLUE}Docker Containers:${NC}"
echo "─────────────────────────────────────────────────────────"
check_container "tip-elasticsearch" || FAILURES=$((FAILURES + 1))
check_container "tip-airflow" || FAILURES=$((FAILURES + 1))
check_container "tip-postgres" || FAILURES=$((FAILURES + 1))
check_container "tip-grafana" || FAILURES=$((FAILURES + 1))
check_container "tip-misp" || FAILURES=$((FAILURES + 1))
check_container "tip-misp-db" || FAILURES=$((FAILURES + 1))
echo ""

# Check HTTP endpoints
echo -e "${BLUE}Service Endpoints:${NC}"
echo "─────────────────────────────────────────────────────────"
check_service "Elasticsearch" "http://localhost:9200/_cluster/health" || FAILURES=$((FAILURES + 1))
check_service "Airflow Web" "http://localhost:8081/health" || FAILURES=$((FAILURES + 1))
check_service "Grafana" "http://localhost:3000/api/health" || FAILURES=$((FAILURES + 1))
check_service "MISP" "http://localhost:8080/users/login" 200 || FAILURES=$((FAILURES + 1))
echo ""

# Check Elasticsearch index
echo -e "${BLUE}Data Status:${NC}"
echo "─────────────────────────────────────────────────────────"
echo -n "Elasticsearch IOC index... "
if curl -s "http://localhost:9200/threat-intel-iocs" >/dev/null 2>&1; then
    count=$(curl -s "http://localhost:9200/threat-intel-iocs/_count" | grep -o '"count":[0-9]*' | cut -d: -f2)
    echo -e "${GREEN}✓ Exists${NC} ($count IOCs)"
else
    echo -e "${YELLOW}⚠ Not created yet${NC}"
fi
echo ""

# Check Airflow DAGs
echo -e "${BLUE}Airflow DAGs:${NC}"
echo "─────────────────────────────────────────────────────────"
echo -n "Checking DAG status... "
if command -v python3 >/dev/null 2>&1; then
    # Try to check via Airflow API
    dag_response=$(curl -s -u admin:admin "http://localhost:8081/api/v1/dags/threat_intel_collection" 2>/dev/null)
    if echo "$dag_response" | grep -q "is_active"; then
        echo -e "${GREEN}✓ DAG found${NC}"
    else
        echo -e "${YELLOW}⚠ DAG not loaded yet${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Python not available for API check${NC}"
fi
echo ""

# System resources
echo -e "${BLUE}System Resources:${NC}"
echo "─────────────────────────────────────────────────────────"

if command -v docker >/dev/null 2>&1; then
    echo "Docker resource usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -7
fi
echo ""

# Summary
echo "═══════════════════════════════════════════════════════════"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Platform is healthy and ready to use."
    exit 0
else
    echo -e "${YELLOW}⚠ $FAILURES check(s) failed${NC}"
    echo ""
    echo "Some services may still be starting up or have issues."
    echo "Wait a few minutes and run this check again."
    echo ""
    echo "For logs, run: make logs"
    exit 1
fi
