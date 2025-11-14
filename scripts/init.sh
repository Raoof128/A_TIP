#!/bin/bash
# Threat Intelligence Platform - Initialization Script
# This script prepares the environment for first run

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Threat Intelligence Platform - Initialization Script   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running in project root
if [ ! -f "README.md" ] || [ ! -d "collectors" ]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

print_info "Starting initialization checks..."
echo ""

# 1. Check for Docker
print_info "Checking Docker installation..."
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    print_success "Docker found: $DOCKER_VERSION"
else
    print_error "Docker is not installed"
    echo "  Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# 2. Check for Docker Compose
print_info "Checking Docker Compose installation..."
if command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version)
    print_success "Docker Compose found: $COMPOSE_VERSION"
else
    print_error "Docker Compose is not installed"
    echo "  Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# 3. Check Python
print_info "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python found: $PYTHON_VERSION"
else
    print_warning "Python 3 is not installed (optional for local testing)"
fi

# 4. Check for API keys configuration
print_info "Checking API keys configuration..."
if [ ! -f "config/api_keys.env" ]; then
    print_warning "API keys file not found"
    print_info "Creating config/api_keys.env from template..."
    cp config/api_keys.env.example config/api_keys.env
    print_success "Created config/api_keys.env"
    echo ""
    print_warning "⚠️  IMPORTANT: Edit config/api_keys.env with your API keys before starting the platform"
    echo ""
    echo "  Get your free API keys from:"
    echo "    - AlienVault OTX: https://otx.alienvault.com/api"
    echo "    - AbuseIPDB:      https://www.abuseipdb.com/api"
    echo "    - VirusTotal:     https://www.virustotal.com/gui/my-apikey"
    echo ""
else
    print_success "API keys file exists"

    # Check if keys are filled in
    if grep -q "your_.*_api_key_here" config/api_keys.env; then
        print_warning "Some API keys appear to be placeholder values"
        print_info "Please edit config/api_keys.env with your actual API keys"
    else
        print_success "API keys appear to be configured"
    fi
fi

# 5. Create necessary directories
print_info "Creating necessary directories..."
mkdir -p logs backups data
print_success "Directories created"

# 6. Check system resources
print_info "Checking system resources..."

# Check available memory
if command -v free &> /dev/null; then
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 8 ]; then
        print_warning "System has less than 8GB RAM. Platform may run slowly."
        echo "  Consider increasing memory allocation if running in a VM"
    else
        print_success "Sufficient memory available (${TOTAL_MEM}GB)"
    fi
fi

# Check disk space
AVAIL_DISK=$(df -h . | awk 'NR==2 {print $4}')
print_success "Available disk space: $AVAIL_DISK"

# 7. Validate configuration
print_info "Validating configuration file..."
if command -v python3 &> /dev/null; then
    if python3 -c "import yaml" 2>/dev/null; then
        python3 -c "import yaml; yaml.safe_load(open('config/config.yaml'))"
        if [ $? -eq 0 ]; then
            print_success "Configuration file is valid YAML"
        else
            print_error "Configuration file has syntax errors"
            exit 1
        fi
    else
        print_warning "PyYAML not installed, skipping config validation"
        print_info "Install with: pip install pyyaml"
    fi
fi

# 8. Check for port conflicts
print_info "Checking for port conflicts..."
PORTS=(9200 8081 3000 5432 3306 8080 8443)
CONFLICTS=0

for PORT in "${PORTS[@]}"; do
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1 || netstat -tuln 2>/dev/null | grep -q ":$PORT "; then
        print_warning "Port $PORT is already in use"
        CONFLICTS=$((CONFLICTS + 1))
    fi
done

if [ $CONFLICTS -eq 0 ]; then
    print_success "All required ports are available"
else
    print_warning "$CONFLICTS port(s) are in use. You may need to stop conflicting services."
fi

# 9. Test Docker daemon
print_info "Testing Docker daemon..."
if docker info >/dev/null 2>&1; then
    print_success "Docker daemon is running"
else
    print_error "Docker daemon is not running"
    echo "  Please start Docker and try again"
    exit 1
fi

# 10. Check Docker Compose file
print_info "Validating Docker Compose configuration..."
cd docker
if docker-compose config >/dev/null 2>&1; then
    print_success "Docker Compose configuration is valid"
else
    print_error "Docker Compose configuration has errors"
    exit 1
fi
cd ..

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Initialization Complete!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "Next steps:"
echo ""
echo "  1. Edit API keys (if not done yet):"
echo "     ${BLUE}nano config/api_keys.env${NC}"
echo ""
echo "  2. Start the platform:"
echo "     ${BLUE}make start${NC}"
echo "     or"
echo "     ${BLUE}cd docker && docker-compose up -d${NC}"
echo ""
echo "  3. Access the services:"
echo "     - Airflow:        http://localhost:8081  (admin/admin)"
echo "     - Grafana:        http://localhost:3000  (admin/admin)"
echo "     - Elasticsearch:  http://localhost:9200"
echo ""
echo "For detailed setup instructions, see: SETUP_GUIDE.md"
echo ""

exit 0
