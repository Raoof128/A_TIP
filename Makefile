# Threat Intelligence Platform - Makefile
# Easy commands for managing the TIP

.PHONY: help install start stop restart logs clean test lint format

# Default target
help:
	@echo "Threat Intelligence Platform - Available Commands"
	@echo "=================================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make install          Install Python dependencies"
	@echo "  make setup            Initial setup (copy config, install deps)"
	@echo ""
	@echo "Docker Commands:"
	@echo "  make start            Start all services"
	@echo "  make stop             Stop all services"
	@echo "  make restart          Restart all services"
	@echo "  make logs             View logs from all services"
	@echo "  make logs-airflow     View Airflow logs"
	@echo "  make logs-es          View Elasticsearch logs"
	@echo ""
	@echo "Development Commands:"
	@echo "  make test             Run unit tests"
	@echo "  make test-coverage    Run tests with coverage report"
	@echo "  make lint             Run code quality checks"
	@echo "  make format           Format code with black"
	@echo ""
	@echo "Data Commands:"
	@echo "  make collect          Run manual collection"
	@echo "  make clean-data       Clean Elasticsearch data"
	@echo "  make backup           Backup Elasticsearch data"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean            Clean temporary files"
	@echo "  make status           Check service status"
	@echo "  make shell-airflow    Open Airflow container shell"

# Setup and Installation
install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt

setup:
	@echo "Setting up Threat Intelligence Platform..."
	@if [ ! -f config/api_keys.env ]; then \
		cp config/api_keys.env.example config/api_keys.env; \
		echo "Created config/api_keys.env - please edit with your API keys"; \
	fi
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "Setup complete! Edit config/api_keys.env with your API keys"

# Docker Management
start:
	@echo "Starting Threat Intelligence Platform..."
	cd docker && docker-compose up -d
	@echo ""
	@echo "Services started!"
	@echo "  - Airflow:        http://localhost:8081 (admin/admin)"
	@echo "  - Grafana:        http://localhost:3000 (admin/admin)"
	@echo "  - Elasticsearch:  http://localhost:9200"
	@echo "  - MISP:           https://localhost:8443 (admin@tip.local/admin123)"

stop:
	@echo "Stopping Threat Intelligence Platform..."
	cd docker && docker-compose down

restart:
	@echo "Restarting Threat Intelligence Platform..."
	cd docker && docker-compose restart

logs:
	@echo "Showing logs from all services..."
	cd docker && docker-compose logs -f

logs-airflow:
	@echo "Showing Airflow logs..."
	cd docker && docker-compose logs -f airflow

logs-es:
	@echo "Showing Elasticsearch logs..."
	cd docker && docker-compose logs -f elasticsearch

status:
	@echo "Service Status:"
	@echo "==============="
	cd docker && docker-compose ps

# Development
test:
	@echo "Running unit tests..."
	pytest tests/ -v

test-coverage:
	@echo "Running tests with coverage..."
	pytest tests/ -v --cov=collectors --cov=enrichment --cov=correlation --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

lint:
	@echo "Running code quality checks..."
	flake8 collectors/ enrichment/ correlation/ --max-line-length=120
	pylint collectors/ enrichment/ correlation/ --max-line-length=120 || true

format:
	@echo "Formatting code with black..."
	black collectors/ enrichment/ correlation/ tests/ --line-length=120

# Data Operations
collect:
	@echo "Running manual collection..."
	@if [ -z "$(OTX_API_KEY)" ]; then \
		echo "Error: OTX_API_KEY not set. Set it or source config/api_keys.env"; \
		exit 1; \
	fi
	python collectors/alienvault_otx.py

collect-urlhaus:
	@echo "Collecting from URLhaus..."
	python collectors/urlhaus_collector.py

clean-data:
	@echo "WARNING: This will delete all IOC data from Elasticsearch!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		curl -X DELETE "http://localhost:9200/threat-intel-iocs"; \
		echo "Data deleted"; \
	fi

backup:
	@echo "Backing up Elasticsearch data..."
	@mkdir -p backups
	@curl -X POST "http://localhost:9200/_snapshot/backup_repo/snapshot_$(shell date +%Y%m%d_%H%M%S)?wait_for_completion=true"
	@echo "Backup complete"

# Utility Commands
clean:
	@echo "Cleaning temporary files..."
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} + || true
	find . -type f -name '.coverage' -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	@echo "Clean complete"

shell-airflow:
	@echo "Opening Airflow container shell..."
	docker exec -it tip-airflow /bin/bash

shell-es:
	@echo "Opening Elasticsearch container shell..."
	docker exec -it tip-elasticsearch /bin/bash

# Quick start for development
dev: setup start
	@echo ""
	@echo "Development environment ready!"
	@echo "Next steps:"
	@echo "  1. Edit config/api_keys.env with your API keys"
	@echo "  2. Run 'make collect' to test collection"
	@echo "  3. Access Airflow at http://localhost:8081"

# Production deployment
prod:
	@echo "Starting production deployment..."
	@echo "WARNING: Ensure all API keys are configured in config/api_keys.env"
	cd docker && docker-compose up -d
	@echo "Production services started"

# Check Elasticsearch health
check-es:
	@echo "Checking Elasticsearch health..."
	@curl -s http://localhost:9200/_cluster/health?pretty

# View IOC count
count-iocs:
	@echo "Counting IOCs in Elasticsearch..."
	@curl -s "http://localhost:9200/threat-intel-iocs/_count" | python -m json.tool

# View recent IOCs
view-recent:
	@echo "Viewing recent IOCs..."
	@curl -s "http://localhost:9200/threat-intel-iocs/_search?size=10&sort=first_seen:desc" | python -m json.tool
