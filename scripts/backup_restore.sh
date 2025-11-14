#!/bin/bash
# Threat Intelligence Platform - Backup and Restore Utility
# Manages backups of Elasticsearch data

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BACKUP_DIR="./backups"
ES_URL="http://localhost:9200"
INDEX_NAME="threat-intel-iocs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Functions
print_usage() {
    echo "Usage: $0 {backup|restore|list|cleanup}"
    echo ""
    echo "Commands:"
    echo "  backup          Create a new backup"
    echo "  restore [file]  Restore from backup file"
    echo "  list            List all backups"
    echo "  cleanup [days]  Remove backups older than N days (default: 30)"
    echo ""
    echo "Examples:"
    echo "  $0 backup"
    echo "  $0 restore backups/threat_intel_20240101_120000.json"
    echo "  $0 list"
    echo "  $0 cleanup 7"
}

check_elasticsearch() {
    if ! curl -s "$ES_URL" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to Elasticsearch at $ES_URL${NC}"
        echo "Make sure the platform is running: make start"
        exit 1
    fi
}

backup_data() {
    echo -e "${BLUE}Creating backup of Elasticsearch data...${NC}"

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Get total document count
    TOTAL_DOCS=$(curl -s "$ES_URL/$INDEX_NAME/_count" | jq -r '.count')

    if [ "$TOTAL_DOCS" == "null" ] || [ -z "$TOTAL_DOCS" ]; then
        echo -e "${YELLOW}Warning: Index may not exist or is empty${NC}"
        TOTAL_DOCS=0
    fi

    echo "Total IOCs to backup: $TOTAL_DOCS"

    # Export all documents
    BACKUP_FILE="$BACKUP_DIR/threat_intel_${TIMESTAMP}.json"

    curl -s -X GET "$ES_URL/$INDEX_NAME/_search?size=10000&scroll=5m" \
        -H 'Content-Type: application/json' \
        -d '{"query": {"match_all": {}}}' > "$BACKUP_FILE"

    if [ $? -eq 0 ]; then
        # Get file size
        FILESIZE=$(du -h "$BACKUP_FILE" | cut -f1)

        echo -e "${GREEN}✓ Backup created successfully${NC}"
        echo "  File: $BACKUP_FILE"
        echo "  Size: $FILESIZE"
        echo "  IOCs: $TOTAL_DOCS"

        # Create metadata file
        cat > "${BACKUP_FILE}.meta" <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "index": "$INDEX_NAME",
  "total_documents": $TOTAL_DOCS,
  "file": "$(basename $BACKUP_FILE)",
  "size": "$FILESIZE"
}
EOF

        echo -e "${GREEN}✓ Metadata saved${NC}"
        return 0
    else
        echo -e "${RED}✗ Backup failed${NC}"
        return 1
    fi
}

restore_data() {
    local backup_file=$1

    if [ -z "$backup_file" ]; then
        echo -e "${RED}Error: No backup file specified${NC}"
        echo "Usage: $0 restore <backup_file>"
        echo ""
        echo "Available backups:"
        list_backups
        exit 1
    fi

    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}Error: Backup file not found: $backup_file${NC}"
        exit 1
    fi

    echo -e "${BLUE}Restoring from backup: $backup_file${NC}"
    echo -e "${YELLOW}WARNING: This will add data to the existing index${NC}"
    read -p "Continue? [y/N] " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Restore cancelled"
        exit 0
    fi

    # Extract and restore documents
    echo "Extracting documents..."

    # Parse JSON and prepare bulk import
    jq -r '.hits.hits[] | "\(.found)INDEX { \"index\": { \"_index\": \"'$INDEX_NAME'\", \"_id\": \"'\(.\_id)'\" } }\n\(._source)"' \
        "$backup_file" | sed 's/falseINDEX//' > /tmp/bulk_restore.json 2>/dev/null

    if [ ! -s /tmp/bulk_restore.json ]; then
        echo -e "${YELLOW}Warning: No documents found in backup or parsing failed${NC}"
        echo "Trying alternative method..."

        # Alternative: Just extract _source
        jq -c '.hits.hits[]._source' "$backup_file" > /tmp/bulk_restore_simple.json 2>/dev/null

        if [ -s /tmp/bulk_restore_simple.json ]; then
            # Import line by line
            COUNT=0
            while IFS= read -r doc; do
                curl -s -X POST "$ES_URL/$INDEX_NAME/_doc" \
                    -H 'Content-Type: application/json' \
                    -d "$doc" >/dev/null
                COUNT=$((COUNT + 1))
                if [ $((COUNT % 100)) -eq 0 ]; then
                    echo -n "."
                fi
            done < /tmp/bulk_restore_simple.json
            echo ""

            echo -e "${GREEN}✓ Restored $COUNT documents${NC}"
        else
            echo -e "${RED}✗ Restore failed - could not parse backup file${NC}"
            exit 1
        fi
    else
        # Bulk import
        curl -s -X POST "$ES_URL/_bulk" \
            -H 'Content-Type: application/json' \
            --data-binary "@/tmp/bulk_restore.json" > /tmp/bulk_response.json

        # Check for errors
        ERRORS=$(jq -r '.errors' /tmp/bulk_response.json)

        if [ "$ERRORS" == "false" ]; then
            IMPORTED=$(jq -r '.items | length' /tmp/bulk_response.json)
            echo -e "${GREEN}✓ Successfully restored $IMPORTED documents${NC}"
        else
            ERROR_COUNT=$(jq -r '[.items[] | select(.index.error)] | length' /tmp/bulk_response.json)
            echo -e "${YELLOW}⚠ Restore completed with $ERROR_COUNT errors${NC}"
        fi
    fi

    # Cleanup
    rm -f /tmp/bulk_restore.json /tmp/bulk_restore_simple.json /tmp/bulk_response.json

    # Verify
    NEW_COUNT=$(curl -s "$ES_URL/$INDEX_NAME/_count" | jq -r '.count')
    echo "Current IOC count in index: $NEW_COUNT"
}

list_backups() {
    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A $BACKUP_DIR/*.json 2>/dev/null)" ]; then
        echo -e "${YELLOW}No backups found${NC}"
        return
    fi

    echo -e "${BLUE}Available backups:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for backup in "$BACKUP_DIR"/*.json; do
        if [ -f "$backup" ]; then
            FILENAME=$(basename "$backup")
            FILESIZE=$(du -h "$backup" | cut -f1)
            FILEDATE=$(date -r "$backup" "+%Y-%m-%d %H:%M:%S")

            echo "$FILENAME"
            echo "  Date: $FILEDATE"
            echo "  Size: $FILESIZE"

            # Read metadata if available
            if [ -f "${backup}.meta" ]; then
                DOCS=$(jq -r '.total_documents' "${backup}.meta" 2>/dev/null)
                if [ ! -z "$DOCS" ] && [ "$DOCS" != "null" ]; then
                    echo "  IOCs: $DOCS"
                fi
            fi
            echo ""
        fi
    done
}

cleanup_old_backups() {
    local days=${1:-30}

    echo -e "${BLUE}Cleaning up backups older than $days days...${NC}"

    if [ ! -d "$BACKUP_DIR" ]; then
        echo "No backup directory found"
        return
    fi

    # Find and remove old backups
    REMOVED=0
    while IFS= read -r -d '' file; do
        rm -f "$file" "${file}.meta"
        echo "Removed: $(basename $file)"
        REMOVED=$((REMOVED + 1))
    done < <(find "$BACKUP_DIR" -name "*.json" -type f -mtime +$days -print0)

    if [ $REMOVED -eq 0 ]; then
        echo -e "${GREEN}No old backups to remove${NC}"
    else
        echo -e "${GREEN}✓ Removed $REMOVED old backup(s)${NC}"
    fi
}

# Main
case "$1" in
    backup)
        check_elasticsearch
        backup_data
        ;;
    restore)
        check_elasticsearch
        restore_data "$2"
        ;;
    list)
        list_backups
        ;;
    cleanup)
        cleanup_old_backups "$2"
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
