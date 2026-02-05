#!/bin/bash

# generate_reports.sh - Generate HTML/JSON reports from DeepScan results
# Usage: ./generate_reports.sh <scan_directory> [--html] [--json] [--both]

set -euo pipefail

# --- COLORES ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- HELPERS ---
usage() {
    cat << EOF
${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}
${CYAN}║         DeepScan Report Generator v1.0                       ║${NC}
${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}

${YELLOW}Usage:${NC} $0 <scan_directory> [options]

${BLUE}Options:${NC}
  --html        Generate HTML report only
  --json        Generate JSON report only
  --both        Generate both (default)
  -h, --help    Show help

${GREEN}Examples:${NC}
  ${CYAN}# Generate both${NC}
  $0 scan_feroxbuster_1234567890

  ${CYAN}# HTML only${NC}
  $0 scan_feroxbuster_1234567890 --html

  ${CYAN}# From last scan${NC}
  $0 \$(ls -td scan_* | head -1) --both
EOF
    exit 0
}

# --- VALIDATION ---
if [ $# -lt 1 ]; then
    usage
fi

SCAN_DIR="$1"
shift

# Parse options
GENERATE_HTML=false
GENERATE_JSON=false

if [ $# -eq 0 ]; then
    GENERATE_HTML=true
    GENERATE_JSON=true
else
    while [[ $# -gt 0 ]]; do
        case $1 in
            --html) GENERATE_HTML=true; shift ;;
            --json) GENERATE_JSON=true; shift ;;
            --both) GENERATE_HTML=true; GENERATE_JSON=true; shift ;;
            -h|--help) usage ;;
            *) echo -e "${RED}[!] Unknown option: $1${NC}"; usage ;;
        esac
    done
fi

# Validate scan directory
if [ ! -d "$SCAN_DIR" ]; then
    echo -e "${RED}[!] Scan directory not found: $SCAN_DIR${NC}"
    exit 1
fi

if [ ! -d "$SCAN_DIR/results" ]; then
    echo -e "${RED}[!] Invalid scan directory (missing results/)${NC}"
    exit 1
fi

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              Generating Reports                              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[*] Scan directory:${NC} $SCAN_DIR"
echo ""

# --- GATHER DATA ---
RESULTS_DIR="$SCAN_DIR/results"
ALL_RESULTS="${RESULTS_DIR}/all_results.txt"
CRITICAL="${RESULTS_DIR}/critical.txt"
FILTERED="${RESULTS_DIR}/filtered.txt"
TIMEOUTS="${RESULTS_DIR}/timeouts.txt"
REPORT_TXT="$SCAN_DIR/report.txt"

# Extract metadata from report.txt
TARGET=$(grep "^Target:" "$REPORT_TXT" 2>/dev/null | cut -d' ' -f2- || echo "unknown")
ENGINE=$(grep "^Engine:" "$REPORT_TXT" 2>/dev/null | cut -d' ' -f2- || echo "unknown")
SCAN_DATE=$(grep "^Date:" "$REPORT_TXT" 2>/dev/null | cut -d' ' -f2- || date)

# Calculate stats - FIXED: Proper counting
TOTAL=$([ -f "$ALL_RESULTS" ] && wc -l < "$ALL_RESULTS" 2>/dev/null || echo 0)
URLS_200=$([ -f "$ALL_RESULTS" ] && grep -c "|200|" "$ALL_RESULTS" 2>/dev/null || echo 0)
URLS_403=$([ -f "$ALL_RESULTS" ] && grep -c "|403|" "$ALL_RESULTS" 2>/dev/null || echo 0)
URLS_401=$([ -f "$ALL_RESULTS" ] && grep -c "|401|" "$ALL_RESULTS" 2>/dev/null || echo 0)
URLS_500=$([ -f "$ALL_RESULTS" ] && grep -c "|500|" "$ALL_RESULTS" 2>/dev/null || echo 0)
CRITICAL_COUNT=$([ -f "$CRITICAL" ] && wc -l < "$CRITICAL" 2>/dev/null || echo 0)
FILTERED_COUNT=$([ -f "$FILTERED" ] && wc -l < "$FILTERED" 2>/dev/null || echo 0)
TIMEOUT_COUNT=$([ -f "$TIMEOUTS" ] && wc -l < "$TIMEOUTS" 2>/dev/null || echo 0)

echo -e "${YELLOW}[*] Statistics:${NC}"
echo -e "    Total URLs: $TOTAL"
echo -e "    200 OK: $URLS_200"
echo -e "    403 Forbidden: $URLS_403"
echo -e "    Critical: $CRITICAL_COUNT"
echo ""

# --- ESCAPE FUNCTION FOR JSON ---
json_escape() {
    local string="$1"
    # Escape backslashes, quotes, and control characters
    printf '%s' "$string" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

# --- GENERATE JSON ---
if [ "$GENERATE_JSON" = true ]; then
    echo -e "${CYAN}[*] Generating JSON report...${NC}"
    
    JSON_FILE="$SCAN_DIR/report.json"
    
    # Start JSON
    cat > "$JSON_FILE" << EOF
{
  "scan_info": {
    "target": "$(json_escape "$TARGET")",
    "engine": "$(json_escape "$ENGINE")",
    "date": "$(json_escape "$SCAN_DATE")",
    "scan_directory": "$(json_escape "$SCAN_DIR")"
  },
  "statistics": {
    "total_urls": $TOTAL,
    "status_200": $URLS_200,
    "status_403": $URLS_403,
    "status_401": $URLS_401,
    "status_500": $URLS_500,
    "critical_findings": $CRITICAL_COUNT,
    "filtered_noise": $FILTERED_COUNT,
    "timeouts": $TIMEOUT_COUNT
  },
  "critical_findings": [
EOF

    # Add critical findings - FIXED
    if [ -f "$CRITICAL" ] && [ -s "$CRITICAL" ]; then
        first=true
        while IFS='|' read -r url vuln_type || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            [ "$first" = false ] && echo "," >> "$JSON_FILE"
            first=false
            cat >> "$JSON_FILE" << JSONEOF
    {
      "url": "$(json_escape "$url")",
      "type": "$(json_escape "$vuln_type")",
      "severity": "critical"
    }
JSONEOF
        done < "$CRITICAL"
        echo "" >> "$JSON_FILE"
    fi
    
    echo "  ]," >> "$JSON_FILE"
    
    # Add all results - FIXED
    echo '  "all_results": [' >> "$JSON_FILE"
    
    if [ -f "$ALL_RESULTS" ] && [ -s "$ALL_RESULTS" ]; then
        first=true
        while IFS='|' read -r url status size || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            [ "$first" = false ] && echo "," >> "$JSON_FILE"
            first=false
            
            # Validate numeric fields
            status=${status:-0}
            size=${size:-0}
            
            cat >> "$JSON_FILE" << JSONEOF
    {
      "url": "$(json_escape "$url")",
      "status": $status,
      "size": $size
    }
JSONEOF
        done < "$ALL_RESULTS"
        echo "" >> "$JSON_FILE"
    fi
    
    echo "  ]," >> "$JSON_FILE"
    
    # Add filtered - FIXED
    echo '  "filtered": [' >> "$JSON_FILE"
    
    if [ -f "$FILTERED" ] && [ -s "$FILTERED" ]; then
        first=true
        while IFS='|' read -r url reason || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            [ "$first" = false ] && echo "," >> "$JSON_FILE"
            first=false
            cat >> "$JSON_FILE" << JSONEOF
    {
      "url": "$(json_escape "$url")",
      "reason": "$(json_escape "$reason")"
    }
JSONEOF
        done < "$FILTERED"
        echo "" >> "$JSON_FILE"
    fi
    
    echo "  ]" >> "$JSON_FILE"
    echo "}" >> "$JSON_FILE"
    
    # Validate JSON
    if command -v jq >/dev/null 2>&1; then
        if jq empty "$JSON_FILE" 2>/dev/null; then
            echo -e "${GREEN}[✓] JSON report: $JSON_FILE${NC}"
        else
            echo -e "${YELLOW}[!] JSON validation failed - check syntax${NC}"
            jq empty "$JSON_FILE" 2>&1 | head -5
        fi
    else
        echo -e "${GREEN}[✓] JSON report: $JSON_FILE (not validated - install jq)${NC}"
    fi
fi

# --- GENERATE HTML ---
if [ "$GENERATE_HTML" = true ]; then
    echo -e "${CYAN}[*] Generating HTML report...${NC}"
    
    HTML_FILE="$SCAN_DIR/report.html"
    
    # Generate critical findings HTML
    critical_html=""
    if [ -f "$CRITICAL" ] && [ -s "$CRITICAL" ]; then
        while IFS='|' read -r url vuln_type || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            critical_html+='<div class="finding critical">'
            critical_html+='<div class="finding-url">'"$(echo "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"'</div>'
            critical_html+='<div><span class="badge badge-danger">🔥 '"$vuln_type"'</span></div>'
            critical_html+='</div>'
        done < "$CRITICAL"
    else
        critical_html='<div class="empty-state"><p style="color:#28a745;font-size:1.5em;">✅ No critical findings</p></div>'
    fi
    
    # Generate all findings HTML
    all_html=""
    if [ -f "$ALL_RESULTS" ] && [ -s "$ALL_RESULTS" ]; then
        while IFS='|' read -r url status size || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            
            badge_class="badge-success"
            badge_text="$status"
            
            case $status in
                200) badge_class="badge-success"; badge_text="200 OK" ;;
                403) badge_class="badge-warning"; badge_text="403 Forbidden" ;;
                401) badge_class="badge-warning"; badge_text="401 Unauthorized" ;;
                500) badge_class="badge-danger"; badge_text="500 Error" ;;
                *) badge_class="badge-info"; badge_text="$status" ;;
            esac
            
            all_html+='<div class="finding">'
            all_html+='<div class="finding-url">'"$(echo "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"'</div>'
            all_html+='<div><span class="badge '"$badge_class"'">'"$badge_text"'</span>'
            all_html+='<span class="badge badge-info">📦 '"$size"' bytes</span></div>'
            all_html+='</div>'
        done < "$ALL_RESULTS"
    else
        all_html='<div class="empty-state"><p>No results</p></div>'
    fi
    
    # Generate filtered HTML
    filtered_html=""
    if [ -f "$FILTERED" ] && [ -s "$FILTERED" ]; then
        while IFS='|' read -r url reason || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            filtered_html+='<div class="finding">'
            filtered_html+='<div class="finding-url">'"$(echo "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"'</div>'
            filtered_html+='<div><span class="badge badge-secondary">🗑️ Filtered</span></div>'
            filtered_html+='<p style="color:#666;margin-top:10px;font-size:0.9em;">'"$(echo "$reason" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"'</p>'
            filtered_html+='</div>'
        done < "$FILTERED"
    else
        filtered_html='<div class="empty-state"><p>No filtered URLs</p></div>'
    fi
    
    # Critical banner class
    critical_banner_class=""
    [ "$CRITICAL_COUNT" -gt 0 ] && critical_banner_class="show"
    
    # Write HTML file with all substitutions
    cat > "$HTML_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeepScan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .critical-banner {
            background: linear-gradient(135deg, #ff4757 0%, #dc3545 100%);
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 1.5em;
            font-weight: bold;
            display: none;
        }
        
        .critical-banner.show { display: block; }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        
        .stat-card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .stat-card.success h3 { color: #28a745; }
        .stat-card.warning h3 { color: #ffc107; }
        .stat-card.danger h3 { color: #dc3545; }
        .stat-card.info h3 { color: #17a2b8; }
        
        .section {
            padding: 30px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 2em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            border-bottom: 2px solid #e9ecef;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 15px 30px;
            background: transparent;
            border: none;
            cursor: pointer;
            font-size: 1em;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .tab:hover { color: #667eea; }
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s;
        }
        
        .tab-content.active { display: block; }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .finding {
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 5px solid #667eea;
            transition: all 0.3s;
        }
        
        .finding:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }
        
        .finding.critical {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .finding.critical:hover { background: #ffe6e6; }
        
        .finding-url {
            font-family: 'Courier New', monospace;
            color: #667eea;
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 10px;
            word-break: break-all;
        }
        
        .finding.critical .finding-url { color: #dc3545; }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 8px;
            margin-top: 5px;
        }
        
        .badge-success { background: #28a745; color: white; }
        .badge-warning { background: #ffc107; color: #333; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        .badge-secondary { background: #6c757d; color: white; }
        
        .search-box {
            width: 100%;
            padding: 15px;
            margin-bottom: 20px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 1em;
        }
        
        .search-box:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px;
            color: #999;
        }
        
        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 DeepScan Pro v4.2</h1>
            <p>Security Analysis Report</p>
            <p style="opacity: 0.8; margin-top: 10px;">$SCAN_DATE</p>
        </div>

        <div class="critical-banner $critical_banner_class">
            ⚠️ $CRITICAL_COUNT CRITICAL VULNERABILITIES DETECTED ⚠️
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>$TOTAL</h3>
                <p>Total URLs</p>
            </div>
            <div class="stat-card success">
                <h3>$URLS_200</h3>
                <p>200 OK</p>
            </div>
            <div class="stat-card warning">
                <h3>$URLS_403</h3>
                <p>403 Forbidden</p>
            </div>
            <div class="stat-card danger">
                <h3>$CRITICAL_COUNT</h3>
                <p>🔥 Critical</p>
            </div>
            <div class="stat-card info">
                <h3>$FILTERED_COUNT</h3>
                <p>Filtered (Noise)</p>
            </div>
        </div>

        <div class="section">
            <div class="tabs">
                <button class="tab active" onclick="openTab('critical')">🔥 Critical</button>
                <button class="tab" onclick="openTab('all')">📋 All URLs</button>
                <button class="tab" onclick="openTab('filtered')">🗑️ Filtered</button>
                <button class="tab" onclick="openTab('info')">ℹ️ Info</button>
            </div>

            <div id="critical" class="tab-content active">
                <h2>🔥 Critical Findings</h2>
                <input type="text" class="search-box" placeholder="🔍 Search..." onkeyup="filterFindings(this.value, 'critical-list')">
                <div id="critical-list">
                    $critical_html
                </div>
            </div>

            <div id="all" class="tab-content">
                <h2>📋 All URLs</h2>
                <input type="text" class="search-box" placeholder="🔍 Search..." onkeyup="filterFindings(this.value, 'all-list')">
                <div id="all-list">
                    $all_html
                </div>
            </div>

            <div id="filtered" class="tab-content">
                <h2>🗑️ Filtered (Noise)</h2>
                <input type="text" class="search-box" placeholder="🔍 Search..." onkeyup="filterFindings(this.value, 'filtered-list')">
                <div id="filtered-list">
                    $filtered_html
                </div>
            </div>

            <div id="info" class="tab-content">
                <h2>ℹ️ Scan Information</h2>
                <div class="finding">
                    <div class="finding-url">Target</div>
                    <p>$TARGET</p>
                </div>
                <div class="finding">
                    <div class="finding-url">Engine</div>
                    <p>$ENGINE</p>
                </div>
                <div class="finding">
                    <div class="finding-url">Date</div>
                    <p>$SCAN_DATE</p>
                </div>
                <div class="finding">
                    <div class="finding-url">Scan Directory</div>
                    <p>$SCAN_DIR</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>🛡️ DeepScan Pro v4.2 - The Final Form</p>
            <p style="margin-top: 10px; opacity: 0.7;">Generated: $SCAN_DATE</p>
        </div>
    </div>

    <script>
        function openTab(tabName) {
            const tabs = document.querySelectorAll('.tab');
            const contents = document.querySelectorAll('.tab-content');
            
            tabs.forEach(tab => tab.classList.remove('active'));
            contents.forEach(content => content.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        function filterFindings(query, containerId) {
            const container = document.getElementById(containerId);
            const items = container.querySelectorAll('.finding');
            const lowerQuery = query.toLowerCase();
            
            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(lowerQuery) ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>
HTMLEOF
    
    echo -e "${GREEN}[✓] HTML report: $HTML_FILE${NC}"
    echo -e "${CYAN}[*] Open with: firefox $HTML_FILE${NC}"
fi

# --- SUMMARY ---
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  ✓ REPORTS GENERATED                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

[ "$GENERATE_JSON" = true ] && echo -e "${GREEN}[✓] JSON: $SCAN_DIR/report.json${NC}"
[ "$GENERATE_HTML" = true ] && echo -e "${GREEN}[✓] HTML: $SCAN_DIR/report.html${NC}"

exit 0
