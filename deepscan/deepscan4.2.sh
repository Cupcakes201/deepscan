#!/bin/bash

# DeepScan Pro v4.2 - With Rate Limiting Support
# NEW: Added --delay parameter for rate limiting

set -euo pipefail

# Load WAF Module
source "$(dirname "$0")/waf_module.sh"

# --- COLORES ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

# --- CONFIGURACIÓN ---
AVAILABLE_ENGINES=("dirb" "feroxbuster" "ffuf")
DEFAULT_ENGINE="feroxbuster"
ANALYSIS_TIMEOUT=10
ANALYSIS_BATCH_SIZE=50
MAX_BODY_SIZE=100000

# Noise filtering
MIN_RESPONSE_SIZE=300
SIMILARITY_THRESHOLD=90
BASELINE_HASH=""

# --- HELPERS ---
check_dependencies() {
    local missing=()
    for cmd in curl parallel bc md5sum shuf; do
        ! command -v "$cmd" >/dev/null && missing+=("$cmd")
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing: ${missing[*]}${NC}"
        exit 1
    fi
}

check_engine() {
    local engine="$1"
    if ! command -v "$engine" >/dev/null; then
        echo -e "${RED}[!] $engine not installed${NC}"
        return 1
    fi
    return 0
}

list_engines() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              Available Enumeration Engines                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    for engine in "${AVAILABLE_ENGINES[@]}"; do
        if command -v "$engine" >/dev/null; then
            echo -e "  ${GREEN}✓${NC} ${YELLOW}$engine${NC}"
        else
            echo -e "  ${RED}✗${NC} ${YELLOW}$engine${NC}"
        fi
    done
}

usage() {
    cat << EOF
${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}
${CYAN}║         DeepScan Pro v4.2 - The Final Form                  ║${NC}
${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}

${YELLOW}Usage:${NC} $0 -t <target> -w <wordlist> [options]

${BLUE}Required:${NC}
  -t, --target      Target URL
  -w, --wordlist    Wordlist path

${BLUE}Engine:${NC}
  -e, --engine      dirb|feroxbuster|ffuf [default: feroxbuster]
  -r, --recursive   Enable recursion
  --depth <N>       Recursion depth [default: 4]
  --list-engines    List engines

${BLUE}Optional:${NC}
  -x, --extensions  Extensions (php,html,js)
  -T, --threads     Threads [auto per engine]
  -d, --delay       Delay between requests in milliseconds [default: 0]
  -F, --no-filter   Disable noise filtering
  --fast            Skip critical detection (faster)
  --auto-tune       Engine auto-tuning
  -h, --help        Show help

${GREEN}Examples:${NC}
  ${CYAN}# Fast scan${NC}
  $0 -t http://target.com -w common.txt --auto-tune

  ${CYAN}# Deep recursive${NC}
  $0 -t http://target.com -w common.txt -r -x php,html

  ${CYAN}# Slow scan (for IPS evasion or rate-limited targets)${NC}
  $0 -t http://target.com -w common.txt -T 1 -d 8000

  ${CYAN}# LFI pentest (professional mode)${NC}
  $0 -t http://target.com -w lfi.txt -T 1 -d 5000 -x php,txt

  ${CYAN}# No filtering (raw results)${NC}
  $0 -t http://target.com -w common.txt -F --fast
EOF
    exit 0
}

# --- NOISE FILTERING ---

initialize_baseline() {
    local target="$1"
    
    echo -e "${YELLOW}[*] Establishing baseline...${NC}"
    
    local random_path="/nonexistent_$(openssl rand -hex 8 2>/dev/null || date +%s).html"
    local test_url="${target}${random_path}"
    
    local baseline=$(timeout 5 curl -sk --max-time 5 "$test_url" 2>/dev/null || echo "")
    
    if [ -z "$baseline" ]; then
        echo -e "${YELLOW}[!] No baseline - filtering disabled${NC}"
        return 1
    fi
    
    BASELINE_HASH=$(echo "$baseline" | md5sum | cut -d' ' -f1)
    echo "$baseline" > "${WORK_DIR}/baseline_404.html"
    
    echo -e "${GREEN}[✓] Baseline: ${BASELINE_HASH:0:12}... (${#baseline} bytes)${NC}"
    return 0
}

is_noise() {
    local url="$1"
    local body="$2"
    
    local size=${#body}
    if [ "$size" -lt "$MIN_RESPONSE_SIZE" ]; then
        echo "NOISE: too small ($size < $MIN_RESPONSE_SIZE)"
        return 0
    fi
    
    if [ -n "$BASELINE_HASH" ]; then
        local current_hash=$(echo "$body" | md5sum | cut -d' ' -f1)
        
        if [ "$current_hash" = "$BASELINE_HASH" ]; then
            echo "NOISE: exact baseline match"
            return 0
        fi
        
        local baseline_size=$(stat -c%s "${WORK_DIR}/baseline_404.html" 2>/dev/null || echo 0)
        if [ "$baseline_size" -gt 0 ]; then
            local diff=$((size > baseline_size ? size - baseline_size : baseline_size - size))
            local percent=$((diff * 100 / baseline_size))
            
            if [ "$percent" -lt 10 ]; then
                echo "NOISE: similar to baseline (${percent}% diff)"
                return 0
            fi
        fi
    fi
    
    if echo "$body" | grep -qiE "404 not found|page not found|not found on this server"; then
        echo "NOISE: 404 indicators"
        return 0
    fi
    
    return 1
}

# --- PARALLEL CRITICAL DETECTION ---

analyze_url_parallel() {
    local url="$1"
    local results_dir="$2"
    
    local response=$(timeout "$ANALYSIS_TIMEOUT" curl -skL --max-time "$ANALYSIS_TIMEOUT" \
        --max-filesize "$MAX_BODY_SIZE" "$url" 2>/dev/null || echo "")
    
    if [ -z "$response" ]; then
        echo "$url|timeout" >> "${results_dir}/timeouts.txt"
        return 1
    fi
    
    local size=${#response}
    local status=$(echo "$response" | grep -E "^HTTP" | tail -1 | awk '{print $2}' || echo "000")
    
    echo "$url|$status|$size" >> "${results_dir}/all_results.txt"
    
    if [ "$ENABLE_FILTER" = "true" ] && [ "$status" = "200" ]; then
        local noise_reason=$(is_noise "$url" "$response")
        if [ $? -eq 0 ]; then
            echo "$url|$noise_reason" >> "${results_dir}/filtered.txt"
            return 0
        fi
    fi
    
    if [ "$status" = "200" ]; then
        local critical=false
        local vuln_type=""
        
        local head=$(echo "$response" | head -c 10000)
        
        if echo "$head" | grep -qiE "root:.*:0:0:|bin/bash|etc/passwd"; then
            critical=true
            vuln_type="LFI"
        fi
        
        if echo "$head" | grep -qiE "SQL syntax|mysql_fetch|mysqli_error|pg_query"; then
            critical=true
            vuln_type="${vuln_type:+$vuln_type+}SQLi"
        fi
        
        if echo "$head" | grep -qiE "Warning:.*in /|Fatal error:.*in /|Parse error:"; then
            critical=true
            vuln_type="${vuln_type:+$vuln_type+}PHP"
        fi
        
        if echo "$head" | grep -qiE "Index of /|Parent Directory|\[DIR\]"; then
            critical=true
            vuln_type="${vuln_type:+$vuln_type+}DIR"
        fi
        
        if [[ "$url" =~ \.(bak|old|backup|sql|env)$ ]]; then
            critical=true
            vuln_type="${vuln_type:+$vuln_type+}BACKUP"
        fi
        
        if [ "$critical" = "true" ]; then
            echo "$url|$vuln_type" >> "${results_dir}/critical.txt"
            echo -e "${RED}[🔥] $url [$vuln_type]${NC}" >&2
        fi
    fi
    
    return 0
}

export -f analyze_url_parallel
export -f is_noise
export ANALYSIS_TIMEOUT MAX_BODY_SIZE ENABLE_FILTER WORK_DIR
export MIN_RESPONSE_SIZE SIMILARITY_THRESHOLD BASELINE_HASH
export RED GREEN YELLOW BLUE NC

analyze_results_parallel() {
    local url_file="$1"
    local results_dir="$2"
    
    local total=$(wc -l < "$url_file")
    
    echo -e "\n${PURPLE}[POST-PROCESSING] Analyzing $total URLs (batched)...${NC}"
    echo -e "${CYAN}[*] Timeout: ${ANALYSIS_TIMEOUT}s per URL${NC}"
    echo -e "${CYAN}[*] Batch size: $ANALYSIS_BATCH_SIZE${NC}"
    
    mkdir -p "$results_dir"
    
    cat "$url_file" | \
        parallel --no-notice -j "$ANALYSIS_BATCH_SIZE" --bar \
        analyze_url_parallel {} "$results_dir" 2>&1
    
    echo -e "${GREEN}[✓] Analysis complete${NC}"
    
    local analyzed=$([ -f "${results_dir}/all_results.txt" ] && wc -l < "${results_dir}/all_results.txt" || echo 0)
    local criticals=$([ -f "${results_dir}/critical.txt" ] && wc -l < "${results_dir}/critical.txt" || echo 0)
    local filtered=$([ -f "${results_dir}/filtered.txt" ] && wc -l < "${results_dir}/filtered.txt" || echo 0)
    local timeouts=$([ -f "${results_dir}/timeouts.txt" ] && wc -l < "${results_dir}/timeouts.txt" || echo 0)
    
    echo -e "${CYAN}[*] Analyzed: $analyzed${NC}"
    echo -e "${GREEN}[*] Valid: $((analyzed - filtered))${NC}"
    echo -e "${ORANGE}[*] Filtered: $filtered${NC}"
    echo -e "${RED}[*] Critical: $criticals${NC}"
    [ "$timeouts" -gt 0 ] && echo -e "${YELLOW}[*] Timeouts: $timeouts${NC}"
}

# --- OUTPUT PARSING (FIXED) ---

parse_dirb_output() {
    local output="$1"
    local url_file="$2"
    
    # Combined single-pass awk for efficiency
    awk '/^\+/ && /http/ {print $2} /^==> DIRECTORY:/ {print $3}' "$output" | sort -u > "$url_file"
}

parse_feroxbuster_output() {
    local output="$1"
    local url_file="$2"
    
    # FIXED: Extract any valid HTTP(S) URL
    grep -oE 'https?://[^[:space:]]+' "$output" | \
        grep -v '^$' | \
        sort -u > "$url_file"
}

parse_ffuf_output() {
    local output="$1"
    local url_file="$2"
    
    if command -v jq >/dev/null && [ -f "$output" ]; then
        if jq -e '.results' "$output" >/dev/null 2>&1; then
            jq -r '.results[]? | .url' "$output" 2>/dev/null | sort -u > "$url_file"
            return 0
        fi
    fi
    
    grep -oE '"url"\s*:\s*"[^"]*"' "$output" 2>/dev/null | \
        sed 's/"url"[[:space:]]*:[[:space:]]*"//;s/"$//' | \
        grep -E '^https?://' | \
        grep -v "FUZZ" | \
        sort -u > "$url_file"
}

# --- LIVE OUTPUT WRAPPER ---

wrap_engine_output() {
    local engine="$1"
    
    while IFS= read -r line; do
        if [[ "$line" =~ 200 ]]; then
            echo -e "${GREEN}$line${NC}"
        elif [[ "$line" =~ (403|401) ]]; then
            echo -e "${YELLOW}$line${NC}"
        elif [[ "$line" =~ (500|502|503) ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ "$line" =~ (301|302|307) ]]; then
            echo -e "${BLUE}$line${NC}"
        elif [[ "$line" =~ (WLD|DIRECTORY|FOUND) ]]; then
            echo -e "${PURPLE}$line${NC}"
        else
            echo "$line"
        fi
    done
}

# --- ENGINE RUNNERS ---

run_dirb() {
    local target="$1"
    local wordlist="$2"
    local output="$3"
    local extensions="$4"
    local delay="$5"
    
    echo -e "${PURPLE}[ENGINE: DIRB]${NC}"
    
    # WAF: Rotate resources
    rotate_user_agent
    rotate_proxy
    waf_load_evasion_headers
    local jitter=$(get_jitter_delay "$delay")
    
    local opts=("-S" "-w")
    [ -n "$extensions" ] && opts+=("-X" ".$extensions")
    
    # Proxy Logic
    if [ -n "$CURRENT_PROXY" ]; then
        opts+=("-p" "$CURRENT_PROXY")
    elif [ -n "$PROXY" ]; then
        opts+=("-p" "$PROXY")
    fi

    [ "$jitter" -gt 0 ] && opts+=("-z" "$jitter")
    
    # WAF: Add evasion headers
    for h in "${WAF_EVASION_HEADERS[@]}"; do
        opts+=("-H" "$h")
    done
    
    # WAF: Use rotated UA
    opts+=("-a" "$CURRENT_UA")
    
    echo -e "${YELLOW}[WAF] UA: ${CURRENT_UA:0:30}... | Jitter: $jitter ms${NC}"
    dirb "$target" "$wordlist" "${opts[@]}" 2>&1 | tee "$output" | wrap_engine_output "dirb"
}

run_feroxbuster() {
    local target="$1"
    local wordlist="$2"
    local output="$3"
    local extensions="$4"
    local recursive="$5"
    local depth="$6"
    local auto_tune="$7"
    local delay="$8"
    
    echo -e "${PURPLE}[ENGINE: Feroxbuster]${NC}"
    
    # WAF: Rotate resources
    rotate_user_agent
    rotate_proxy
    waf_load_evasion_headers
    local jitter=$(get_jitter_delay "$delay")
    
    local opts=(
        "--url" "$target"
        "--wordlist" "$wordlist"
        "--output" "$output"
        "--silent"
        "--user-agent" "$CURRENT_UA"
    )

    # Proxy Logic
    if [ -n "$CURRENT_PROXY" ]; then
        opts+=("--proxy" "$CURRENT_PROXY")
    elif [ -n "$PROXY" ]; then
        opts+=("--proxy" "$PROXY")
    fi
    
    # WAF: Add evasion headers
    for h in "${WAF_EVASION_HEADERS[@]}"; do
        opts+=("--headers" "$h")
    done
    
    # --- LÓGICA DE RATE LIMITING ---
    if [ "$jitter" -gt 0 ]; then
        # Feroxbuster usa peticiones por SEGUNDO (RPS).
        local rps=$((1000 / jitter))
        [ "$rps" -eq 0 ] && rps=1
        
        opts+=("--rate-limit" "$rps")
        opts+=("--threads" "1")
        echo -e "${YELLOW}[*] Modo Lento (WAF Jitter): ${rps} req/s (Delay: ${jitter}ms)${NC}"
    else
        opts+=("--threads" "${THREADS:-50}")
    fi
    
    # --- RECURSIÓN ---
    if [ "$recursive" = "true" ]; then
        opts+=("--depth" "$depth" "--extract-links")
    else
        opts+=("--no-recursion")
    fi
    
    # --- EXTENSIONES ---
    if [ -n "$extensions" ]; then
        opts+=("--extensions" "$extensions")
    fi
    
    # --- AUTO-TUNE ---
    if [ "$auto_tune" = "true" ]; then
        opts+=("--auto-tune" "--auto-bail")
    fi
    
    # --- FILTROS Y PROXY ---
    opts+=("--status-codes" "200,204,301,302,307,308,401,403,405,500")
    [ -n "$PROXY" ] && opts+=("--proxy" "$PROXY")
    
    echo -e "${YELLOW}[*] Ejecutando Feroxbuster...${NC}"
    feroxbuster "${opts[@]}" 2>&1 | wrap_engine_output "feroxbuster"
}

run_ffuf() {
    local target="$1"
    local wordlist="$2"
    local output="$3"
    local extensions="$4"
    local recursive="$5"
    local depth="$6"
    local auto_tune="$7"
    local delay="$8"
    
    echo -e "${PURPLE}[ENGINE: FFUF]${NC}"
    
    # WAF: Rotate
    rotate_user_agent
    rotate_proxy
    waf_load_evasion_headers
    local jitter=$(get_jitter_delay "$delay")
    
    local fuzz_url="${target}/FUZZ"
    
    local opts=(
        "-u" "$fuzz_url"
        "-w" "$wordlist"
        "-o" "$output"
        "-of" "json"
        "-t" "${THREADS:-100}"
        "-mc" "200,204,301,302,307,308,401,403,405,500"
        "-fc" "404"
        "-s"
        "-H" "User-Agent: $CURRENT_UA"
    )
    
    # WAF: Headers
    for h in "${WAF_EVASION_HEADERS[@]}"; do
        opts+=("-H" "$h")
    done
    
    # Jitter logic for FFUF (supports float seconds)
    if [ "$jitter" -gt 0 ]; then
         local sec=$(echo "scale=3; $jitter / 1000" | bc)
         opts+=("-p" "$sec")
         echo -e "${YELLOW}[WAF] Jitter delay: ${sec}s${NC}"
    fi

    [ "$auto_tune" = "true" ] && opts+=("-ac")
    [ "$recursive" = "true" ] && opts+=("-recursion" "-recursion-depth" "$depth")
    [ -n "$extensions" ] && opts+=("-e" ".$extensions")
    
    # Proxy Logic
    if [ -n "$CURRENT_PROXY" ]; then
        opts+=("-x" "$CURRENT_PROXY")
    elif [ -n "$PROXY" ]; then
        opts+=("-x" "$PROXY")
    fi
    
    ffuf "${opts[@]}" 2>&1 | wrap_engine_output "ffuf"
}

# --- REPORT GENERATION ---

generate_report() {
    local results_dir="$1"
    local report_file="$2"
    
    local total=$([ -f "${results_dir}/all_results.txt" ] && wc -l < "${results_dir}/all_results.txt" || echo 0)
    local filtered=$([ -f "${results_dir}/filtered.txt" ] && wc -l < "${results_dir}/filtered.txt" || echo 0)
    local critical=$([ -f "${results_dir}/critical.txt" ] && wc -l < "${results_dir}/critical.txt" || echo 0)
    local valid=$((total - filtered))
    
    cat > "$report_file" << EOF
╔══════════════════════════════════════════════════════════════╗
║              DeepScan Pro v4.2 - Report                      ║
╚══════════════════════════════════════════════════════════════╝

Target: $TARGET
Engine: $ENGINE
Date: $(date)

═══ STATISTICS ═══
Total analyzed: $total
├─ Valid: $valid
├─ Filtered (noise): $filtered
└─ 🔥 Critical: $critical

═══ CONFIGURATION ═══
Engine: $ENGINE
Recursive: ${RECURSIVE:-false}
Extensions: ${EXTENSIONS:-none}
Threads: ${THREADS:-auto}
Delay: ${DELAY:-0}ms
Auto-tune: ${AUTO_TUNE:-false}
Noise filter: ${ENABLE_FILTER:-true}
Fast mode: ${FAST_MODE:-false}

EOF

    if [ "$critical" -gt 0 ]; then
        echo "═══ ⚠️  CRITICAL FINDINGS ═══" >> "$report_file"
        cat "${results_dir}/critical.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    if [ "$ENABLE_FILTER" = "true" ] && [ "$filtered" -gt 0 ]; then
        echo "═══ FILTERED (NOISE) ═══" >> "$report_file"
        head -20 "${results_dir}/filtered.txt" >> "$report_file"
        [ "$filtered" -gt 20 ] && echo "... and $((filtered - 20)) more" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    echo "═══ ALL FINDINGS ═══" >> "$report_file"
    if [ -f "${results_dir}/all_results.txt" ]; then
        while IFS='|' read -r url status size; do
            case "$status" in
                200) echo "[✓] $url ($size bytes)" >> "$report_file" ;;
                403|401) echo "[✗] $url ($status)" >> "$report_file" ;;
                *) echo "[?] $url ($status)" >> "$report_file" ;;
            esac
        done < "${results_dir}/all_results.txt"
    fi
}

# --- MAIN ---

# Defaults
ENGINE="$DEFAULT_ENGINE"
RECURSIVE=false
DEPTH=4
EXTENSIONS=""
PROXY=""
THREADS=""
DELAY=0
AUTO_TUNE=false
ENABLE_FILTER=true
FAST_MODE=false

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target) TARGET="$2"; shift 2 ;;
        -w|--wordlist) WORDLIST="$2"; shift 2 ;;
        -e|--engine) ENGINE="$2"; shift 2 ;;
        -r|--recursive) RECURSIVE=true; shift ;;
        --depth) DEPTH="$2"; shift 2 ;;
        -x|--extensions) EXTENSIONS="$2"; shift 2 ;;
        -T|--threads) THREADS="$2"; shift 2 ;;
        -d|--delay) DELAY="$2"; shift 2 ;;
        -F|--no-filter) ENABLE_FILTER=false; shift ;;
        --fast) FAST_MODE=true; shift ;;
        --auto-tune) AUTO_TUNE=true; shift ;;
        --list-engines) list_engines; exit 0 ;;
        -h|--help) usage ;;
        *) echo -e "${RED}[!] Unknown: $1${NC}"; usage ;;
    esac
done

# Validate
if [ -z "$TARGET" ] || [ -z "$WORDLIST" ]; then
    usage
fi
[[ ! "$TARGET" =~ ^https?:// ]] && TARGET="http://${TARGET}"
[ ! -f "$WORDLIST" ] && { echo -e "${RED}[!] Wordlist not found${NC}"; exit 1; }

check_dependencies
check_engine "$ENGINE" || exit 1

# WAF Init
waf_init || exit 1

# Setup
TIMESTAMP=$(date +%s)
WORK_DIR="scan_${ENGINE}_${TIMESTAMP}"
RESULTS_DIR="${WORK_DIR}/results"
mkdir -p "$RESULTS_DIR"

ENGINE_OUTPUT="${WORK_DIR}/engine_raw.txt"
URL_FILE="${WORK_DIR}/urls.txt"
REPORT="${WORK_DIR}/report.txt"

# Banner
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          DeepScan Pro v4.2 - The Final Form                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}Target:${NC} $TARGET"
echo -e "${BLUE}Engine:${NC} ${YELLOW}$ENGINE${NC}"
echo -e "${BLUE}Wordlist:${NC} $(basename "$WORDLIST") ($(wc -l < "$WORDLIST") lines)"
[ "$DELAY" -gt 0 ] && echo -e "${BLUE}Delay:${NC} ${ORANGE}${DELAY}ms${NC}"
echo ""

# Phase 0: Baseline
if [ "$ENABLE_FILTER" = "true" ]; then
    initialize_baseline "$TARGET" || ENABLE_FILTER=false
    echo ""
fi

# Phase 1: Engine
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║ PHASE 1: Enumeration                                         ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"

case "$ENGINE" in
    dirb) run_dirb "$TARGET" "$WORDLIST" "$ENGINE_OUTPUT" "$EXTENSIONS" "$DELAY" ;;
    feroxbuster) run_feroxbuster "$TARGET" "$WORDLIST" "$ENGINE_OUTPUT" "$EXTENSIONS" "$RECURSIVE" "$DEPTH" "$AUTO_TUNE" "$DELAY" ;;
    ffuf) run_ffuf "$TARGET" "$WORDLIST" "$ENGINE_OUTPUT" "$EXTENSIONS" "$RECURSIVE" "$DEPTH" "$AUTO_TUNE" "$DELAY" ;;
esac

# Phase 2: Parse
echo -e "\n${PURPLE}[PHASE 2] Parsing results...${NC}"

case "$ENGINE" in
    dirb) parse_dirb_output "$ENGINE_OUTPUT" "$URL_FILE" ;;
    feroxbuster) parse_feroxbuster_output "$ENGINE_OUTPUT" "$URL_FILE" ;;
    ffuf) parse_ffuf_output "$ENGINE_OUTPUT" "$URL_FILE" ;;
esac

if [ ! -s "$URL_FILE" ]; then
    echo -e "${YELLOW}[!] No URLs found${NC}"
    exit 0
fi

TOTAL=$(wc -l < "$URL_FILE")
echo -e "${GREEN}[✓] Found $TOTAL URLs${NC}"

# Phase 3: Analysis
if [ "$FAST_MODE" = "false" ]; then
    analyze_results_parallel "$URL_FILE" "$RESULTS_DIR"
else
    echo -e "${YELLOW}[*] Fast mode: skipping analysis${NC}"
    awk -F'|' '{print $1"|200|0"}' "$URL_FILE" > "${RESULTS_DIR}/all_results.txt"
fi

# Phase 4: Report
echo -e "\n${PURPLE}[PHASE 4] Generating report...${NC}"
generate_report "$RESULTS_DIR" "$REPORT"

cat "$REPORT"

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ✓ SCAN COMPLETE                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${GREEN}[✓] Report: $REPORT${NC}"

if [ -f "${RESULTS_DIR}/critical.txt" ]; then
    CRIT=$(wc -l < "${RESULTS_DIR}/critical.txt")
    [ "$CRIT" -gt 0 ] && echo -e "${RED}[🔥] $CRIT CRITICAL FINDINGS!${NC}"
fi

exit 0
