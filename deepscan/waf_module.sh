#!/bin/bash

# WAF Resilience Module for DeepScan Pro
# Version: 1.0 (Educational WAF Testing)

# Configuration Paths
WAF_CONFIG_DIR="$(dirname "$0")/config"
UA_FILE="${WAF_CONFIG_DIR}/user_agents.txt"
HEADERS_FILE="${WAF_CONFIG_DIR}/headers.txt"
PROXIES_FILE="${WAF_CONFIG_DIR}/proxies.txt"

# State
CURRENT_UA=""
CURRENT_PROXY=""
EXTRA_HEADERS=()

# --- INIT ---
waf_init() {
    if [ ! -d "$WAF_CONFIG_DIR" ]; then
        echo -e "${YELLOW}[WAF] Creating config directory...${NC}"
        mkdir -p "$WAF_CONFIG_DIR"
    fi
    
    # Check for User-Agent file
    if [ ! -f "$UA_FILE" ]; then
        echo -e "${RED}[WAF] Error: User-Agent file not found at $UA_FILE${NC}"
        return 1
    fi
    
    # Pick initial random User-Agent and Proxy
    rotate_user_agent
    rotate_proxy
    
    echo -e "${GREEN}[WAF] Module loaded.${NC}"
    echo -e "${GREEN}[WAF] UA: ${CURRENT_UA:0:40}...${NC}"
    [ -n "$CURRENT_PROXY" ] && echo -e "${GREEN}[WAF] Proxy: $CURRENT_PROXY${NC}"
    return 0
}

# --- FUNCTIONS ---

# Rotates the User-Agent string from the file
rotate_user_agent() {
    if [ -f "$UA_FILE" ]; then
        CURRENT_UA=$(shuf -n 1 "$UA_FILE")
    else
        CURRENT_UA="Mozilla/5.0 (Compatible; DeepScan/4.2)"
    fi
}

# Rotates the Proxy from the file
rotate_proxy() {
    if [ -f "$PROXIES_FILE" ] && [ -s "$PROXIES_FILE" ]; then
        # Filter out comments and empty lines
        local proxy=$(grep -vE "^#|^$" "$PROXIES_FILE" | shuf -n 1)
        if [ -n "$proxy" ]; then
            CURRENT_PROXY="$proxy"
        fi
    fi
}

# Generates random "Jitter" delay
# Usage: get_jitter_delay <base_delay_ms>
# Returns: milliseconds (integer)
get_jitter_delay() {
    local base=$1
    if [ "$base" -eq 0 ]; then
        echo "0"
        return
    fi
    
    # +/- 30% Variance
    local variance=$((base * 30 / 100))
    local rand=$(shuf -i 0-$((variance * 2)) -n 1)
    local jitter=$((rand - variance))
    local final=$((base + jitter))
    
    # Ensure no negative delay
    [ "$final" -lt 0 ] && final=0
    echo "$final"
}

# Populates global WAF_EVASION_HEADERS array
waf_load_evasion_headers() {
    WAF_EVASION_HEADERS=()
    
    # Random "X-Forwarded-For" to bypass IP blocks
    local rand_ip="$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"
    WAF_EVASION_HEADERS+=("X-Forwarded-For: $rand_ip")
    WAF_EVASION_HEADERS+=("X-Originating-IP: $rand_ip")
    WAF_EVASION_HEADERS+=("X-Remote-IP: $rand_ip")
    WAF_EVASION_HEADERS+=("X-Remote-Addr: $rand_ip")
    
    # Add random Referer from list if available
    if [ -f "$HEADERS_FILE" ]; then
        local rand_referer=$(grep "^Referer:" "$HEADERS_FILE" | shuf -n 1)
        [ -n "$rand_referer" ] && WAF_EVASION_HEADERS+=("$rand_referer")
    fi
}

# Generates engine-specific arguments
# Usage: waf_get_engine_args <engine> <delay_ms>
waf_get_engine_args() {
    local engine=$1
    local delay=$2
    local extra_args=""
    
    # Rotate resources for this run
    rotate_user_agent
    local jittered_delay=$(get_jitter_delay "$delay")
    
    # Load Headers into WAF_EVASION_HEADERS
    waf_load_evasion_headers
    
    # NOTE: This function returns a string for simple concatenation, 
    # but for complex scripts it is better to use the globals directly.
    # We keep this for backward compatibility or simple usage.
    
    case "$engine" in
        feroxbuster)
            extra_args+=" --user-agent \"$CURRENT_UA\""
            for h in "${WAF_EVASION_HEADERS[@]}"; do
                extra_args+=" --headers \"$h\""
            done
            ;;
        ffuf)
            extra_args+=" -H \"User-Agent: $CURRENT_UA\""
            for h in "${WAF_EVASION_HEADERS[@]}"; do
                extra_args+=" -H \"$h\""
            done
            ;;
        dirb)
            extra_args+=" -a \"$CURRENT_UA\""
            for h in "${WAF_EVASION_HEADERS[@]}"; do
                extra_args+=" -H \"$h\""
            done
            ;;
    esac
    
    echo "$extra_args"
}

export -f waf_init
export -f rotate_user_agent
export -f rotate_proxy
export -f get_jitter_delay
export -f waf_load_evasion_headers
export -f waf_get_engine_args
export WAF_EVASION_HEADERS
export CURRENT_PROXY

