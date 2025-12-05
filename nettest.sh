#!/bin/zsh

# ==============================================================================
# macOS Network Diagnostics Tool (OSI Layer 1-7)
# ==============================================================================
# Author: werner sellschopp / macOS Infrastructure
# Version: 1.0.0 (Fix: Strict separation of IP Routing vs. DNS Configuration)
# Description: Read-only diagnostic tool. Robust SSID detection & DNS analysis.
# Permissions: Requires root (sudo).
# ==============================================================================

# --- Configuration & Dynamic Path Discovery ---
find_airport_binary() {
    local paths=(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"
        "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
    )
    for p in "${paths[@]}"; do
        if [[ -x "$p" ]]; then echo "$p"; return; fi
    done
}
AIRPORT_CMD=$(find_airport_binary)

# --- ANSI Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- State Variables ---
VPN_ACTIVE=false
PRIMARY_IF=""
GATEWAY_IP=""
DNS_SERVER_IP=""
HAS_NMAP=false
HAS_DIG=false
HAS_MTR=false

# ==============================================================================
# Helper Functions
# ==============================================================================

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
header() { echo -e "\n${BOLD}============================================================\n $1\n============================================================${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "Root privileges required."
        echo "Please run: sudo $0"
        exit 1
    fi
}

detect_vpn() {
    if ifconfig | grep -q "utun" || scutil --nc list | grep -q "Connected"; then
        VPN_ACTIVE=true
    fi
}

get_primary_interface() {
    PRIMARY_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
    GATEWAY_IP=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
    
    # Get Primary DNS Server via scutil (macOS standard resolver info)
    DNS_SERVER_IP=$(scutil --dns | grep "nameserver\[0\]" | awk '{print $3}' | head -n 1)

    if [[ -z "$PRIMARY_IF" ]]; then
        fail "No default route found (Offline?)"
        PRIMARY_IF="unknown"
    fi
}

check_dependencies() {
    header "Dependency Check"
    if command -v nmap &> /dev/null; then HAS_NMAP=true; pass "nmap found"; else warn "nmap not found"; fi
    if command -v mtr &> /dev/null; then HAS_MTR=true; pass "mtr found"; else warn "mtr not found"; fi
    if command -v dig &> /dev/null; then HAS_DIG=true; pass "dig found"; else warn "dig not found"; fi
    
    if [[ -z "$AIRPORT_CMD" ]]; then
        warn "Airport utility binary not found. Detailed signal stats will be limited."
    fi
    echo ""
}

# ==============================================================================
# Layer 2: Wi-Fi & LAN
# ==============================================================================

get_wifi_details() {
    echo -e "${CYAN}--- Detailed Wi-Fi Statistics ---${NC}"

    local wifi_dev=$(networksetup -listallhardwareports | grep -A 1 -E "Wi-Fi|WLAN" | tail -n 1 | awk '{print $2}')
    
    if [[ -z "$wifi_dev" ]]; then
        if ifconfig en0 &>/dev/null; then wifi_dev="en0"; else fail "No Wi-Fi interface found."; return; fi
    fi

    echo -e "Interface:     ${BOLD}$wifi_dev${NC}"

    # SSID Retrieval (ipconfig getsummary as primary source)
    ipconfig setverbose 1 2>/dev/null
    local ssid=$(ipconfig getsummary "$wifi_dev" 2>/dev/null | grep " SSID" | cut -d ':' -f 2 | xargs)

    if [[ -z "$ssid" ]]; then
        local ssid_raw=$(networksetup -getairportnetwork "$wifi_dev" 2>/dev/null)
        ssid=$(echo "$ssid_raw" | sed 's/^Current Wi-Fi Network: //')
    fi

    if [[ "$ssid" == *"redacted"* || -z "$ssid" ]]; then
        echo -e "SSID:          ${RED}<Unknown/Hidden>${NC}"
        warn "Could not retrieve SSID. Ensure Location Services are enabled for Terminal."
    else
        echo -e "SSID:          ${BOLD}$ssid${NC}"
    fi

    if [[ -x "$AIRPORT_CMD" ]]; then
        local wifi_info=$("$AIRPORT_CMD" -I)
        local wifi_state=$(echo "$wifi_info" | awk '/ state/ {print $2}')
        
        if [[ "$wifi_state" == "init" ]]; then
            warn "Interface is ON but disconnected."
            return
        fi

        local bssid=$(echo "$wifi_info" | awk '/ BSSID/ {print $2}')
        local rssi=$(echo "$wifi_info" | awk '/ agrCtlRSSI/ {print $2}')
        local noise=$(echo "$wifi_info" | awk '/ agrCtlNoise/ {print $2}')
        local channel=$(echo "$wifi_info" | awk '/ channel/ {print $2}')
        local mcs=$(echo "$wifi_info" | awk '/ MCS/ {print $2}')
        local rate=$(echo "$wifi_info" | awk '/ lastTxRate/ {print $2}')
        local band=""
        if [[ "$channel" -gt 14 ]]; then band=" (5GHz/6GHz)"; else band=" (2.4GHz)"; fi

        echo -e "BSSID:         $bssid"
        echo -e "Channel:       $channel$band"
        echo -e "Tx Rate:       $rate Mbps (MCS: $mcs)"
        
        if [[ $rssi -eq 0 ]]; then
            warn "Signal: 0 dBm (Invalid reading)"
        elif [[ $rssi -gt -50 ]]; then
            echo -e "Signal:        ${GREEN}$rssi dBm (Excellent)${NC}"
        elif [[ $rssi -gt -70 ]]; then
            echo -e "Signal:        ${GREEN}$rssi dBm (Good)${NC}"
        elif [[ $rssi -gt -80 ]]; then
            echo -e "Signal:        ${YELLOW}$rssi dBm (Weak)${NC}"
        else
            echo -e "Signal:        ${RED}$rssi dBm (Unusable)${NC}"
        fi
        echo -e "Noise Floor:   $noise dBm"
    else
        warn "Cannot retrieve advanced signal stats (airport binary missing)."
    fi
}

scan_lan_participants() {
    echo -e "${CYAN}--- Scanning Network Participants ---${NC}"
    if $HAS_NMAP; then
        log "Using Nmap (Ping Scan)..."
        nmap -sn -e "$PRIMARY_IF" -oG - 192.168.1.0/24 2>/dev/null | grep "Status: Up" | awk '{print "Host: " $2 " (" $3 ")"}' | sed 's/()//g'
    else
        log "Using Broadcast Ping + ARP..."
        ping -c 2 -t 2 255.255.255.255 &> /dev/null
        echo -e "\n${BOLD}ARP Table:${NC}"
        arp -a -n -i "$PRIMARY_IF" | grep -v "incomplete" | grep -v "255.255.255.255" | awk '{printf "%-18s %s\n", $2, $4}' | tr -d '()'
    fi
}

check_layer2_menu() {
    while true; do
        header "Layer 2 Check (Data Link & LAN)"
        echo "1) Check Gateway ARP"
        echo "2) Show Extended Wi-Fi Details"
        echo "3) Scan Local Network Participants"
        echo "0) Return to Main Menu"
        
        read "l2opt?Select option [1-3, 0]: "
        echo ""
        
        case $l2opt in
            1) 
                log "Checking Gateway ARP..."
                if [[ -n "$GATEWAY_IP" ]]; then
                    local gw_mac=$(arp -n "$GATEWAY_IP" | awk '{print $4}')
                    if [[ "$gw_mac" != "(incomplete)" && -n "$gw_mac" ]]; then pass "Gateway MAC: $gw_mac"; else fail "Gateway ARP failed"; fi
                else warn "No Gateway IP."; fi
                ;;
            2) get_wifi_details ;;
            3) scan_lan_participants ;;
            0) break ;;
            *) echo -e "${RED}Invalid option.${NC}" ;;
        esac
        echo -e "\n${BLUE}Press Enter to continue...${NC}"
        read -r dummy
    done
}

# ==============================================================================
# Standard Layers
# ==============================================================================

check_layer1() {
    header "Layer 1: Physical"
    log "Interface: $PRIMARY_IF"
    local link_status=$(ifconfig "$PRIMARY_IF" | grep "status:" | awk '{print $2}')
    if [[ "$link_status" == "active" ]]; then pass "Link Status: ACTIVE"; else fail "Link Status: INACTIVE"; fi
}

check_layer3() {
    header "Layer 3: Network (IP & Routing)"
    if $VPN_ACTIVE; then warn "VPN DETECTED! Ping results masked."; fi
    
    # 1. IP Check
    local ip=$(ifconfig "$PRIMARY_IF" | grep "inet " | awk '{print $2}')
    if [[ -n "$ip" ]]; then pass "IPv4: $ip"; else fail "No IPv4"; fi

    # 2. Gateway Reachability
    if [[ -n "$GATEWAY_IP" ]]; then
        if ping -c 2 -W 1000 "$GATEWAY_IP" &>/dev/null; then pass "Gateway Reachable ($GATEWAY_IP)"; else fail "Gateway UNREACHABLE"; fi
    fi

    # 3. Public IP Routing (Cloudflare) - Strictly checks Routing, NOT DNS
    if ping -c 2 -W 1000 1.1.1.1 &>/dev/null; then 
        pass "Public IP Routing (1.1.1.1) - Connectivity OK"
    else 
        fail "Public IP Routing FAILED - No Internet Connection"
    fi

    # 4. DNS Server Reachability (Layer 3 Check of Layer 7 Infrastructure)
    if [[ -n "$DNS_SERVER_IP" ]]; then
        log "Checking configured DNS Server: $DNS_SERVER_IP"
        if ping -c 2 -W 1000 "$DNS_SERVER_IP" &>/dev/null; then
            pass "DNS Server ($DNS_SERVER_IP) is Reachable (Ping)"
        else
            fail "DNS Server ($DNS_SERVER_IP) is UNREACHABLE. Check settings!"
        fi
    else
        fail "No DNS Server configuration found!"
    fi
}

check_layer4() {
    header "Layer 4: Transport"
    local fw=$(socketfilterfw --getglobalstate | awk '{print $3}')
    if [[ "$fw" == "enabled." ]]; then pass "Firewall: ENABLED"; else warn "Firewall: DISABLED"; fi
    log "Top TCP Listeners:"
    lsof -iTCP -sTCP:LISTEN -P -n | awk '{print $1, $9}' | head -n 6 | column -t
    log "Outbound Test (443):"
    if nc -z -w 2 google.com 443; then pass "HTTPS Outbound OK"; else fail "HTTPS Outbound BLOCKED"; fi
}

check_layer57() {
    header "Layer 5-7: Application (DNS Resolution)"
    
    # DNS Resolution Check
    log "Testing DNS Resolution via $DNS_SERVER_IP..."
    
    # We try to resolve using the SYSTEM default first
    if host google.com &>/dev/null; then 
        pass "DNS Resolution OK (google.com)"
    else 
        fail "DNS Resolution FAILED. Internet may be unreachable."
    fi

    # HTTP Check
    local http_code=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 3 https://www.apple.com)
    local resp_time=$(curl -o /dev/null -s -w "%{time_total}" --connect-timeout 3 https://www.apple.com)
    
    if [[ "$http_code" == "200" ]]; then 
        pass "HTTP 200 OK (Time: ${resp_time}s)"
    else 
        fail "HTTP Error: $http_code"
    fi
}

# ==============================================================================
# Main Menu
# ==============================================================================

check_root
get_primary_interface
detect_vpn
check_dependencies

while true; do
    echo -e "\n${BOLD}--- macOS Network Diagnostics SRE Tool (v2.0) ---${NC}"
    if $VPN_ACTIVE; then echo -e "${YELLOW}VPN: ACTIVE${NC}"; else echo -e "${GREEN}VPN: Inactive${NC}"; fi
    echo "1) Layer 1 Check (Physical)"
    echo "2) Layer 2 Check (Wi-Fi & LAN)"
    echo "3) Layer 3 Check (Network & DNS Reachability)"
    echo "4) Layer 4 Check (Transport)"
    echo "5) Layer 5-7 Check (Application & Resolution)"
    echo "9) Run Full Diagnostics"
    echo "0) Exit"
    
    read "opt?Select option [0-9]: "
    echo "" 

    case $opt in
        1) check_layer1 ;;
        2) check_layer2_menu ;;
        3) check_layer3 ;;
        4) check_layer4 ;;
        5) check_layer57 ;;
        9) 
            check_layer1
            get_wifi_details
            check_layer3
            check_layer4
            check_layer57
            ;;
        0) echo "Exiting."; exit 0 ;;
        *) echo -e "${RED}Invalid selection.${NC}" ;;
    esac
    
    echo -e "\n${BLUE}Press Enter to return to menu...${NC}"
    read -r dummy
done
