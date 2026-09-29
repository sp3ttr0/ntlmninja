# ntlmninja

This script automates the setup and execution of an SMB relay attack using tools like Responder, Impacket’s ntlmrelayx, NetExec, and tmux. It identifies misconfigured SMB signing on target machines and launches a relay attack against vulnerable hosts within a managed tmux session.

## Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:

- **tmux**
- **Responder** (`responder`)
- **Impacket** (`impacket-ntlmrelayx`)
- **NetExec** (`nxc`)
- **ip** (used to detect and validate the network interface)
- **Python 3** (standard library only, used to validate target addresses)

Install these tools as needed before using the script. The full workflow, session management, and configuration restoration require root privileges. Scan-only mode needs NetExec, Python 3, and standard shell utilities; it does not require Responder, Impacket, tmux, or root. Session management checks tmux independently of scanning dependencies.

## Usage

```bash
sudo ./ntlmninja.sh -f TARGET_FILE [options]
```

## Options

```text
-f TARGET_FILE        Required for scans: one IP address or canonical CIDR per line.
-i NETWORK_INTERFACE (Optional) Network interface to use for the attack (default: automatically detected from the default route).
-x                   (Optional) Enable interactive shell in ntlmrelayx (--interactive).
-h                   (Optional) Displays the help message and exits.
-s                   Scan only; do not modify configuration or start services.
-o OUTPUT_DIR        Parent directory for fresh runs (default: ./ntlmninja-runs).
-r BACKUP_FILE       Restore Responder configuration from a saved backup and exit.
-a                   Attach to the existing session and exit after attachment ends.
-k                   Stop the existing session and exit; configuration is not restored.
-C                   Disable wrapper colors; NO_COLOR and redirected output do this too.
```

Use `-a`, `-k`, and `-r` separately from scan options and from each other. Scan-only mode rejects `-i` because NetExec selects its own routing, and rejects `-x` because no session is launched. The full workflow's `-i` selects the Responder interface, not the scanner's interface.

Target files support IPv4, IPv6, canonical CIDR networks, blank lines, UTF-8 BOMs, CRLF line endings, and `#` comments. Duplicates are removed. Hostnames, address ranges, scoped IPv6 addresses, malformed addresses, and CIDRs with host bits set are rejected before scanning. An empty or comment-only file is an error. For example, `192.0.2.0/24` is accepted, while `192.0.2.1/24` is rejected rather than silently expanding it to a network.

## Example

```bash
# Scan only and review the findings
./ntlmninja.sh -s -f targets.txt

# Put a fresh run under a custom output directory
./ntlmninja.sh -s -f targets.txt -o './assessment reports'

# Run with target file and automatically detected interface
sudo ./ntlmninja.sh -f targets.txt

# Run with custom interface
sudo ./ntlmninja.sh -f targets.txt -i wlan0

# Run with interactive ntlmrelayx shell
sudo ./ntlmninja.sh -f targets.txt -x

# Manage a session without a target file or another scan
sudo ./ntlmninja.sh -a
sudo ./ntlmninja.sh -k
```

## Important Notes

Responder Configuration:
Ensures SMB and HTTP are disabled in `/etc/responder/Responder.conf` to prevent conflicts with ntlmrelayx.

Each new scan creates a private, unique run directory containing:

- `input-targets.txt`: the original input snapshot.
- `targets.txt`: validated, normalized, deduplicated scan inputs.
- `vulnerable_smb_targets.txt`: the candidate list; the legacy filename does not imply proven exploitability.
- `attack.log`: raw NetExec output for diagnostics.
- `events.log`: wrapper events with UTC timestamps, separate from scanner output.
- `status`: `running` while active; `scan-complete`, `attachment-ended`, or `failed` plus an exit code when the wrapper ends normally or handles a signal.

Session logs are also written there. Failed scans retain partial output for diagnosis; a nonzero exit means the results must not be treated as a successful run. Abrupt termination such as SIGKILL can leave a stale `running` status. Status records the wrapper's outcome, not ongoing service health. An empty candidate list is not proof that every host was assessed successfully. A finding means signing was reported as not required, not that an attack will succeed.

Before configuration changes, the full workflow saves and verifies `Responder.conf.backup` in that run directory. It requires exactly one active SMB setting and one active HTTP setting, stages the edits, and verifies the replacement. Symlinked configuration files are rejected. To restore a backup after stopping the running services:

```bash
sudo ./ntlmninja.sh -r /absolute/path/to/run.XXXXXXXX/Responder.conf.backup
```

Restoration replaces the configuration contents with the selected backup, including any settings changed since that backup. It is explicit, not automatic on tmux detach. Scan-only mode does not create a configuration backup because it never changes the configuration. A later full run performs a new scan rather than reusing a scan-only candidate list.

Scanner and scan-log pipeline failures stop the workflow. tmux command failures are also checked, but successful tmux dispatch does not prove the launched services are healthy. Detaching leaves the session running; a partial session startup can leave an already-started process running. Review the session and its logs before restoring configuration.

Existing-session prompts require an interactive terminal. For scripted use, choose `-a` or `-k` explicitly. `-k` stops the fixed `smb_relay_attack` session; it does not restart it. Exiting, interruption, and detaching do not automatically stop the session or restore configuration.

## Offline checks

From this directory:

```bash
bash -n ntlmninja.sh
python3 tests/test_workflow.py
# Optional, when ShellCheck is installed:
shellcheck ntlmninja.sh
```

The tests mock network and service commands and use temporary configuration files. They cover failure propagation, fresh outputs, input normalization and rejection, configuration backup/restore, route parsing, session actions, and run status. They do not validate live NetExec results or service health.

## Disclaimer

This tool is for educational and authorized testing purposes only. Do not use this script on networks or systems for which you do not have explicit permission. The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk. You assume full responsibility for your actions and their consequences.
