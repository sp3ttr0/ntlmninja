# ntlmninja

This script automates the setup and execution of an SMB relay attack using tools like Responder, Impacket’s ntlmrelayx, CrackMapExec, and tmux. It identifies misconfigured SMB signing on target machines and launches a relay attack against vulnerable hosts within a managed tmux session.

## Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:
- **tmux**
- **Responder**
- **Impacket**
- **CrackMapExec**

Install these tools as needed before using the script.

## Usage:
```bash
./ntlmninja.sh [-f TARGET_FILE] [options]
```

## Options
```
-f TARGET_FILE       (Required) File containing a list of target IP addresses to scan for misconfigured SMB signing.
-i NETWORK_INTERFACE (Optional) Network interface to use for the attack (default: eth0).
-x                   (Optional) Enable interactive shell in ntlmrelayx (--interactive).
-h                   (Optional) Displays the help message and exits.
```

## Example
```bash
# Run with target file and default interface
./ntlmninja.sh -f targets.txt

# Run with custom interface
./ntlmninja.sh -f targets.txt -i wlan0

# Run with interactive ntlmrelayx shell
./ntlmninja.sh -f targets.txt -x
```

## Important Notes

Responder Configuration:
Ensures SMB and HTTP are disabled in /etc/responder/Responder.conf to prevent conflicts with ntlmrelayx.

## Disclaimer

This tool is for educational and authorized testing purposes only. Do not use this script on networks or systems for which you do not have explicit permission. The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk. You assume full responsibility for your actions and their consequences.
