# ntlmninja

This script automates the setup and execution of an SMB relay attack using tools like responder, impacket-ntlmrelayx, crackmapexec, and tmux. It streamlines the process of identifying misconfigured SMB signing on target machines and launching a relay attack against vulnerable hosts.

## Prerequisites

Ensure the following tools are installed:
- tmux
- responder
- impacket
- crackmapexec

Install them if they are not available in your environment.

## Usage:
```bash
./smb_relay_attack.sh [-f TARGET_FILE] [-h]
```

## Options
```
-f TARGET_FILE: Specifies the file containing a list of target IP addresses to scan for misconfigured SMB signing.
-h: Displays this help message and exits.
```

## Example
```bash
./smb_relay_attack.sh -f targets.txt
```

## Important Notes
- The script is configured to run responder on the eth0 interface by default. Modify this setting in the script if a different network interface is needed.
- Use responsibly and only on networks and devices you have explicit permission to test.

## Disclaimer
This tool is for educational and authorized testing purposes only. Unauthorized use of this tool may violate the law. The authors are not liable for any misuse or damage caused by this script.
