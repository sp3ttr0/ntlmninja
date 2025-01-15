# ntlmninja

This script automates the setup and execution of an SMB relay attack using tools like Responder, Impacket's ntlmrelayx, CrackMapExec, and tmux. It identifies misconfigured SMB signing on target machines and launches a relay attack against vulnerable hosts.

## Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:
tmux
Responder
Impacket
CrackMapExec

Install these tools as needed before using the script.

## Usage:
```bash
./ntlmninja.sh [-f TARGET_FILE] [-i NETWORK_INTERFACE] [-h]
```

## Options
```
-f TARGET_FILE: Specifies the file containing a list of target IP addresses to scan for misconfigured SMB signing.
-i NETWORK_INTERFACE: Specifies the network interface to use for the attack (default: eth0).
-h: Displays the help message and exits.
```

## Example
```bash
./ntlmninja.sh -f targets.txt
```

## Important Notes

Responder Configuration:
The script automatically updates the Responder.conf file to disable SMB and HTTP if not already configured.

Logging:
The script provides color-coded output for better readability and logs misconfigured targets during the scanning phase.

Output File:
Identified vulnerable SMB targets are stored in vulnerable_smb_targets.txt.

Network Interface:
The default network interface is eth0, but it can be configured using the -i option to suit different environments.

## Disclaimer
This tool is for educational and authorized testing purposes only. Unauthorized use of this tool may violate the law. The authors are not liable for any misuse or damage caused by this script.
