# ntlmninja

This script automates the setup and execution of an SMB relay attack using tools like Responder, Impacket's ntlmrelayx, CrackMapExec, and tmux. It identifies misconfigured SMB signing on target machines and launches a relay attack against vulnerable hosts.

## Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:
- **tmux**
- **Responder**
- **Impacket**
- **CrackMapExec**

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
The script provides color-coded output for better readability and logs misconfigured targets during scanning.

Output File:
Identified vulnerable SMB targets are stored in vulnerable_smb_targets.txt.

Network Interface:
The default network interface is eth0, but it can be configured using the -i option to suit different environments.

Use Responsibly:
This script is intended solely for authorized testing and research purposes. Always ensure you have explicit permission to perform penetration testing or security assessments on the target network.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. Unauthorized use may violate laws and regulations. The authors of this script are not responsible for any misuse or damage caused by this tool. Using this script, you agree to take full responsibility for your actions and their consequences.
