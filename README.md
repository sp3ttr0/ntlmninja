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
-f TARGET_FILE: Specifies the file containing a list of target IP addresses to scan for misconfigured SMB signing.
-i INTERFACE: Specifies the network interface to use for the attack (default: eth0).
-x Enable the --interactive shell mode in ntlmrelayx.
-h: Displays the help message and exits.
```

## Example
```bash
./ntlmninja.sh -f targets.txt -i eth0 -x
```

## Important Notes

Responder Configuration:
If Responder’s config (/etc/responder/Responder.conf) has SMB or HTTP enabled, the script will automatically disable them to prevent conflicts with ntlmrelayx.

## Disclaimer

This tool is for educational and authorized testing only. Do not use this script on networks or systems for which you do not have explicit permission. The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk. You assume full responsibility for your actions and their consequences.
