# ntlmninja

Checks SMB signing with NetExec and manages Responder and ntlmrelayx in tmux. Includes a scan-only mode.

## Dependencies

- Bash and standard shell utilities
- NetExec (`nxc`)
- Python 3
- Full workflow: `tmux`, `responder`, `impacket-ntlmrelayx`, and `ip`

Full runs, session management, and configuration restoration require root. Scan-only mode does not.

## Usage

```bash
# Scan only
./ntlmninja.sh -s -f targets.txt

# Full workflow (automatically detects the Responder interface)
sudo ./ntlmninja.sh -f targets.txt

# Specify the Responder interface and enable interactive mode
sudo ./ntlmninja.sh -f targets.txt -i eth0 -x
```

Targets: one IPv4/IPv6 address or canonical CIDR per line (e.g. `192.0.2.0/24`). Blank lines and `#` comments are allowed; duplicates are removed. Hostnames and empty target lists are rejected.

## Options

| Option | Purpose |
| --- | --- |
| `-f FILE` | Target file, required for scans |
| `-s` | Scan only |
| `-i INTERFACE` | Responder interface; default: auto |
| `-x` | Interactive ntlmrelayx mode |
| `-o DIR` | Output directory; default: `./ntlmninja-runs` |
| `-a` | Attach to the existing session |
| `-k` | Stop the existing session |
| `-r FILE` | Restore a Responder configuration backup |
| `-C` | Disable colors |
| `-h` | Show help |

Use `-a`, `-k`, or `-r` separately from scan options. Scan-only mode cannot use `-i` or `-x`.

## Important notes

- Each run saves fresh results, logs, and status in a unique output folder. Signing not required is a finding, not proof of exploitability.
- Full runs back up `/etc/responder/Responder.conf` before disabling SMB and HTTP. Scan-only mode leaves it unchanged.
- Detaching or exiting leaves session processes running. Stop them with `sudo ./ntlmninja.sh -k`, then restore configuration explicitly:

```bash
sudo ./ntlmninja.sh -r /path/to/run.XXXXXXXX/Responder.conf.backup
```

Restoration replaces the entire configuration with the selected backup. Review logs for failures; session startup does not confirm service health.

## Offline checks

```bash
bash -n ntlmninja.sh
python3 tests/test_workflow.py
```

Use only on systems you have explicit permission to assess.
