"""Offline checks with mocked scanners and temporary configuration files."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ntlmninja.sh'


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'])
        self.targets = self.root / 'input targets.txt'
        self.targets.write_text('192.0.2.1\n')
        self.reports = self.root / 'run reports'
        self.mock('nxc', '''while [ "$#" -gt 0 ]; do
if [ "$1" = --gen-relay-list ]; then shift; printf '192.0.2.1\\n' > "$1"; fi
shift
done
exit "${SCAN_EXIT:-0}"
''')
        for command in ('tmux', 'responder', 'impacket-ntlmrelayx', 'ip'):
            self.mock(command, 'echo "Unexpected service invocation" >&2; exit 99\n')
        self.mock('tmux', 'if [ "$1" = has-session ]; then exit 1; fi; exit 99\n')

    def mock(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + body)
        path.chmod(0o755)

    def run_scan(self, **env):
        return subprocess.run(['bash', str(SCRIPT), '-s', '-f', str(self.targets),
                               '-o', str(self.reports)], env=dict(self.env, **env),
                              capture_output=True, text=True)

    def config_call(self, action, contents):
        config = self.root / 'Responder.conf'
        config.write_text(contents)
        config.chmod(0o640)
        run = self.root / 'config-run'
        run.mkdir(exist_ok=True)
        result = subprocess.run([
            'bash', '-c', 'source "$1"; RESPONDER_CONFIG_FILE="$2"; RUN_DIR="$3"; ' + action,
            'test', str(SCRIPT), str(config), str(run)], env=self.env,
            capture_output=True, text=True)
        return result, config, run

    def test_fresh_runs_and_scan_only(self):
        for _ in range(2):
            result = self.run_scan()
            self.assertEqual(result.returncode, 0, result.stderr)
        runs = list(self.reports.iterdir())
        self.assertEqual(len(runs), 2)
        for run in runs:
            self.assertEqual((run / 'input-targets.txt').read_text(), self.targets.read_text())
            self.assertTrue((run / 'attack.log').exists())
            self.assertFalse((run / 'Responder.conf.backup').exists())
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)

    def test_scanner_failure(self):
        result = self.run_scan(SCAN_EXIT='7')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Scan-only run finished', result.stdout)

    def test_logging_failure(self):
        self.mock('tee', 'cat >/dev/null; exit 8\n')
        self.assertNotEqual(self.run_scan().returncode, 0)

    def test_no_stale_candidates(self):
        self.assertEqual(self.run_scan().returncode, 0)
        self.mock('nxc', 'exit 0\n')
        self.assertEqual(self.run_scan().returncode, 0)
        outputs = [p.read_text() for p in self.reports.glob('*/vulnerable_smb_targets.txt')]
        self.assertCountEqual(outputs, ['192.0.2.1\n', ''])

    def test_backup_edit_and_restore(self):
        original = '[Responder Core]\nSMB = On\nHTTP = On\nOther = Keep\n'
        result, config, run = self.config_call('edit_responder_conf', original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((run / 'Responder.conf.backup').read_text(), original)
        self.assertEqual(config.read_text(), original.replace('= On', '= Off'))
        self.assertEqual(config.stat().st_mode & 0o777, 0o640)
        restored = subprocess.run(['bash', '-c',
            'source "$1"; trap finish_run EXIT; RESPONDER_CONFIG_FILE="$2"; RESTORE_BACKUP="$3"; restore_config',
            'test', str(SCRIPT), str(config), str(run / 'Responder.conf.backup')],
            env=self.env, capture_output=True, text=True)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(config.read_text(), original)

    def test_missing_or_duplicate_keys_leave_config_unchanged(self):
        for original in ('SMB = On\n', 'SMB = On\nSMB = Off\nHTTP = On\n'):
            result, config, _ = self.config_call('edit_responder_conf', original)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(config.read_text(), original)

    def test_failed_backup_leaves_config_unchanged(self):
        self.mock('cp', 'exit 1\n')
        original = 'SMB = On\nHTTP = On\n'
        result, config, _ = self.config_call('edit_responder_conf', original)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_text(), original)

    def test_failed_replace_leaves_config_unchanged(self):
        self.mock('mv', 'exit 1\n')
        original = 'SMB = On\nHTTP = On\n'
        result, config, _ = self.config_call('edit_responder_conf', original)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_text(), original)

    def test_normalized_scope_and_plain_output(self):
        self.targets.write_bytes(b'\xef\xbb\xbf# scope\r\n192.0.2.1 # note\r\n192.0.2.1\n2001:db8::1\n192.0.2.0/24\n')
        result = self.run_scan(NO_COLOR='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('\x1b', result.stdout)
        run = next(self.reports.iterdir())
        self.assertEqual((run / 'targets.txt').read_text(), '192.0.2.1\n2001:db8::1\n192.0.2.0/24\n')
        self.assertIn('status=scan-complete', (run / 'status').read_text())
        self.assertRegex((run / 'events.log').read_text(), r'\[\d{4}-\d\d-\d\dT')
        self.assertNotIn('vulnerable target', result.stdout)

    def test_invalid_scope_never_scans(self):
        marker = self.root / 'scanner-called'
        self.mock('nxc', 'touch "' + str(marker) + '"\n')
        for contents in ('', '# comments only\n', '999.1.1.1\n', 'host.example\n',
                         '192.0.2.1/24\n', '192.0.2.1 192.0.2.2\n', 'fe80::1%eth0\n'):
            with self.subTest(contents=contents):
                self.targets.write_text(contents)
                self.assertNotEqual(self.run_scan().returncode, 0)
                self.assertFalse(marker.exists())

    def test_argument_errors(self):
        for args in (['-f'], ['-z'], ['-s', '-x'], ['-s', '-i', 'eth0'],
                     ['-a', '-k'], ['-r', 'backup', '-o', 'output'],
                     ['-i', ''], ['-o', ''], ['unexpected']):
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(SCRIPT), *args], env=self.env,
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    def test_failure_status(self):
        self.assertNotEqual(self.run_scan(SCAN_EXIT='7').returncode, 0)
        run = next(self.reports.iterdir())
        self.assertIn('status=failed', (run / 'status').read_text())

    def test_route_formats(self):
        for route, interface in (('default via 192.0.2.1 dev eth0 proto dhcp', 'eth0'),
                                 ('default dev tun0 scope link', 'tun0')):
            self.mock('ip', "printf '%s\\n' '" + route + "'\n")
            result = subprocess.run(['bash', '-c', 'source "$1"; detect_network_interface',
                                     'test', str(SCRIPT)], env=self.env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), interface)
        self.mock('ip', 'exit 2\n')
        result = subprocess.run(['bash', '-c', 'source "$1"; detect_network_interface',
                                 'test', str(SCRIPT)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_session_actions_do_not_scan(self):
        marker = self.root / 'scanner-called'
        self.mock('nxc', 'touch "' + str(marker) + '"\n')
        self.mock('tmux', 'printf "tmux:%s\\n" "$1"\n')
        for flag, expected in (('-a', 'attach-session'), ('-k', 'kill-session')):
            # Override the privilege check only in this sourced, mocked test.
            result = subprocess.run(['bash', '-c',
                'source "$1"; RESPONDER_CONFIG_FILE="$3"; validate_privileges() { :; }; main "$2"',
                'test', str(SCRIPT), flag, str(self.root / 'Responder.conf')], env=self.env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('tmux:' + expected, result.stdout)
            self.assertFalse(marker.exists())

    def test_missing_dependency_is_identified(self):
        result = subprocess.run(['bash', '-c',
            'source "$1"; command() { if [ "$2" = nxc ]; then return 1; fi; builtin command "$@"; }; '
            'main -s -f "$2" -o "$3"', 'test', str(SCRIPT), str(self.targets), str(self.reports)],
            env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nxc is not installed', result.stdout + result.stderr)
        self.assertFalse(self.reports.exists())

    def restore(self, config, run):
        return subprocess.run(['bash', '-c',
            'source "$1"; trap finish_run EXIT; RESPONDER_CONFIG_FILE="$2"; '
            'RESTORE_BACKUP="$3"; restore_config', 'test', str(SCRIPT), str(config),
            str(run / 'Responder.conf.backup')], env=self.env, capture_output=True, text=True)

    def test_restore_refuses_later_edits(self):
        result, config, run = self.config_call('edit_responder_conf', 'SMB = On\nHTTP = On\n')
        self.assertEqual(result.returncode, 0)
        changed = config.read_text() + 'Other = new\n'
        config.write_text(changed)
        result = self.restore(config, run)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restoration cancelled', result.stderr)
        self.assertEqual(config.read_text(), changed)
        self.assertFalse(Path(str(config) + '.ntlmninja.lock').exists())

    def test_restore_refuses_missing_snapshot_and_active_session(self):
        _, config, run = self.config_call('edit_responder_conf', 'SMB = On\nHTTP = On\n')
        changed = config.read_text()
        self.mock('tmux', 'exit 0\n')
        result = self.restore(config, run)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Stop the existing session', result.stderr)
        self.mock('tmux', 'exit 1\n')
        (run / 'Responder.conf.updated').unlink()
        self.assertNotEqual(self.restore(config, run).returncode, 0)
        self.assertEqual(config.read_text(), changed)

    def test_restore_is_idempotent(self):
        original = 'SMB = On\nHTTP = On\n'
        _, config, run = self.config_call('edit_responder_conf', original)
        self.assertEqual(self.restore(config, run).returncode, 0)
        result = self.restore(config, run)
        self.assertEqual(result.returncode, 0)
        self.assertIn('already matches', result.stdout)
        self.assertEqual(config.read_text(), original)

    def test_side_by_side_layout_uses_returned_pane_ids(self):
        commands = self.root / 'tmux-commands'
        self.env['TMUX_COMMAND_LOG'] = str(commands)
        self.mock('tmux', '''printf '%s\\n' "$*" >> "$TMUX_COMMAND_LOG"
case "$1" in
    new-session) printf '%%41\\n' ;;
    split-window) printf '%%58\\n' ;;
esac
''')
        result = subprocess.run(['bash', '-c',
            'source "$1"; RUN_DIR="$2"; prepare_tmux_layout',
            'test', str(SCRIPT), str(self.root)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = commands.read_text()
        self.assertIn('split-window -h -t %41', calls)
        self.assertIn('select-layout -t %41 even-horizontal', calls)
        self.assertIn('select-pane -t %41 -T Responder', calls)
        self.assertIn('select-pane -t %58 -T ntlmrelayx', calls)
        self.assertNotIn('send-keys', calls)

    def test_split_failure_stops_layout_setup(self):
        self.mock('tmux', '''case "$1" in
    new-session) printf '%%41\\n' ;;
    split-window) exit 1 ;;
    *) echo 'unexpected later command' >&2; exit 99 ;;
esac
''')
        result = subprocess.run(['bash', '-c',
            'source "$1"; RUN_DIR="$2"; prepare_tmux_layout',
            'test', str(SCRIPT), str(self.root)], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected later command', result.stderr)

    def test_concurrent_lock_and_release(self):
        config = self.root / 'Responder.conf'
        holder = subprocess.Popen(['bash', '-c',
            'source "$1"; RESPONDER_CONFIG_FILE="$2"; trap finish_run EXIT; '
            'trap "exit 143" TERM; acquire_lock; echo ready; read -r reply',
            'test', str(SCRIPT), str(config)], env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), 'ready')
            result = subprocess.run(['bash', '-c',
                'source "$1"; RESPONDER_CONFIG_FILE="$2"; trap finish_run EXIT; acquire_lock',
                'test', str(SCRIPT), str(config)], env=self.env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Cannot acquire lock', result.stderr)
            self.assertTrue(Path(str(config) + '.ntlmninja.lock/pid').exists())
        finally:
            holder.communicate('done\n', timeout=5)
        self.assertEqual(holder.returncode, 0)
        self.assertFalse(Path(str(config) + '.ntlmninja.lock').exists())
        result = subprocess.run(['bash', '-c',
            'source "$1"; RESPONDER_CONFIG_FILE="$2"; trap finish_run EXIT; acquire_lock; exit 7',
            'test', str(SCRIPT), str(config)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(Path(str(config) + '.ntlmninja.lock').exists())


if __name__ == '__main__':
    unittest.main()
