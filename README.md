# journald-summary

`logfilter.py` condenses systemd journal logs from a few Linux servers into a short report per host. It filters and deduplicates entries without calling an LLM: similar messages become one pattern with a count, a time range and an example. The aim is to make failures easy to spot.

This is stage 1 of a log analysis pipeline. A planned stage 2 (not written yet) will send the report files to a local LLM (Ollama) for analysis.

## Requirements

- Python 3 (standard library only)
- `journalctl` (systemd)
- Root access, because reading the journals requires it

Remote hosts are expected to send their journals to the central server with `systemd-journal-remote`, which stores them in `/var/log/journal/remote/`.

## Usage

```
sudo ./logfilter.py [HOST ...] [--since WINDOW] [--state-dir PATH] [--report-dir PATH]
```

| Option | Meaning |
|---|---|
| `HOST ...` | Hosts to process. Default: every host in `HOSTS`. |
| `--since WINDOW` | Preview mode. Reads a time window (`journalctl --since` syntax, e.g. `"2 hours ago"` or `yesterday`). Does not read the cursor and does not write state. |
| `--state-dir PATH` | State root directory. Default: `/var/lib/logfilter`. |
| `--report-dir PATH` | Write each report to `PATH/<host>/<YYYYmmdd-HHMMSS>.txt` instead of stdout. Not allowed with `--since`. |

Examples:

```
sudo ./logfilter.py                          # all hosts, continue from the saved cursors
sudo ./logfilter.py palvelin --since "6 hours ago"   # look at a window without changing state
sudo ./logfilter.py --report-dir /var/lib/logfilter/reports
```

If a host fails (for example, `journalctl` exits with an error), the script prints the error to stderr, continues with the other hosts and exits with status 1.

## How it works

### Modes

- **Normal mode** (no `--since`): reads entries after the cursor saved for the host. On the first run there is no cursor, so it reads `INITIAL_SINCE` (24 hours ago). After the report is produced, it saves the new cursor and the patterns it has seen.
- **Preview mode** (`--since`): reads the given window and prints the report. It does not read the cursor and writes no files. It reads the saved patterns so it can still mark new ones.

### Filtering

Each entry goes through these steps in this order:

1. **`RULES`**: if a rule matches, the entry is always selected and tagged `[rule:<name>]`. Noise and priority limits do not apply. Built-in rules cover failed units, OOM, full disks, I/O and filesystem errors, read-only remounts, kernel crashes, segfaults and core dumps, hardware errors, undervoltage and thermal events.
2. **`NOISE`**: if no rule matched and a noise pattern matches, the entry is dropped and counted as noise. This also applies to entries that match `ALWAYS_INCLUDE`.
3. **Priority**: the entry is selected if its priority is `MAX_PRIORITY` (warning) or more severe, or if it matches `ALWAYS_INCLUDE` (by default: boot messages).

### Normalization and deduplication

Selected messages are normalized: the `EXTRA_NORMALIZERS` run first, then MAC addresses, timestamps, UUIDs, IPv4/IPv6 addresses, hex values and numbers are replaced with placeholders (`<MAC>`, `<TIME>`, `<UUID>`, `<IP>`, `<HEX>`, `<N>`). Entries with the same source (systemd unit, syslog identifier or `kernel`) and the same normalized template form one pattern. IP addresses are counted per pattern.

A pattern is **new** if its key is not yet in the host's `seen.json`.

### State

State is kept in plain files under `<state-dir>/<host>/`:

- `cursor`: last processed journal cursor
- `seen.json`: pattern keys already seen, each mapped to the time it was first seen

All state and report files are written atomically. State is saved only after the report has been written, so a failed run is repeated on the next run instead of being skipped.

## Report format

Example output (synthetic data):

```
=== palvelin ===
mode: normal (first run, since 24 hours ago)
range: 2026-10-07T07:00:00+03:00 -> 2026-10-07T09:30:00+03:00
entries read: 51  (err=5 warning=4 info=42)
dropped as noise: 1
selected: 10 entries in 4 patterns (1 with rule matches, 4 new)
note: no saved patterns for this host yet, so every pattern is marked new

[rule:unit_failed] [NEW] warning systemd x1  2026-10-07T08:00:00+03:00 -> 2026-10-07T08:00:00+03:00
  pattern: backup.service: Failed with result 'exit-code'.
  example: backup.service: Failed with result 'exit-code'.
[NEW] err nginx.service x5  2026-10-07T08:06:40+03:00 -> 2026-10-07T08:26:40+03:00
  pattern: <N>/<N>/<N> <TIME> [error] <N>#<N>: *<N> upstream timed out (<N>: Connection timed out) while connecting to upstream, client: <IP>
  example: 2026/10/07 01:10:00 [error] 123#123: *900 upstream timed out (110: Connection timed out) while connecting to upstream, client: 203.0.113.5
  top IPs: 203.0.113.5 x3, 198.51.100.20 x1, 2001:db8::17 x1 (3 distinct)
[NEW] warning chronyd.service x3  2026-10-07T08:56:40+03:00 -> 2026-10-07T09:26:40+03:00
  pattern: Can't synchronise: no selectable sources
  example: Can't synchronise: no selectable sources
[NEW] info systemd x1  2026-10-07T09:30:00+03:00 -> 2026-10-07T09:30:00+03:00
  pattern: Startup finished in <N> (kernel) + <N> (userspace) = <N>.
  example: Startup finished in 3.512s (kernel) + 6.201s (userspace) = 9.713s.
report size: 1411 characters
```

Patterns are sorted so that rule matches come first, then new patterns, then by priority (most severe first) and by count (largest first). The stage 2 LLM step will parse this format, so changes to it must be made with care.

## Configuration

All settings are at the top of `logfilter.py`:

| Setting | Purpose |
|---|---|
| `REMOTE_DIR` | Directory of the journals received with `systemd-journal-remote` |
| `HOSTS` | Host name → `journalctl` arguments. Remote hosts are selected by `_HOSTNAME`, not by file name. |
| `DEFAULT_STATE_DIR` | Default for `--state-dir` |
| `INITIAL_SINCE` | Window for the first normal run of a host |
| `MAX_PRIORITY` | Least severe priority that is selected (4 = warning) |
| `RULES` | `(name, identifier or None, regex)`: always selected |
| `ALWAYS_INCLUDE` | `(identifier or None, regex)`: selected regardless of priority |
| `NOISE` | `(identifier or None, regex)`: dropped unless a rule matches |
| `EXTRA_NORMALIZERS` | `(regex, replacement)`: applied before the built-in normalization |

The identifier is matched against `SYSLOG_IDENTIFIER` (or `_COMM` if that is missing). Regexes are matched against `MESSAGE` with `re.search`.

## Installation (daily systemd timer)

```
sudo install -m 755 logfilter.py /usr/local/bin/logfilter.py
sudo cp systemd/logfilter.service systemd/logfilter.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now logfilter.timer
```

The service runs once a day and writes reports to `/var/lib/logfilter/reports/<host>/`. It runs with `ProtectSystem=strict`, so a state or report directory outside `/var/lib/logfilter` needs a `ReadWritePaths=` entry in the unit.

To run it immediately and check the result:

```
sudo systemctl start logfilter.service
journalctl -u logfilter.service
```

## Testing

Do not test against real journals or the real state directory. Use a fake `journalctl` that prints synthetic JSON entries, and temporary state and report directories:

```
mkdir -p /tmp/lf/bin
cat > /tmp/lf/bin/journalctl <<'EOF'
#!/bin/sh
echo '{"__CURSOR":"s=x;i=1","__REALTIME_TIMESTAMP":"1791345600000000","PRIORITY":"3","MESSAGE":"Connection from 192.0.2.1 failed","SYSLOG_IDENTIFIER":"demo","_TRANSPORT":"journal","_HOSTNAME":"palvelin"}'
EOF
chmod +x /tmp/lf/bin/journalctl
PATH=/tmp/lf/bin:$PATH python3 logfilter.py palvelin --state-dir /tmp/lf/state
```

Use only documentation address ranges in test data (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).

Syntax check:

```
python3 -m py_compile logfilter.py
```

## License

MIT. See [LICENSE](LICENSE).
