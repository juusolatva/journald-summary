# journald-summary

[![CI](https://github.com/juusolatva/journald-summary/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/juusolatva/journald-summary/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=juusolatva_journald-summary&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=juusolatva_journald-summary)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=juusolatva_journald-summary&metric=coverage)](https://sonarcloud.io/summary/new_code?id=juusolatva_journald-summary)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/github/license/juusolatva/journald-summary)](LICENSE)

`logfilter.py` condenses systemd journal logs from a few Linux servers into a short report per host. It filters and deduplicates entries without calling an LLM: similar messages become one pattern with a count, a time range and an example. The aim is to make failures easy to spot.

The goal is to spot software and hardware problems (failed units, crashes, disk, memory, filesystem, thermal and power issues, misconfiguration). Security monitoring (intrusion detection, auditing, login attempts, scanning) is out of scope; dedicated tools such as auditd cover it.

This is stage 1 of a log analysis pipeline. Stage 2, `analyze.py`, sends the report files to a local LLM (Ollama) for analysis; see [Analysis (stage 2)](#analysis-stage-2).

## Requirements

- Python 3.10 or newer (standard library only)
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

Selected messages are normalized: the `EXTRA_NORMALIZERS` run first (for example, the defaults replace Docker veth interface names with `veth<ID>` and libata register dumps with `<REGS>`, and drop coredump stack traces), then IPv4/IPv6 addresses, MAC addresses, timestamps, UUIDs, hex values and numbers are replaced with placeholders (`<IP>`, `<MAC>`, `<TIME>`, `<UUID>`, `<HEX>`, `<N>`). Entries with the same source (systemd unit, syslog identifier or `kernel`) and the same normalized template form one pattern. IP addresses are counted per pattern.

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

Patterns are sorted so that rule matches come first, then new patterns, then by priority (most severe first) and by count (largest first). The stage 2 analysis (`analyze.py`) reads this format, so changes to it must be made with care.

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

## Analysis (stage 2)

`analyze.py` reads the reports written with `--report-dir`, sends each one to an Ollama model and writes the result next to the report as `<host>/<YYYYmmdd-HHMMSS>.analysis.txt`. A report counts as analyzed once that file exists, so a report whose analysis failed is tried again on the next run. Python 3.10 or newer, standard library only.

```
sudo ./analyze.py [HOST ...] [--report-dir PATH] [--url URL] [--model MODEL] [--known-issues PATH]
```

| Option | Meaning |
|---|---|
| `HOST ...` | Hosts to process. Default: every directory in the report directory. |
| `--report-dir PATH` | Report directory. Default: `/var/lib/logfilter/reports`. |
| `--url URL` | Ollama server, an `http://` or `https://` URL with a host (anything else exits with status 2). Default: `http://localhost:11434`. |
| `--model MODEL` | Ollama model. Default: `qwen3:4b-instruct-2507-q8_0`. |
| `--known-issues PATH` | Known issues file. Default: `/etc/logfilter/known-issues.txt`. |

How it works:

- Reports are processed oldest first. A report with no selected patterns gets its analysis file without calling the model.
- A report that fits in `CHUNK_CHARS` is sent in one request. A larger one is split between pattern blocks, each chunk repeating the report header, and a final request merges the chunk results into one analysis.
- Requests go to `/api/chat` with a JSON schema as `format`, temperature 0 and `num_ctx` set to `NUM_CTX`. A reply is accepted only if it matches the schema, generation was not cut short and the context window was not full.
- Each request is tried up to three times (`RETRY_DELAYS`). If Ollama cannot be reached, the run stops and leaves the remaining reports for the next run. If the replies for one report stay invalid, that report is skipped and the others continue. In both cases the exit status is 1.
- The known issues file has one issue per line (empty lines and lines starting with `#` are ignored), for example `palvelin: ata1 SATA link errors (SSD port, cable being checked)`. The model marks matching issues as known instead of leaving them out. A missing file means no known issues.

Example analysis (synthetic data):

```
=== palvelin 20261007-000000 ===
model: qwen3:4b-instruct-2507-q8_0
chunks: 1
summary: One unit failed; nginx could not reach its upstream for 20 minutes.

[high] backup.service failed
  backup.service failed once at 08:00 with result 'exit-code'.
[medium] nginx upstream timeouts
  Five upstream timeouts between 08:06 and 08:26, likely an unresponsive backend.
[low] [known] Clock not synchronised
  chronyd had no selectable sources three times.
```

Issues are sorted with unknown issues first, then by severity (`critical`, `high`, `medium`, `low`).

Settings at the top of `analyze.py`:

| Setting | Purpose |
|---|---|
| `DEFAULT_REPORT_DIR`, `DEFAULT_URL`, `DEFAULT_MODEL` | Defaults for `--report-dir`, `--url`, `--model` |
| `NUM_CTX` | Context window requested from Ollama, in tokens |
| `CHUNK_CHARS` | Maximum report characters per request |
| `KNOWN_ISSUES` | Default for `--known-issues` |
| `REQUEST_TIMEOUT` | Seconds to wait for one reply |
| `RETRY_DELAYS` | Waits between attempts of one request |
| `SYSTEM_PROMPT`, `MERGE_PROMPT`, `SCHEMA` | Prompts and the reply schema |

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

To add the analysis (on the machine that runs Ollama):

```
sudo install -m 755 analyze.py /usr/local/bin/analyze.py
sudo cp systemd/analyze.service /etc/systemd/system/
sudo systemctl daemon-reload
```

`logfilter.service` pulls in `analyze.service` (`Wants=`), which starts after logfilter has finished, also when one host failed. If the analysis fails, systemd restarts it every 30 minutes until all reports are analyzed. The service may only connect to localhost (`IPAddressAllow=localhost`). The first run analyzes every existing report that has no analysis file yet.

## Testing

The automated tests in `tests/` use only the standard library (`unittest`), synthetic data, a fake `journalctl` and a fake Ollama server on `127.0.0.1`. They do not need root and do not touch real journals or `/var/lib/logfilter`. Run them from the repository root:

```
python3 -m unittest discover -s tests -v
```

The tests also run under pytest (settings in `pytest.ini` and `pyproject.toml`). The development tools (pytest, pytest-cov, ruff) are listed in `requirements-dev.txt` and pinned with hashes in `requirements-dev.lock`. Install them (for example in a virtual environment) and run the same checks as CI:

```
python3 -m pip install --require-hashes --only-binary :all: -r requirements-dev.lock
python3 -m pytest --cov
ruff check
ruff format --check
```

Code follows the `ruff format` layout (line length 120, settings in `pyproject.toml`). After changing `requirements-dev.txt`, regenerate the lock with the command below. `--upgrade` also updates the indirect dependencies, which Dependabot does not see, and `--exclude-newer "7 days"` matches the Dependabot cooldown:

```
uv pip compile --universal --generate-hashes --no-header --python-version 3.10 --upgrade --exclude-newer "7 days" requirements-dev.txt -o requirements-dev.lock
```

CI (`.github/workflows/ci.yml`) runs `ruff check` and `ruff format --check`, checks that `requirements-dev.lock` satisfies `requirements-dev.txt`, runs the tests with coverage on Python 3.10 to 3.14, and runs a SonarQube Cloud scan. Dependabot (`.github/dependabot.yml`) opens weekly update PRs, one for the actions and one for `requirements-dev.txt`. It cannot update `requirements-dev.lock`, so regenerate the lock with the command above on its pip PRs before merging; the test jobs fail until then.

For manual testing:

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

To test `analyze.py` without a real model, run a small fake Ollama server (`http.server`) that answers `POST /api/chat` with a JSON reply whose `message.content` matches the schema, point `--url` at it and use a temporary report directory with synthetic reports.

Syntax check:

```
python3 -m py_compile logfilter.py analyze.py
```

## License

MIT. See [LICENSE](LICENSE).
