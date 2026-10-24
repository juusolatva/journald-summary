# AGENTS.md

## Project

`logfilter.py` is stage 1 of a small log analysis pipeline for a handful of Linux servers. It reads systemd journal entries per host, filters and deduplicates them deterministically, and produces a condensed report per host (stdout, or one file per host per run with `--report-dir`). It does not call any LLM. It runs daily via `systemd/logfilter.service` and `systemd/logfilter.timer`.

The goal is to spot software and hardware problems (failed units, crashes, disk, memory, filesystem, thermal and power issues, misconfiguration). Security monitoring (intrusion detection, auditing, login attempts, scanning) is out of scope; dedicated tools such as auditd cover it. Do not add rules, patterns or report fields aimed at security.

Stage 2, `analyze.py`, reads the report files and sends them, in chunks when needed, to a local LLM (Ollama native HTTP API, `http://localhost:11434` by default), retrying until analysis succeeds. It writes `<report-dir>/<host>/<YYYYmmdd-HHMMSS>.analysis.txt` next to each report; a report counts as analyzed when that file exists. It runs via `systemd/analyze.service`, which `logfilter.service` pulls in. All LLM and HTTP code belongs in `analyze.py`; `logfilter.py` never calls an LLM or the network.

## CLI

`logfilter.py`:

- `hosts`: optional positional host names (default: all hosts in `HOSTS`).
- `--since <window>`: preview mode for a time window using `journalctl --since` syntax.
- `--state-dir <path>`: state storage root directory (default: `/var/lib/logfilter`).
- `--report-dir <path>`: write each host's report to `<report-dir>/<host>/<YYYYmmdd-HHMMSS>.txt` instead of stdout. Not allowed with `--since`.

`analyze.py`:

- `hosts`: optional positional host names (default: every subdirectory of the report directory). A host without a report directory is an error (exit status 2).
- `--report-dir <path>`: report directory (default: `/var/lib/logfilter/reports`).
- `--url <url>`: Ollama server URL (default: `http://localhost:11434`). Must be an `http://` or `https://` URL with a host; anything else is an error (exit status 2).
- `--model <name>`: Ollama model (default: `qwen3:4b-instruct-2507-q8_0`).
- `--known-issues <path>`: known issues file, one issue per line, empty lines and `#` lines ignored (default: `/etc/logfilter/known-issues.txt`).

## Environment

- Runs on `palvelin` (openSUSE Tumbleweed), the central server.
- Hosts and where their logs are:
  - `palvelin`: local journal.
  - `vakoilu` (Debian stable VPS) and `seuranta` (DietPi, Raspberry Pi 4): received with `systemd-journal-remote` into `/var/log/journal/remote/`, selected by `_HOSTNAME=<name>`.
- File names in `/var/log/journal/remote/` contain `CN=` (for example `remote-CN=vakoilu.journal`). Never select hosts by file name; always use the `_HOSTNAME` field.
- Reading the journals requires root. The script is run with `sudo`.

## Hard constraints

- Python 3.10 or newer, standard library only, for `logfilter.py`, `analyze.py` and the tests (`requirements.txt` lists no runtime dependencies). No third-party packages, no `python-systemd`, no other languages. The only exception is development and CI tooling (`pytest`, `pytest-cov`, `ruff`) in `requirements-dev.txt`, pinned with hashes in `requirements-dev.lock`; never import it from the scripts or tests.
- Read the journal only through `journalctl --output=json` via `subprocess`. Never parse `journalctl` text output: it is locale-dependent (palvelin prints Finnish month names such as `loka` and `syys`).
- No databases. State is plain files in `<state-dir>/<host>/` (default `/var/lib/logfilter/<host>/`):
  - `cursor`: last processed journal cursor string.
  - `seen.json`: pattern keys already seen, mapped to first-seen ISO timestamp string.
- State and report files are written atomically (temporary file + `os.replace`). State is written only after the report has been produced (with `--report-dir`: after the report file is in place), so a failed run is repeated instead of skipped.
- `--since` (preview mode) must never read the cursor or write any state or report files. It may read `seen.json` to mark new patterns.
- Filtering order must be strictly preserved:
  1. `RULES`: match always selects entry, bypassing `NOISE` and priority limits.
  2. `NOISE`: match drops entry if no rule matched (even if matching `ALWAYS_INCLUDE`).
  3. Priority selection: entry is selected if `PRIORITY <= MAX_PRIORITY` or if it matches `ALWAYS_INCLUDE`.
- Keep all configuration settings (`REMOTE_DIR`, `DEFAULT_STATE_DIR`, `INITIAL_SINCE`, `MAX_PRIORITY`) and tunable lists (`HOSTS`, `RULES`, `ALWAYS_INCLUDE`, `NOISE`, `EXTRA_NORMALIZERS`) in the configuration section at the top of the file.
- Keep `logfilter.py` and `analyze.py` single scripts (plus the systemd units in `systemd/`) unless asked otherwise. `analyze.py` also uses the standard library only (`urllib.request` for HTTP), keeps its settings and prompts in its configuration section, and writes analysis files atomically.

## Report format

The downstream LLM stage parses the report format. Do not modify it unless explicitly requested.

Structure per host:
1. Header:
   - `=== <host> ===`
   - `mode: <mode description>`
   - `range: <first_iso> -> <last_iso>` (or `range: no entries`)
   - `entries read: <count>  (<prio_counts>)`
   - `dropped as noise: <count>`
   - `selected: <count> entries in <patterns_count> patterns (<rules_count> with rule matches, <new_count> new)`
   - optional note if no saved patterns exist
2. Blank line
3. Patterns sorted by: rule matches first, then new patterns, then minimum priority (most severe first), then count (desc):
   - `[rule:<name>]... [[NEW]] <priority_name> <source> x<count>  <first_iso> -> <last_iso>`
   - `  pattern: <normalized_template>`
   - `  example: <sample_message>`
   - `  top IPs: <ip xcount, ...> (<distinct_count> distinct)` (omitted if no IPs)
4. Footer:
   - `report size: <char_count> characters`

Journal-derived text (`<source>`, `<normalized_template>`, `<sample_message>`) must never break a report line: `split_report` in `analyze.py` reads the file with universal newlines. `one_line()` and `clip()` in `logfilter.py` handle this: newlines in messages become ` | `, every Cc/Cf/Zl/Zp character except tab is written as a visible escape (`printable()`), template and example are cut at 400 characters and the source at `SOURCE_LIMIT` (512), with ` …` marking a cut. Only a bounded prefix is escaped, so large fields cost no extra memory; keep it that way. Render any new journal-derived report field through these helpers.

## Scope and changes

- Do only what is asked. Do not add features, options, refactors, or "improvements" that were not requested.
- Necessary changes outside the request are allowed only if required for the task to work. Explain each one.
- For every change, state what changed and why.
- Do not change the report format unless asked. The LLM stage consumes it (`split_report` and `SYSTEM_PROMPT` in `analyze.py`). If a requested change affects the format or the normalization placeholders, say so explicitly and update `analyze.py` to match.
- Prefer the simplest working solution.

## Testing

Do not run the script against real journals, and do not create or modify anything under `/var/lib/logfilter/`.

Automated tests live in `tests/` (`test_logfilter.py`, `test_analyze.py`, standard library `unittest`, synthetic data only). Run them from the repository root after every change, and add or update tests along with any behavior change:

```
python3 -m unittest discover -s tests -v
```

CI (`.github/workflows/ci.yml`) also runs `ruff check` and `ruff format --check` with the ruff version pinned in `requirements-dev.txt`, runs the tests with `pytest --cov` on Python 3.10 to 3.14 (tools installed from `requirements-dev.lock`, after checking that the lock satisfies `requirements-dev.txt`), and sends coverage to SonarQube Cloud (`sonar-project.properties`). Actions are pinned to full commit SHAs with a version comment. Dependabot (`.github/dependabot.yml`) opens weekly update PRs, one for the actions and one for `requirements-dev.txt`; it cannot update `requirements-dev.lock`, so regenerate the lock on its pip PRs before merging (the test jobs fail until then). Code follows `ruff format` layout (line length 120, settings in `pyproject.toml`): run `ruff format` and `ruff check` before committing. After changing `requirements-dev.txt`, regenerate the lock with `uv pip compile --universal --generate-hashes --no-header --python-version 3.10 --upgrade --exclude-newer "7 days" requirements-dev.txt -o requirements-dev.lock` (`--upgrade` also updates the indirect dependencies, which Dependabot does not see; `--exclude-newer "7 days"` matches the Dependabot cooldown). SonarQube taint findings on CLI arguments (path traversal, SSRF, command argument injection) are accepted as false positives; do not "fix" them by restricting legitimate paths or URLs.

The guidance below describes what the tests do and how to test by hand.

Test with a fake `journalctl`: an executable script named `journalctl` in a temporary directory that prints JSON lines (one journal entry per line, with fields such as `__CURSOR`, `__REALTIME_TIMESTAMP`, `PRIORITY`, `MESSAGE`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`, `_TRANSPORT`, `_HOSTNAME`). Put that directory first in `PATH` and always pass a temporary `--state-dir` (the default is `/var/lib/logfilter`) and, when used, a temporary `--report-dir`.

When invoking `logfilter.py` in tests, specify `palvelin` as a positional argument unless testing multi-host dispatch, to avoid unexpected calls for remote hosts.

Cover at least:
- normal mode: first run, then a second run continuing from the saved cursor
- preview mode (`--since`): no state files written
- rule match overriding a noise match
- normalization of IPv4, IPv6, MAC, UUID, hex, numbers, timestamps
- binary `MESSAGE` fields (JSON array of byte values) and repeated fields (JSON array of strings)
- `--report-dir`: report file written, nothing on stdout, and no state saved if writing the report fails

Test `analyze.py` with a fake Ollama server (a small `http.server` script answering `POST /api/chat`) and synthetic reports in a temporary `--report-dir`, passing `--url` and `--known-issues` explicitly. Cover at least: single-chunk and multi-chunk reports (including the merge request), empty reports (no request), already analyzed reports skipped, invalid replies retried, and an unreachable server stopping the run with no analysis files written.

Syntax check command:

```
python3 -m py_compile logfilter.py analyze.py
```
- `python3`: Python interpreter executable.
- `-m py_compile`: executes standard library module `py_compile` to compile source code to bytecode.
- `logfilter.py analyze.py`: target script files to check.

## Test data

Logs are sensitive. Never use real log content in tests, examples, or commit messages. Use synthetic data with documentation address ranges only:
- IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- IPv6: `2001:db8::/32`

## Known issues (deferred)

Observed in production output. Not yet decided; do not fix unless asked. Fixes for 1, 3 and 4 would change the report format.

1. `NOISE` can silently drop high-severity entries (crit/err): the report only shows the total `dropped as noise` count, not which noise patterns dropped what or at which priority.
2. `dropped as noise` also counts entries above `MAX_PRIORITY` that priority selection would have dropped anyway, so on hosts with noisy info-level logs (for example container logs) it overstates how much noise suppressed.
3. The same message logged by one process under different units (for example sshd messages under both `sshd.service` and `session-<N>.scope`) becomes separate patterns, because `source` is part of the pattern key.
4. A host where nothing has ever been selected keeps an empty `seen.json`, so the "no saved patterns" note repeats on every run.

## Communication

- English only. Keep Finnish identifiers, hostnames, strings, and month names exactly as they appear.
