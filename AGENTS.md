# AGENTS.md

This file is the authoritative contributor and agent guidance. `CLAUDE.md` includes it. Keep durable project conventions here and user-facing usage and setup instructions in [README.md](README.md).

## Project

`logfilter.py` is stage 1 of a small log analysis pipeline for a handful of Linux servers. It reads systemd journal entries per host, filters and deduplicates them deterministically, and produces a condensed report per host (stdout, or one file per host per run with `--report-dir`). It does not call any LLM. It runs daily via `systemd/logfilter.service` and `systemd/logfilter.timer`.

The goal is to spot software and hardware problems (failed units, crashes, disk, memory, filesystem, thermal and power issues, misconfiguration). Security monitoring (intrusion detection, auditing, login attempts, scanning) is out of scope; dedicated tools such as auditd cover it. Do not add rules, patterns or report fields aimed at security.

Stage 2, `analyze.py`, reads the report files and sends them, in chunks when needed, to a local LLM (Ollama native HTTP API, `http://localhost:11434` by default), retrying until analysis succeeds or the report is `GIVE_UP_DAYS` old. It writes `<report-dir>/<host>/<YYYYmmdd-HHMMSS>.analysis.txt` next to each report; a report counts as analyzed when that file exists. It runs via `systemd/analyze.service`, which `logfilter.service` pulls in. All LLM and HTTP code belongs in `analyze.py`; `logfilter.py` never calls an LLM or the network.

## Repository map

- `logfilter.py`: configuration, normalization, journal entry helpers, state files, and main processing. `process_host()` coordinates journal reading, report output, and state saving.
- `analyze.py`: configuration and prompts, report parsing and chunking, Ollama requests and retries, and main processing.
- `systemd/`: daily logfilter timer and the two services.
- `tests/test_logfilter.py`, `tests/test_analyze.py`: synthetic unit and integration tests, also collected by pytest through `pytest.ini`.
- `pyproject.toml`: Ruff and coverage settings. `requirements-dev.txt` and `requirements-dev.lock`: development tools and their hashed lock. `.github/` and `sonar-project.properties`: CI and dependency updates.

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

- Python 3.13 or newer, standard library only, for `logfilter.py`, `analyze.py` and the tests (no runtime dependencies, so there is no `requirements.txt`: Semgrep Supply Chain fails to parse a requirements file with no requirements). No third-party packages, no `python-systemd`, no other languages. The only exception is development and CI tooling (`pytest`, `pytest-cov`, `ruff`) in `requirements-dev.txt`, pinned with hashes in `requirements-dev.lock`; never import it from the scripts or tests.
- Read the journal only through `journalctl --output=json` via `subprocess`. Never parse `journalctl` text output: it is locale-dependent (palvelin prints Finnish month names such as `loka` and `syys`).
- Keep `--all` in the journalctl command; without it, fields larger than 4096 bytes can be returned as null.
- The command requests only `JOURNAL_FIELDS` with `--output-fields` (JSON output always adds `__CURSOR` and `__REALTIME_TIMESTAMP`), so large unused fields are never read. Add a field there when the code starts reading it; `ReadJournalTest` checks every `entry.get()` field against the list.
- No databases. State is plain files in `<state-dir>/<host>/` (default `/var/lib/logfilter/<host>/`):
  - `cursor`: last processed journal cursor string.
  - `seen.json`: pattern keys already seen, mapped to first-seen ISO timestamp string.
- State and report files are written atomically (temporary file + `os.replace`). State is written only after the report has been produced (with `--report-dir`: after the report file is in place), so a failed run is repeated instead of skipped. A report file is never replaced (`write_atomic(..., overwrite=False)` links it into place): if `<stamp>.txt` exists, that host fails before saving state.
- `--since` (preview mode) must never read the cursor or write any state or report files. It may read `seen.json` to mark new patterns.
- Filtering order must be strictly preserved:
  1. `RULES`: match always selects entry, bypassing `NOISE` and priority limits.
  2. `NOISE`: match drops entry if no rule matched (even if matching `ALWAYS_INCLUDE`).
  3. Priority selection: entry is selected if `PRIORITY <= MAX_PRIORITY` or if it matches `ALWAYS_INCLUDE`.
- Keep all configuration settings (`REMOTE_DIR`, `DEFAULT_STATE_DIR`, `INITIAL_SINCE`, `MAX_PRIORITY`) and tunable lists (`HOSTS`, `RULES`, `ALWAYS_INCLUDE`, `NOISE`, `EXTRA_NORMALIZERS`) in the configuration section at the top of the file.
- Keep `logfilter.py` and `analyze.py` single scripts (plus the systemd units in `systemd/`) unless asked otherwise. `analyze.py` also uses the standard library only (`urllib.request` for HTTP), keeps its settings and prompts in its configuration section, and writes analysis files atomically.

## Code conventions and invariants

- Match the scripts' existing style: plain functions, no classes (other than a small exception subclass such as `ContextFullError`) or type hints, short docstrings where behavior is non-obvious, and sparse inline comments. Keep code in the matching section under the existing section banners.
- Journal text fields go through `text()` so binary fields and repeated fields are handled consistently.
- `RULES` entries are `(name, identifier_or_None, regex)`; `ALWAYS_INCLUDE` and `NOISE` entries are `(identifier_or_None, regex)`. Their regex must stay last because `compile_list()` consumes it positionally. `EXTRA_NORMALIZERS` entries are `(regex, replacement)`. Identifiers match `SYSLOG_IDENTIFIER` (fallback `_COMM`); regexes use `re.search` on `MESSAGE`.
- Preserve normalization order: extra normalizers, IPv4, IPv6, MAC, timestamps, UUID, hex, numbers. IP candidates are validated with `ipaddress`; IPs must precede MAC and time matching to preserve IPv6, and MACs must precede times.
- Pattern keys are the first 16 hex characters of SHA-1 of `source + "\0" + template`. Changes to normalization, source selection or this formula can mark existing patterns new again.
- Sources prefer kernel transport, then `_SYSTEMD_USER_UNIT`, then `_SYSTEMD_UNIT` (each skipped if it is `init.scope`; a user service also carries `_SYSTEMD_UNIT=user@<UID>.service`), then the identifier. Source digits become `<N>`. A pattern keeps the most severe priority among its entries; an unparseable or out-of-range (not 0-7) entry priority defaults to info (6).
- Keep processing helpers small enough to stay within SonarQube's cognitive-complexity limit of 15.

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

The size counts the report text before the newline introducing the footer; it excludes the footer itself.

Journal-derived text (`<source>`, `<normalized_template>`, `<sample_message>`) must never break a report line: `split_report` in `analyze.py` reads the file with universal newlines. `one_line()` and `clip()` in `logfilter.py` handle this: newlines in messages become ` | `, every Cc/Cf/Zl/Zp character except tab is written as a visible escape (`printable()`), template and example are cut at 400 characters and the source at `SOURCE_LIMIT` (512), with ` …` marking a cut. Only a bounded prefix is escaped, so large fields cost no extra memory; keep it that way. Render any new journal-derived report field through these helpers.

## Analysis invariants

- Only `<YYYYmmdd-HHMMSS>.txt` files matching `REPORT_NAME` are inputs; `.analysis.txt` files must never match. Reports are processed oldest first within each host. A missing default report directory means nothing to analyze (exit status 0); any other error reading it (not a directory, no permission) exits with status 2.
- `split_report()` takes the header before the first blank line, groups each pattern heading with its following two-space-indented lines, and drops the `report size:` footer. `make_chunks()` keeps pattern blocks whole and repeats the header. Multiple chunks are combined by `merge()`: each merge request takes at least two chunk analyses and as many as fit `CHUNK_CHARS` (packed by `pack()`), in rounds until one analysis is left; a single leftover analysis is carried to the next round unchanged.
- A report whose header lacks `=== ` or `entries read:` (empty or damaged file) is a `ValueError`, never "no issues". Reports with no selected patterns are analyzed without Ollama (`model: -`, `chunks: 0`). A report with `entries read: 0` must produce the high-severity "No journal entries received" issue rather than "no issues".
- `chat()` uses `/api/chat`, `stream: false`, `format: SCHEMA`, temperature 0 and `num_ctx: NUM_CTX`, through `OPENER`, which ignores proxy environment variables; an HTTP error's message includes the start of its body (`ERROR_BODY_LIMIT`). `reply_content()` and `validate()` reject (as `ValueError`) a reply that is not a finished (`done`) object, an explicit `done_reason` other than `stop`, non-integer token counts, prompt plus generated token counts reaching `NUM_CTX` (`ContextFullError`), a missing or non-string `message.content`, an invalid schema, or strings that cannot be encoded as UTF-8.
- `render()` writes every model-supplied field (summary, title, details) through its `one_line()`: newlines become ` | ` and Cc/Cf/Zl/Zp characters except tab are escaped, so only `render()` starts analysis lines.
- `wrap_data()` encloses every user message, including merge input, in `<data-ID>` and `</data-ID>` lines. Generate a fresh random ID absent from the text for each request; keep this marker format and both prompts in sync.
- Each chunk request and merge request gets `1 + len(RETRY_DELAYS)` attempts, except that `ContextFullError` is raised at once (the same input fails the same way). After retries, `OSError` or `http.client.HTTPException` stops the run (including HTTP errors); `ValueError` or `KeyError` skips only the affected report, writing a failure analysis once it reaches `GIVE_UP_DAYS`. An unreachable server must never cause a report to be marked analyzed or given up on.

## Scope and changes

- Do only what is asked. Do not add features, options, refactors, or "improvements" that were not requested.
- Necessary changes outside the request are allowed only if required for the task to work. Explain each one.
- For every change, state what changed and why.
- Do not change the report format unless asked. The LLM stage consumes it (`split_report` and `SYSTEM_PROMPT` in `analyze.py`). If a requested change affects the format or the normalization placeholders, say so explicitly and update `analyze.py` to match.
- Prefer the simplest working solution.
- Commits are allowed; prefer opening a pull request from a branch over committing directly to `main`.

## Testing

Do not run the script against real journals, and do not create or modify anything under `/var/lib/logfilter/`.

Automated tests live in `tests/` (`test_logfilter.py`, `test_analyze.py`, standard library `unittest`, synthetic data only). Run them from the repository root after every change, and add or update tests along with any behavior change:

```
python3 -m unittest discover -s tests -v
```

CI (`.github/workflows/ci.yml`) also runs `ruff check` and `ruff format --check` with the ruff version pinned in `requirements-dev.txt`, runs the tests with `pytest --cov` on Python 3.13 and 3.14 (tools installed from `requirements-dev.lock`, after checking that the lock satisfies `requirements-dev.txt`), and sends coverage to SonarQube Cloud (`sonar-project.properties`). `.github/workflows/osv-scanner.yml` scans `requirements-dev.lock` with OSV-Scanner on pushes, PRs and a weekly schedule. Actions are pinned to full commit SHAs with a version comment. Dependabot (`.github/dependabot.yml`) opens weekly update PRs, one for the actions and one for `requirements-dev.txt`; it cannot update `requirements-dev.lock`, so regenerate the lock on its pip PRs before merging (the test jobs fail until then). Code follows `ruff format` layout (line length 120, settings in `pyproject.toml`): run `ruff format` and `ruff check` before committing. After changing `requirements-dev.txt`, regenerate the lock with `uv pip compile --universal --generate-hashes --no-header --python-version 3.13 --upgrade --exclude-newer "7 days" requirements-dev.txt -o requirements-dev.lock` (`--upgrade` also updates the indirect dependencies, which Dependabot does not see; `--exclude-newer "7 days"` matches the Dependabot cooldown). SonarQube taint findings on CLI arguments (path traversal, SSRF, command argument injection) are accepted as false positives; do not "fix" them by restricting legitimate paths or URLs.

The guidance below describes what the tests do and how to test by hand.

`RulesTest.test_every_rule_has_a_sample` and `NoiseTest.test_every_noise_entry_has_a_sample` require a synthetic sample for every rule and noise entry. Add samples when changing those lists. The analysis tests use `FakeServerMixin` for scripted HTTP replies and patch retry delays to avoid production waits.

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

The gitignored `logfilter/` directory may contain local copies of production state, reports and analyses. Treat them as sensitive: never commit, publish or copy their content into documentation or test fixtures.

## Known issues (deferred)

Observed in production output. Not yet decided; do not fix unless asked. Fixes for 1, 3 and 4 would change the report format.

1. `NOISE` can silently drop high-severity entries (crit/err): the report only shows the total `dropped as noise` count, not which noise patterns dropped what or at which priority.
2. `dropped as noise` also counts entries above `MAX_PRIORITY` that priority selection would have dropped anyway, so on hosts with noisy info-level logs (for example container logs) it overstates how much noise suppressed.
3. The same message logged by one process under different units (for example sshd messages under both `sshd.service` and `session-<N>.scope`) becomes separate patterns, because `source` is part of the pattern key.
4. A host where nothing has ever been selected keeps an empty `seen.json`, so the "no saved patterns" note repeats on every run.

## Deferred review findings

From the security audit and repository review of revision `bb16286` (2026-11-20); the rest of their findings are fixed. Not yet decided; do not fix unless asked.

1. `analyze.py` does not authenticate the Ollama listener: if Ollama is down and another local process takes `localhost:11434`, it receives report chunks and known issues and can return analyses that are saved as complete. Ollama has no TLS or authentication of its own, so a fix needs a TLS reverse proxy with certificate checks. Accepted for now: it needs local access to palvelin while Ollama is not running.
2. `seen.json` has no size limit or expiry, and every normal run rewrites it even with no new patterns. A bound would need eviction (an evicted pattern becomes new again); skipping unchanged writes must keep first-run initialization and report-before-state ordering.
3. One report that takes longer than `TimeoutStartSec=6h` is killed and redone from its first chunk after every restart, holding up later reports, other hosts included. `GIVE_UP_DAYS` cannot help because the process is killed, not failing. A fix needs per-chunk checkpoints keyed to report content and analysis settings, or bounded batches per run.
4. `too_old()` uses only the report's file name time, so after an Ollama outage of `GIVE_UP_DAYS` or more, a report that fails once (three attempts within about 2.5 minutes) is given up on at the first run after the server returns. A fix needs failure tracking (first failure time or attempt count), which is new state.
5. A damaged `cursor` file (not UTF-8, or a cursor `journalctl` rejects) makes that host fail on every run until it is removed by hand.
6. Report file names use naive local time, so names in the DST fall-back hour (Europe/Helsinki) are ambiguous: `pending_reports()` order and `too_old()` can be off by an hour.
7. `logfilter.service` pulls in `analyze.service` with `Wants=`. If `analyze.service` is already running (a 30-minute retry), no second run is queued, so reports written after it listed the directory wait for its next restart or the next day.
8. IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) normalize to `::ffff:<IP>`, because IPv4 is replaced first; the IPv4 part is still counted in top IPs.
9. `analyze.py` follows HTTP redirects, and `chat()` appends `/api/chat` to the raw `--url`, so a URL with a query string or fragment is mangled.
10. The `invalid user` normalizer in `EXTRA_NORMALIZERS` uses `\S*` (it also matches an empty name) and is security-flavored; removing it would split sshd noise into many patterns and change their keys.
11. The SonarQube CI job runs on every pull request without a guard for forks, where `SONAR_TOKEN` is missing. Only matters if outside contributions start.

## Communication

- English only. Keep Finnish identifiers, hostnames, strings, and month names exactly as they appear.
