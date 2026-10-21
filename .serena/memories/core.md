# journald-summary — core

Authoritative rules: `AGENTS.md` (CLAUDE.md just includes it). Hard constraints, CLI, report format, test-data policy live there; read it before any change.

## Source map
- `logfilter.py` — stage 1 (single script, ~360 lines). Sections in order:
  - Configuration: `REMOTE_DIR`, `HOSTS` (host -> extra journalctl args), `DEFAULT_STATE_DIR`, `INITIAL_SINCE`, `MAX_PRIORITY`, `RULES`, `ALWAYS_INCLUDE`, `NOISE`, `EXTRA_NORMALIZERS`.
  - Normalization: `RX_*` regexes, `PRIO_NAMES`, `compile_list` -> `RULES_RX`/`ALWAYS_RX`/`NOISE_RX`/`EXTRA_RX` (compiled at import), `normalize(msg) -> (template, ips)`.
  - Entry helpers: `text` (journal JSON value -> str; int list = binary bytes, str list = repeated field -> first), `source_of`, `match_any`, `fmt_ts`, `one_line`.
  - State: `read_file`, `write_atomic` (`path.tmp` + `os.replace`, dir mode 0700).
  - `process_host(host, since, state_dir, report_dir)` — runs journalctl, filters, aggregates, emits report (stdout, or atomic file `<report_dir>/<host>/<YYYYmmdd-HHMMSS>.txt`), then saves state.
  - `main()` — argparse; `--report-dir` + `--since` rejected; per-host exceptions go to stderr, other hosts continue, exit status 1.
- `DEFAULT_STATE_DIR = "/var/lib/logfilter"` (production path; tests must always pass `--state-dir`). `logfilter/` (gitignored) is a local copy of production output (`<host>/{cursor,seen.json}`, `reports/<host>/*.txt`): real, sensitive logs — read for tuning only, never commit, quote in tests/commits, or publish.
- `systemd/logfilter.service` (oneshot, root, `ProtectSystem=strict`, `StateDirectory=logfilter`, reports to `/var/lib/logfilter/reports`) + `systemd/logfilter.timer` (daily, `Persistent=true`). Script installed as `/usr/local/bin/logfilter.py`.
- `analyze.py` — stage 2: sends the report files to Ollama and writes `<stamp>.analysis.txt` next to each report. All LLM/HTTP code lives there, never in `logfilter.py`. Same style as `logfilter.py` (configuration section first, plain functions). Invariants (chunking, error classes, retry/stop rules): `mem:analyze`.
- `systemd/analyze.service` (oneshot, `Restart=on-failure` every 30 min, `IPAddressAllow=localhost`). `logfilter.service` has `Wants=analyze.service`, and analyze is ordered `After=logfilter.service`, so it runs after every logfilter run, also when one host failed.

## Non-obvious invariants
- Filter order inside `process_host`: RULES (ident-scoped or `None`) -> NOISE -> priority/ALWAYS_INCLUDE. Rule match skips both later checks.
- Pattern key = sha1(`source\0template`)[:16]; these keys are what `seen.json` stores. Changing `normalize`, `EXTRA_NORMALIZERS`, `source_of` or the key formula re-marks every pattern `[NEW]` on existing hosts.
- Normalizer order matters: EXTRA -> IPv4 -> IPv6 -> MAC -> TIME -> UUID -> HEX -> NUM. IPs go first because MAC/TIME would eat groups of valid IPv6 such as `2001:db8::12:34:56` or `2001:db8:aa:bb:cc:dd:ee:ff`. MAC must still precede TIME, otherwise `aa:bb:cc:10:00:01` loses its last 3 octets to TIME. IP regex hits are checked with `ipaddress`; invalid ones (MACs, clock times) are left for the later regexes.
- `source_of`: kernel transport -> `kernel`; else `_SYSTEMD_UNIT`/`_SYSTEMD_USER_UNIT` unless `init.scope`, else ident; digits normalized to `<N>`.
- Unparseable PRIORITY defaults to 6 (info). Non-JSON journalctl lines are skipped silently. journalctl non-zero exit -> RuntimeError after the loop, before any report/state.
- `report size` footer counts the report without the footer line itself.

## Further memories
- Language/runtime/tooling facts: `mem:tech_stack`.
- Code style and idioms to match when editing `logfilter.py`: `mem:conventions`.
- Fake-journalctl test harness recipe and run commands: `mem:suggested_commands`.
- Checklist before declaring a task done: `mem:task_completion`.
