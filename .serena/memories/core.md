# journald-summary — core

Authoritative rules: `AGENTS.md` (CLAUDE.md just includes it). Hard constraints, CLI, report format, test-data policy live there; read it before any change.

## Source map
- `logfilter.py` — the whole project (single script, ~330 lines). Sections in order:
  - Configuration: `REMOTE_DIR`, `HOSTS` (host -> extra journalctl args), `DEFAULT_STATE_DIR`, `INITIAL_SINCE`, `MAX_PRIORITY`, `RULES`, `ALWAYS_INCLUDE`, `NOISE`, `EXTRA_NORMALIZERS`.
  - Normalization: `RX_*` regexes, `PRIO_NAMES`, `compile_list` -> `RULES_RX`/`ALWAYS_RX`/`NOISE_RX`/`EXTRA_RX` (compiled at import), `normalize(msg) -> (template, ips)`.
  - Entry helpers: `text` (journal JSON value -> str; int list = binary bytes, str list = repeated field -> first), `source_of`, `match_any`, `fmt_ts`, `one_line`.
  - State: `read_file`, `write_atomic` (`path.tmp` + `os.replace`, dir mode 0700).
  - `process_host(host, since, state_dir)` — runs journalctl, filters, aggregates, prints report, then saves state.
  - `main()` — argparse; per-host exceptions go to stderr, other hosts continue, exit status 1.
- `logfilter_state/` — gitignored; default `--state-dir` (`DEFAULT_STATE_DIR = "./logfilter_state"`, relative to CWD).

## Non-obvious invariants
- Filter order inside `process_host`: RULES (ident-scoped or `None`) -> NOISE -> priority/ALWAYS_INCLUDE. Rule match skips both later checks.
- Pattern key = sha1(`source\0template`)[:16]; these keys are what `seen.json` stores. Changing `normalize`, `EXTRA_NORMALIZERS`, `source_of` or the key formula re-marks every pattern `[NEW]` on existing hosts.
- Normalizer order matters: EXTRA -> TIME -> UUID -> MAC -> IPv4 -> IPv6 -> HEX -> NUM. IP regex hits are validated with `ipaddress`; invalid ones are left as-is (then possibly eaten by HEX/NUM).
- `source_of`: kernel transport -> `kernel`; else `_SYSTEMD_UNIT`/`_SYSTEMD_USER_UNIT` unless `init.scope`, else ident; digits normalized to `<N>`.
- Unparseable PRIORITY defaults to 6 (info). Non-JSON journalctl lines are skipped silently. journalctl non-zero exit -> RuntimeError after the loop, before any report/state.
- `report size` footer counts the report without the footer line itself.

## Further memories
- Language/runtime/tooling facts: `mem:tech_stack`.
- Code style and idioms to match when editing `logfilter.py`: `mem:conventions`.
- Fake-journalctl test harness recipe and run commands: `mem:suggested_commands`.
- Checklist before declaring a task done: `mem:task_completion`.
