# AGENTS.md

## Project

`logfilter.py` is stage 1 of a small log analysis pipeline for a handful of Linux servers. It reads systemd journal entries per host, filters and deduplicates them deterministically, and prints a condensed report per host. It does not call any LLM.

A later stage will send these reports to a local LLM (Ollama native HTTP API on `localhost`). That stage does not exist yet. Do not add LLM, network, or HTTP code unless explicitly asked.

## Environment

- Runs on `palvelin` (openSUSE Tumbleweed), the central server.
- Hosts and where their logs are:
  - `palvelin`: local journal.
  - `vakoilu` (Debian stable VPS) and `seuranta` (DietPi, Raspberry Pi 4): received with `systemd-journal-remote` into `/var/log/journal/remote/`, selected by `_HOSTNAME=<name>`.
- File names in `/var/log/journal/remote/` contain `CN=` (for example `remote-CN=vakoilu.journal`). Never select hosts by file name; always use the `_HOSTNAME` field.
- Reading the journals requires root. The script is run with `sudo`.

## Hard constraints

- Python 3, standard library only. No third-party packages, no `python-systemd`, no other languages.
- Read the journal only through `journalctl --output=json` via `subprocess`. Never parse `journalctl` text output: it is locale-dependent (palvelin prints Finnish month names such as `loka` and `syys`).
- No databases. State is plain files in `/var/lib/logfilter/<host>/`:
  - `cursor`: last processed journal cursor.
  - `seen.json`: pattern keys already seen, with first-seen time.
- State is written atomically (temporary file + `os.replace`) and only after the report has been produced, so a failed run is repeated instead of skipped.
- `--since` (preview mode) must never read the cursor or write any state. It may read `seen.json` to mark new patterns.
- `RULES` are checked before `NOISE`. A rule match must always select the entry, even if it also matches a noise pattern. Keep this order.
- Keep all tunable lists (`HOSTS`, `RULES`, `ALWAYS_INCLUDE`, `NOISE`, `EXTRA_NORMALIZERS`) and settings in the configuration section at the top of the file.
- Keep the project a single script unless asked otherwise.

## Scope and changes

- Do only what is asked. Do not add features, options, refactors, or "improvements" that were not requested.
- Necessary changes outside the request are allowed only if required for the task to work. Explain each one.
- For every change, state what changed and why.
- Do not change the report format unless asked. The LLM stage will consume it. If a requested change affects the format, say so explicitly.
- Prefer the simplest working solution.

## Testing

Do not run the script against real journals, and do not create or modify anything under `/var/lib/logfilter/`.

Test with a fake `journalctl`: an executable script named `journalctl` in a temporary directory that prints JSON lines (one journal entry per line, with fields such as `__CURSOR`, `__REALTIME_TIMESTAMP`, `PRIORITY`, `MESSAGE`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`, `_TRANSPORT`, `_HOSTNAME`). Put that directory first in `PATH` and use a temporary `--state-dir`.

Cover at least:
- normal mode: first run, then a second run continuing from the saved cursor
- preview mode (`--since`): no state files written
- rule match overriding a noise match
- normalization of IPv4, IPv6, MAC, UUID, hex, numbers, timestamps
- binary `MESSAGE` fields (JSON array of byte values) and repeated fields (JSON array of strings)

Syntax check:

```
python3 -m py_compile logfilter.py
```

## Test data

Logs are sensitive. Never use real log content in tests, examples, or commit messages. Use synthetic data with documentation address ranges only:
- IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- IPv6: `2001:db8::/32`

## Communication

- English only. Keep Finnish identifiers, hostnames, strings, and month names exactly as they appear.
- Be concise and direct. No filler.
- When giving commands, define every flag, option, and positional argument used.
- Present code changes as complete functions or files, not as diffs.
- Do not comment on intent, ethics, or best practices unless directly relevant to the task.
