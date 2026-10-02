# Suggested commands

- Syntax check: `python3 -m py_compile logfilter.py`
- Optional type/lint check (not project-mandated): `basedpyright logfilter.py`
- Production run (target host only, never in dev/tests): `sudo ./logfilter.py [hosts...] [--since WINDOW] [--state-dir DIR]`

## Fake journalctl harness (the only allowed way to run the script in tests)
- Create a temp dir with an executable `journalctl` that prints JSON lines (fields: `__CURSOR`, `__REALTIME_TIMESTAMP`, `PRIORITY`, `MESSAGE`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`, `_TRANSPORT`, `_HOSTNAME`).
- To test cursor continuation, make the fake inspect its args: `--after-cursor=<c>` -> emit only entries after `<c>`; `--since=` -> emit all. Log received args to a file to assert `--since`/`--after-cursor` usage.
- Exit non-zero from the fake to test the RuntimeError/stderr path (exit status 1, other hosts continue).
- Run: `PATH="$TMP:$PATH" python3 logfilter.py palvelin --state-dir "$TMP/state"` (always pass `palvelin` unless testing multi-host dispatch; always pass `--state-dir`).
- Binary MESSAGE = JSON int array of bytes; repeated field = JSON string array.
- Synthetic data only, documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
- Put temp dirs in the session scratchpad, never under `/var/lib/logfilter/`.

## Linux notes
- System locale is Finnish: `ls -l`, `date`, journalctl text output show Finnish month names (loka, syys). Use `LC_ALL=C` when parsing command output.
