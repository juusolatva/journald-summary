# Suggested commands

- Test suite (stdlib unittest, ~5 s, no root, no network beyond 127.0.0.1): `python3 -m unittest discover -s tests -v`
  - `tests/test_logfilter.py`: unit tests (normalize, text, source_of, RULES/NOISE samples) plus end-to-end subprocess runs with a fake `journalctl` generated per test (`E2EBase`). `NoiseTest.test_every_noise_entry_has_a_sample` / `RulesTest.test_every_rule_has_a_sample` fail when a new NOISE or RULES entry has no synthetic sample, so add one.
  - `tests/test_analyze.py`: an in-process fake Ollama server (`FakeServerMixin`, port 0, scripted replies) and `MainTest` calling `analyze.main()` with patched `sys.argv` and `RETRY_DELAYS`. `setUpModule` disables proxies and lowers `REQUEST_TIMEOUT`.
- Syntax check: `python3 -m py_compile logfilter.py analyze.py`
- Lint/format (CI fails on either): `ruff format` then `ruff check`. CI-equivalent check: `ruff format --check --diff && ruff check`.
- Dev tools (into a venv): `python3 -m pip install --require-hashes --only-binary :all: -r requirements-dev.lock`.
- CI-equivalent tests with coverage: `python3 -m pytest --cov --cov-report=xml`. Writes `.coverage` / `coverage.xml`, both gitignored.
- Optional type check (not project-mandated; ruff is the required linter): `basedpyright logfilter.py`
- Production run (target host only, never in dev/tests): `sudo ./logfilter.py [hosts...] [--since WINDOW] [--state-dir DIR] [--report-dir DIR]`
- Verify units without installing: copy `systemd/*` to scratch, point `ExecStart` at the repo script, `systemd-analyze verify <copies>`.

## Fake journalctl harness (the only allowed way to run the script in tests)
- Create a temp dir with an executable `journalctl` that prints JSON lines (fields: `__CURSOR`, `__REALTIME_TIMESTAMP`, `PRIORITY`, `MESSAGE`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`, `_TRANSPORT`, `_HOSTNAME`).
- To test cursor continuation, make the fake inspect its args: `--after-cursor=<c>` -> emit only entries after `<c>`; `--since=` -> emit all. Log received args to a file to assert `--since`/`--after-cursor` usage.
- Exit non-zero from the fake to test the RuntimeError/stderr path (exit status 1, other hosts continue).
- Run: `PATH="$TMP:$PATH" python3 logfilter.py palvelin --state-dir "$TMP/state"` (always pass `palvelin` unless testing multi-host dispatch; always pass `--state-dir`).
- Binary MESSAGE = JSON int array of bytes; repeated field = JSON string array.
- Synthetic data only, documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
- Put temp dirs in the session scratchpad, never under `/var/lib/logfilter/`.

## Fake Ollama harness (analyze.py)
- Small `http.server` script on 127.0.0.1 answering `POST /api/chat` with `{"message": {"content": <JSON string>}, "done_reason": "stop", "prompt_eval_count": .., "eval_count": ..}`; have it log request bodies and take a scripted list of reply kinds (ok / schema-invalid / non-JSON / `done_reason: "length"`).
- Synthetic reports in a temp report dir (one with patterns, one with 0 patterns, one over `CHUNK_CHARS` to force chunks plus a merge).
- Run with zero retry waits: `python3 -c "import sys; sys.argv=['analyze.py']+sys.argv[1:]; import analyze; analyze.RETRY_DELAYS=[0,0]; sys.exit(analyze.main())" --report-dir $TMP/r --url http://127.0.0.1:PORT --known-issues $TMP/known.txt`
- Unreachable server: run the same command with no server listening.
- Real-model smoke test (dev machine): `--url http://10.0.0.4:11434`, synthetic reports only, unless the user asks to analyze real reports.

## Linux notes
- System locale is Finnish: `ls -l`, `date`, journalctl text output show Finnish month names (loka, syys). Use `LC_ALL=C` when parsing command output.
