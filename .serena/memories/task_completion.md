# Task completion checklist

0. `python3 -m unittest discover -s tests` must pass (OK). Add or adjust tests in `tests/test_logfilter.py` / `tests/test_analyze.py` with every behavior change.
1. `ruff format` then `ruff check`, with ruff 0.17.1: pinned in `requirements-dev.txt` (CI reads the version from there) and installed locally from `requirements-dev.lock`. CI runs `ruff check --output-format=github` and `ruff format --check --diff`.
2. `python3 -m py_compile logfilter.py analyze.py`
3. Exercise changed behavior with the fake-journalctl harness (`mem:suggested_commands`). Coverage required by AGENTS.md:
   - normal first run, then a second run from the saved cursor;
   - `--since` writes no state;
   - rule overrides noise;
   - normalization of IPv4/IPv6/MAC/UUID/hex/numbers/timestamps;
   - binary and repeated fields;
   - `--report-dir` writes the file, prints nothing, and saves no state if the report write fails.
   For `analyze.py` changes, use the fake Ollama harness (`mem:suggested_commands`) and cover the cases listed in AGENTS.md Testing.
4. If the report text or the normalization placeholders changed in any way, say so explicitly. The downstream stage (`analyze.py` `split_report` / `SYSTEM_PROMPT`) parses the report.
5. Confirm no state was written outside the temp `--state-dir`, and nothing under `/var/lib/logfilter/`.
6. Report what changed and why, per change; list any necessary out-of-scope edits with justification.
7. Commits are allowed; prefer a branch and pull request over committing directly to `main`.
