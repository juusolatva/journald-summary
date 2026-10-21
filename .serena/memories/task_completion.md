# Task completion checklist

0. `python3 -m unittest discover -s tests` must pass (OK; known bugs are pinned as `@unittest.expectedFailure`). Add or adjust tests in `tests/test_logfilter.py` / `tests/test_analyze.py` with every behavior change. When a bug is fixed, remove its marker, because unittest reports an unexpected success as a failure.
1. `python3 -m py_compile logfilter.py analyze.py`
   - For `analyze.py` changes, use the fake Ollama harness (`mem:suggested_commands`) and cover the cases listed in AGENTS.md Testing.
2. Exercise changed behavior with the fake-journalctl harness (`mem:suggested_commands`). Coverage required by AGENTS.md: normal first run + second run from saved cursor; `--since` writes no state; rule overrides noise; normalization of IPv4/IPv6/MAC/UUID/hex/numbers/timestamps; binary and repeated fields.
3. If the report text changed in any way, say so explicitly (downstream LLM stage parses it).
4. Confirm no state written outside the temp `--state-dir`, and nothing under `/var/lib/logfilter/`.
5. Report what changed and why, per change; list any necessary out-of-scope edits with justification.
