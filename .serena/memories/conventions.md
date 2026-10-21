# Conventions (logfilter.py)

- Plain functions, no classes, no type hints. Short docstrings only where behavior is non-obvious; sparse inline comments.
- Section banners: `# --- Name ---...` padded with dashes to ~79 cols. Keep new code in the matching section; all tunables stay in Configuration.
- Tunable list shapes (consumed positionally by `compile_list`/`match_any`; regex must be the last element):
  - `RULES`: `(name, ident_or_None, regex)`
  - `ALWAYS_INCLUDE`, `NOISE`: `(ident_or_None, regex)`
  - `EXTRA_NORMALIZERS`: `(regex, replacement)`
  - ident is compared to `SYSLOG_IDENTIFIER` (fallback `_COMM`); regex is searched (not matched) in MESSAGE.
- Pattern aggregates are plain dicts (`source, template, example, prio, count, first, last, rules:set, ips:Counter`); `prio` keeps the minimum (most severe).
- Journal field access always goes through `text()` to handle binary/repeated fields.
- Timestamps are `__REALTIME_TIMESTAMP` microsecond ints, formatted via `fmt_ts`; seen.json values are local ISO with offset, `timespec="seconds"`.
- Layout: `ruff format` (line length 120, `pyproject.toml`), and `ruff check` with ruff's default rule set; CI fails on either. Implicit string concatenation inside tuples/lists must be parenthesized (ISC004), e.g. the multi-line NOISE regexes. The deliberate broad `except Exception` in `logfilter.main()` carries `# noqa: BLE001`.
- Strings: f-strings, double quotes. Finnish identifiers/hostnames kept verbatim.
