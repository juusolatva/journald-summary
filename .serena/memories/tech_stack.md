# Tech stack

- Python 3, standard library only (argparse, subprocess, json, re, ipaddress, hashlib, collections.Counter, datetime). No packaging: no pyproject/requirements, no venv.
- External runtime dependency: `journalctl` binary (systemd), invoked as `journalctl --output=json --no-pager --quiet [host args] (--since=... | --after-cursor=...)`.
- Target host: `palvelin` (openSUSE Tumbleweed), run with sudo. Dev machine differs (Fedora); never run against real journals.
- No test suite, linter config, or CI in repo. Tests are ad hoc with a fake `journalctl` (see `mem:suggested_commands`).
- Serena LS: `python_basedpyright` (set in `.serena/project.yml`); Serena launches it via `uvx -p 3.13 --from basedpyright==<pinned>`, so uv needs a Python 3.13 interpreter available.
