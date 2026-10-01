#!/usr/bin/env python3
"""logfilter: condense journald logs per host into deduplicated patterns.

Stage 1 of the log analysis pipeline: deterministic filtering only, no LLM.
Prints one report per host to stdout.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime

# --- Configuration -----------------------------------------------------------

REMOTE_DIR = "/var/log/journal/remote"

# Host name -> journalctl arguments that select that host's entries.
HOSTS = {
    "palvelin": [],  # local journal
    "vakoilu": [f"--directory={REMOTE_DIR}", "_HOSTNAME=vakoilu"],
    "seuranta": [f"--directory={REMOTE_DIR}", "_HOSTNAME=seuranta"],
}

DEFAULT_STATE_DIR = "/var/lib/logfilter"

# Window for the first normal run of a host (no saved cursor yet).
INITIAL_SINCE = "24 hours ago"

# Entries at this priority or more severe are selected (4 = warning).
MAX_PRIORITY = 4

# (rule name, SYSLOG_IDENTIFIER or None for any, regex on MESSAGE).
# A match always selects the entry, even if it also matches NOISE.
RULES = [
    ("unit_failed", None, r"Failed with result|entered failed state"),
    ("oom", None, r"(?i)out of memory|oom-kill|invoked oom-killer"),
    ("disk_full", None, r"No space left on device"),
    ("io_error", None, r"(?i)I/O error|EXT4-fs error|BTRFS (error|critical)|critical medium error"),
    ("fs_readonly", None, r"(?i)remount\w*.*read-only"),
    ("kernel_crash", None, r"Kernel panic|kernel BUG|Oops:|general protection fault|Call Trace:"),
    ("crash", None, r"segfault at|dumped core"),
    ("hardware", None, r"(?i)hardware error|machine check|EDAC"),
    ("undervoltage", None, r"(?i)under-?voltage"),
    ("thermal", None, r"(?i)temperature above threshold|thermal throttl"),
]

# (SYSLOG_IDENTIFIER or None, regex): selected regardless of priority.
ALWAYS_INCLUDE = [
    (None, r"^Accepted \S+ for \S+ from"),  # successful SSH logins
    (None, r"^(Invalid user|Failed \S+ for)"),  # failed SSH logins (logged at info)
    ("sudo", r"COMMAND="),  # sudo usage
    (None, r"new user: |new group: |delete user |delete group |password changed for "),
    (None, r"^Startup finished in .*\(kernel\)"),  # system boots
]

# (SYSLOG_IDENTIFIER or None, regex): routine entries dropped before selection.
NOISE = [
    # ("sshd-session", r"^Connection closed by .* \[preauth\]$"),
]

# (regex, replacement): applied before the generic normalization below.
EXTRA_NORMALIZERS = [
    (r"(?i)\b(invalid user) \S*", r"\1 <USER>"),
]

# --- Normalization -----------------------------------------------------------

RX_TIME = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    r"|\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"
)
RX_UUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
RX_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
RX_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RX_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
RX_HEX = re.compile(r"\b0x[0-9A-Fa-f]+\b|\b(?=[0-9A-Fa-f]*\d)(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{8,}\b")
RX_NUM = re.compile(r"\b\d+(?:\.\d+)*(?:[A-Za-z]{1,3})?\b")

PRIO_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def compile_list(items):
    return [tuple(item[:-1]) + (re.compile(item[-1]),) for item in items]


RULES_RX = compile_list(RULES)
ALWAYS_RX = compile_list(ALWAYS_INCLUDE)
NOISE_RX = compile_list(NOISE)
EXTRA_RX = [(re.compile(rx), rep) for rx, rep in EXTRA_NORMALIZERS]


def normalize(msg):
    """Replace variable parts of a message with placeholders.

    Returns (template, list of IP addresses found).
    """
    ips = []

    def ip_rep(m):
        try:
            ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        ips.append(m.group(0))
        return "<IP>"

    for rx, rep in EXTRA_RX:
        msg = rx.sub(rep, msg)
    msg = RX_TIME.sub("<TIME>", msg)
    msg = RX_UUID.sub("<UUID>", msg)
    msg = RX_MAC.sub("<MAC>", msg)
    msg = RX_IPV4.sub(ip_rep, msg)
    msg = RX_IPV6.sub(ip_rep, msg)
    msg = RX_HEX.sub("<HEX>", msg)
    msg = RX_NUM.sub("<N>", msg)
    return msg, ips


# --- Journal entry helpers ---------------------------------------------------


def text(value):
    """Convert a journal JSON field value to a string (or None)."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, list):
        if value and all(isinstance(x, int) for x in value):  # binary field
            return bytes(value).decode("utf-8", "replace")
        return text(value[0]) if value else None  # repeated field: first value
    return str(value)


def source_of(entry, ident):
    """Short label for where an entry came from, with numbers normalized."""
    if text(entry.get("_TRANSPORT")) == "kernel":
        return "kernel"
    unit = text(entry.get("_SYSTEMD_UNIT")) or text(entry.get("_SYSTEMD_USER_UNIT"))
    label = unit if unit and unit != "init.scope" else (ident or "unknown")
    return RX_NUM.sub("<N>", label)


def match_any(rules, ident, msg):
    return any((i is None or i == ident) and rx.search(msg) for i, rx in rules)


def fmt_ts(usec):
    return datetime.fromtimestamp(usec / 1_000_000).astimezone().isoformat(timespec="seconds")


def one_line(s, limit=400):
    s = s.replace("\n", " | ")
    return s if len(s) <= limit else s[:limit] + " …"


# --- State files -------------------------------------------------------------


def read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def write_atomic(path, content):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


# --- Main processing ---------------------------------------------------------


def process_host(host, since, state_dir):
    host_dir = os.path.join(state_dir, host)
    cursor_path = os.path.join(host_dir, "cursor")
    seen_path = os.path.join(host_dir, "seen.json")
    preview = since is not None

    cmd = ["journalctl", "--output=json", "--no-pager", "--quiet"] + HOSTS[host]
    if preview:
        cmd.append(f"--since={since}")
        mode = f"preview (since {since}; state not updated)"
    else:
        cursor = read_file(cursor_path)
        if cursor:
            cmd.append(f"--after-cursor={cursor}")
            mode = "normal (after saved cursor)"
        else:
            cmd.append(f"--since={INITIAL_SINCE}")
            mode = f"normal (first run, since {INITIAL_SINCE})"

    seen_raw = read_file(seen_path)
    seen = json.loads(seen_raw) if seen_raw else {}

    patterns = {}
    by_prio = Counter()
    total = noise = 0
    first_ts = last_ts = None
    last_cursor = None

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    for line in proc.stdout:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        last_cursor = entry.get("__CURSOR", last_cursor)
        ts = int(entry.get("__REALTIME_TIMESTAMP", 0))
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        try:
            prio = int(text(entry.get("PRIORITY")))
        except (TypeError, ValueError):
            prio = 6
        by_prio[prio] += 1

        msg = text(entry.get("MESSAGE")) or ""
        ident = text(entry.get("SYSLOG_IDENTIFIER")) or text(entry.get("_COMM")) or ""

        rules = [name for name, i, rx in RULES_RX if (i is None or i == ident) and rx.search(msg)]
        if not rules:
            if match_any(NOISE_RX, ident, msg):
                noise += 1
                continue
            if prio > MAX_PRIORITY and not match_any(ALWAYS_RX, ident, msg):
                continue

        source = source_of(entry, ident)
        template, ips = normalize(msg)
        key = hashlib.sha1(f"{source}\0{template}".encode()).hexdigest()[:16]
        p = patterns.get(key)
        if p is None:
            p = patterns[key] = {
                "source": source, "template": template, "example": msg,
                "prio": prio, "count": 0, "first": ts, "last": ts,
                "rules": set(), "ips": Counter(),
            }
        p["count"] += 1
        p["last"] = ts
        p["prio"] = min(p["prio"], prio)
        p["rules"].update(rules)
        p["ips"].update(ips)

    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"journalctl exited with status {proc.returncode}")

    # --- Report ---
    new_keys = [k for k in patterns if k not in seen]
    selected = sum(p["count"] for p in patterns.values())
    rule_count = sum(1 for p in patterns.values() if p["rules"])

    out = [f"=== {host} ===", f"mode: {mode}"]
    if total:
        out.append(f"range: {fmt_ts(first_ts)} -> {fmt_ts(last_ts)}")
    else:
        out.append("range: no entries")
    prio_text = " ".join(f"{PRIO_NAMES[i]}={by_prio[i]}" for i in range(8) if by_prio[i])
    out.append(f"entries read: {total}  ({prio_text or 'none'})")
    out.append(f"dropped as noise: {noise}")
    out.append(f"selected: {selected} entries in {len(patterns)} patterns "
               f"({rule_count} with rule matches, {len(new_keys)} new)")
    if not seen:
        out.append("note: no saved patterns for this host yet, so every pattern is marked new")
    out.append("")

    def sort_key(item):
        k, p = item
        return (0 if p["rules"] else 1, 0 if k in new_keys else 1, p["prio"], -p["count"])

    for k, p in sorted(patterns.items(), key=sort_key):
        tags = [f"[rule:{r}]" for r in sorted(p["rules"])]
        if k in new_keys:
            tags.append("[NEW]")
        prio_name = PRIO_NAMES[p["prio"]] if 0 <= p["prio"] < 8 else str(p["prio"])
        head = " ".join(tags + [prio_name, p["source"], f"x{p['count']}"])
        out.append(f"{head}  {fmt_ts(p['first'])} -> {fmt_ts(p['last'])}")
        out.append(f"  pattern: {one_line(p['template'])}")
        out.append(f"  example: {one_line(p['example'])}")
        if p["ips"]:
            top = ", ".join(f"{ip} x{n}" for ip, n in p["ips"].most_common(5))
            out.append(f"  top IPs: {top} ({len(p['ips'])} distinct)")
    report = "\n".join(out)
    print(report)
    print(f"report size: {len(report)} characters\n")

    # --- Save state (normal mode only, after the report was produced) ---
    if not preview:
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        for k in new_keys:
            seen[k] = now
        write_atomic(seen_path, json.dumps(seen, indent=0))
        if last_cursor:
            write_atomic(cursor_path, last_cursor)


def main():
    ap = argparse.ArgumentParser(description="Condense journald logs per host into patterns.")
    ap.add_argument("hosts", nargs="*", help=f"hosts to process (default: all of {', '.join(HOSTS)})")
    ap.add_argument("--since", help="preview a time window (journalctl --since syntax) without using or updating saved state")
    ap.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help=f"state directory (default: {DEFAULT_STATE_DIR})")
    args = ap.parse_args()

    hosts = args.hosts or list(HOSTS)
    unknown = [h for h in hosts if h not in HOSTS]
    if unknown:
        ap.error(f"unknown host(s): {', '.join(unknown)}")

    status = 0
    for host in hosts:
        try:
            process_host(host, args.since, args.state_dir)
        except Exception as exc:  # report and continue with the other hosts
            print(f"{host}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
