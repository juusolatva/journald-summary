#!/usr/bin/env python3
"""logfilter: condense journald logs per host into deduplicated patterns.

Stage 1 of the log analysis pipeline: deterministic filtering only, no LLM.
Prints one report per host to stdout, or with --report-dir writes one report
file per host.
"""

import argparse
import functools
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
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
# Write "fixed-length A, then B later on the same line" as (?m)^(?=(.*?A))\1.*B, not A.*B: the lookahead does not
# backtrack, so only the first A of each line is tried and a long line repeating A stays linear to search.
RULES = [
    ("unit_failed", None, r"Failed with result|entered failed state"),
    ("oom", None, r"(?i)out of memory|oom-kill|invoked oom-killer"),
    ("disk_full", None, r"No space left on device"),
    ("io_error", None, r"(?i)I/O error|EXT4-fs error|BTRFS (error|critical)|critical medium error"),
    ("fs_readonly", None, r"(?im)^(?=(.*?remount))\1.*read-only"),
    ("kernel_crash", None, r"Kernel panic|kernel BUG|Oops:|general protection fault|Call Trace:"),
    ("crash", None, r"segfault at|dumped core"),
    ("hardware", None, r"(?im)hardware error|machine check events|^(?=(.*?\bEDAC\b))\1.*\berror"),
    ("undervoltage", None, r"(?i)under-?voltage"),
    ("thermal", None, r"(?i)temperature above threshold|thermal throttl"),
]

# (SYSLOG_IDENTIFIER or None, regex): selected regardless of priority.
ALWAYS_INCLUDE = [
    (None, r"^Startup finished in .*\(kernel\)"),  # system boots
]

# (SYSLOG_IDENTIFIER or None, regex): routine entries dropped before selection.
NOISE = [
    # ("sshd-session", r"^Connection closed by .* \[preauth\]$"),
    (None, r"^s6-rc: info: "),  # s6-overlay service start/stop in containers
    (None, r"^WARNING: COMMAND_FAILED: .*DOCKER"),  # firewalld cleanup of Docker chains
    (None, r"^WARNING: COMMAND_FAILED: '\S*ip6?tables -w10 -t nat -D (PREROUTING|OUTPUT)' failed: "),  # Docker restart
    (None, r"^ERROR: NAME_CONFLICT: new_policy_object\(\): 'docker-forwarding'"),  # Docker restart
    # aborted sudo password prompts (not anchored: some arrive with a garbled ident line before them)
    (None, r"pam_unix\(sudo(-i)?:auth\): "),
    (None, r"^error: mm_reap: (preauth )?child terminated"),
    (None, r"\A\s*\Z"),  # empty messages
    ("kernel", r"^\[UFW BLOCK\] "),  # firewall block logging
    ("kernel", r"^ (\? )?[\w.]+\+0x[0-9a-f]+/0x[0-9a-f]+"),  # stack trace frames
    ("kernel", r"^ </?TASK>$"),
    # register dump and context lines around a stack trace (the event itself is caught by RULES)
    (
        "kernel",
        (
            r"^(RIP|RSP|RAX|RDX|RBP|R10|R13|FS|CS|CR2|DR0|DR3|PKRU): |^Code: "
            r"|^CPU: \d+ (UID: \d+ )?PID: \d+ Comm: |^Hardware name: "
        ),
    ),
    # boot-time firmware, driver and CPU messages that are the same on every boot
    ("kernel", r"taints kernel\.$|inheriting taint\.$|^Disabling lock debugging due to kernel taint$"),
    ("kernel", r"^NVRM: loading NVIDIA UNIX "),
    (
        "kernel",
        (
            r"^ACPI BIOS Error \(bug\): Could not resolve symbol "
            r"|^ACPI Error: Aborting method .* due to previous error \(AE_NOT_FOUND\)"
            r"|^ACPI Warning: SystemIO range .* conflicts with OpRegion "
        ),
    ),
    ("kernel", r"admin-guide/hw-vuln/"),  # CPU vulnerability notices
    ("kernel", r"^ENERGY_PERF_BIAS: |^amd_pstate: the _CPC object is not present"),
    ("kernel", r": supply \w+ not found, using dummy regulator$"),
    ("kernel", r"^ata\d+\.\d+: (supports DRM functions|LPM support broken)"),
    ("kernel", r"^NOTICE: Automounting of tracing to debugfs is deprecated"),
    ("kernel", r"^asus_wmi: failed to register LPS0 sleep handler"),
    ("kernel", r"^device-mapper: core: CONFIG_IMA_DISABLE_HTABLE is disabled"),
    ("kernel", r"^kauditd_printk_skb: \d+ callbacks suppressed$"),
    (None, r"^lm_sensors\.service: Referenced but unset environment variable"),
    (None, r"^No swap; memory pressure usage will be degraded$"),  # systemd-oomd
    (None, r"Found matching \.network file, based on potentially unpredictable interface name"),
    (None, r"^Cannot change IRQ \d+ affinity: Permission denied$|^IRQ \d+ affinity is now unmanaged$"),
    # memory info dump after a page allocation failure
    (
        "kernel",
        (
            r"^(Mem-Info:|active_anon:|Node \d+ |lowmem_reserve\[\]:|\d+ total pagecache pages|\d+ pages "
            r"|Free swap |Total swap |Memory cgroup min protection )"
        ),
    ),
    (None, r"^/package/admin/s6-overlay/libexec/preinit: info: "),  # container startup
    (None, r'^\{"level":"info"'),  # JSON info logs from containers (logged at err)
]

# (regex, replacement): applied before the generic normalization below.
EXTRA_NORMALIZERS = [
    (r"(?i)\b(invalid user) \S*", r"\1 <USER>"),
    (r"\bveth[0-9a-f]{7}\b", "veth<ID>"),  # Docker veth interfaces
    (r"(?s)( dumped core\.).*", r"\1"),  # drop coredump stack traces (they differ per crash)
    (r"\b(cmd|res) [0-9a-f]{2}/[0-9a-f:/]+", r"\1 <REGS>"),  # libata taskfile register dumps
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
    # IPs first: RX_MAC and RX_TIME would eat groups of a valid IPv6 address. MACs and
    # clock times are not valid IPs, so ip_rep leaves them for the regexes below.
    msg = RX_IPV4.sub(ip_rep, msg)
    msg = RX_IPV6.sub(ip_rep, msg)
    msg = RX_MAC.sub("<MAC>", msg)  # before RX_TIME, which would match the last three octets
    msg = RX_TIME.sub("<TIME>", msg)
    msg = RX_UUID.sub("<UUID>", msg)
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
    return re.sub(r"\d+", "<N>", label)


def match_any(rules, ident, msg):
    return any((i is None or i == ident) and rx.search(msg) for i, rx in rules)


def fmt_ts(usec):
    return datetime.fromtimestamp(usec / 1_000_000).astimezone().isoformat(timespec="seconds")


# Longest source label shown in full: a valid unit name is under 256 characters (systemd UNIT_NAME_MAX), and
# source_of() replacing digits with <N> at most about doubles that.
SOURCE_LIMIT = 512


@functools.cache
def escape_table():
    """str.translate table that escapes control, format and line separator characters, except tab."""
    chars = (chr(c) for c in range(sys.maxunicode + 1))
    return {
        ord(ch): ch.encode("unicode_escape").decode("ascii")
        for ch in chars
        if ch != "\t" and unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")
    }


def printable(s):
    """s with control, format and line separator characters (such as CR and ESC) written as visible escapes."""
    return s if s.isprintable() else s.translate(escape_table())


def clip(s, limit):
    """printable(s) cut to limit characters, with " …" marking a cut."""
    # Escaping never shortens text, so escaping the first limit + 1 characters is enough.
    s = printable(s[: limit + 1])
    return s if len(s) <= limit else s[:limit] + " …"


def one_line(s, limit=400):
    return clip(s.replace("\n", " | "), limit)


# --- State files -------------------------------------------------------------


def read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def load_seen(path):
    """Read seen.json; a damaged file is reported and treated as empty, so the host keeps working."""
    try:
        seen = json.loads(read_file(path) or "{}")
    except ValueError as exc:  # also UnicodeDecodeError
        print(f"warning: ignoring damaged {path}: {exc}", file=sys.stderr)
        return {}
    if not isinstance(seen, dict):
        print(f"warning: ignoring damaged {path}: not a JSON object", file=sys.stderr)
        return {}
    return seen


def write_atomic(path, content):
    """Write content to path via a uniquely named temporary file, flushed to disk before os.replace."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with open(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


# --- Main processing ---------------------------------------------------------


def journal_command(host, since, cursor):
    """Return the journalctl command and the report's mode description."""
    # --all: without it, fields over 4096 bytes (e.g. coredump stack traces) are output as null.
    cmd = ["journalctl", "--output=json", "--all", "--no-pager", "--quiet"] + HOSTS[host]
    if since is not None:
        return cmd + [f"--since={since}"], f"preview (since {since}; state not updated)"
    if cursor:
        return cmd + [f"--after-cursor={cursor}"], "normal (after saved cursor)"
    return cmd + [f"--since={INITIAL_SINCE}"], f"normal (first run, since {INITIAL_SINCE})"


def entry_priority(entry):
    try:
        return int(text(entry.get("PRIORITY")))
    except (TypeError, ValueError):
        return 6


def classify(ident, msg, prio):
    """Apply RULES, NOISE and priority selection, in that order.

    Returns (matched rule names, "selected" | "noise" | "skipped").
    """
    rules = [name for name, i, rx in RULES_RX if (i is None or i == ident) and rx.search(msg)]
    if rules:
        return rules, "selected"
    if match_any(NOISE_RX, ident, msg):
        return rules, "noise"
    if prio > MAX_PRIORITY and not match_any(ALWAYS_RX, ident, msg):
        return rules, "skipped"
    return rules, "selected"


def add_entry(patterns, entry, ident, msg, prio, ts, rules):
    source = source_of(entry, ident)
    template, ips = normalize(msg)
    key = hashlib.sha1(f"{source}\0{template}".encode()).hexdigest()[:16]
    p = patterns.get(key)
    if p is None:
        p = patterns[key] = {
            "source": source,
            "template": template,
            "example": msg,
            "prio": prio,
            "count": 0,
            "first": ts,
            "last": ts,
            "rules": set(),
            "ips": Counter(),
        }
    p["count"] += 1
    p["last"] = ts
    p["prio"] = min(p["prio"], prio)
    p["rules"].update(rules)
    p["ips"].update(ips)


def read_journal(cmd):
    """Run journalctl and aggregate the selected entries into patterns."""
    stats = {
        "patterns": {},
        "by_prio": Counter(),
        "total": 0,
        "noise": 0,
        "first_ts": None,
        "last_ts": None,
        "last_cursor": None,
    }
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    for line in proc.stdout:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        stats["total"] += 1
        stats["last_cursor"] = entry.get("__CURSOR", stats["last_cursor"])
        ts = int(entry.get("__REALTIME_TIMESTAMP", 0))
        if stats["first_ts"] is None:
            stats["first_ts"] = ts
        stats["last_ts"] = ts
        prio = entry_priority(entry)
        stats["by_prio"][prio] += 1

        msg = text(entry.get("MESSAGE")) or ""
        ident = text(entry.get("SYSLOG_IDENTIFIER")) or text(entry.get("_COMM")) or ""
        rules, verdict = classify(ident, msg, prio)
        if verdict == "noise":
            stats["noise"] += 1
        elif verdict == "selected":
            add_entry(stats["patterns"], entry, ident, msg, prio, ts, rules)

    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"journalctl exited with status {proc.returncode}")
    return stats


def sort_key(key, p, new_keys):
    """Rule matches first, then new patterns, then by priority and count."""
    return (0 if p["rules"] else 1, 0 if key in new_keys else 1, p["prio"], -p["count"])


def pattern_lines(key, p, new_keys):
    tags = [f"[rule:{r}]" for r in sorted(p["rules"])]
    if key in new_keys:
        tags.append("[NEW]")
    prio_name = PRIO_NAMES[p["prio"]] if 0 <= p["prio"] < 8 else str(p["prio"])
    # A newline in the source is shown as \n, not as a " | " line break as in messages.
    head = " ".join(tags + [prio_name, clip(p["source"], SOURCE_LIMIT), f"x{p['count']}"])
    lines = [
        f"{head}  {fmt_ts(p['first'])} -> {fmt_ts(p['last'])}",
        f"  pattern: {one_line(p['template'])}",
        f"  example: {one_line(p['example'])}",
    ]
    if p["ips"]:
        top = ", ".join(f"{ip} x{n}" for ip, n in p["ips"].most_common(5))
        lines.append(f"  top IPs: {top} ({len(p['ips'])} distinct)")
    return lines


def render_report(host, mode, stats, seen, new_keys):
    """Return the full report text, footer included."""
    patterns = stats["patterns"]
    selected = sum(p["count"] for p in patterns.values())
    rule_count = sum(1 for p in patterns.values() if p["rules"])
    if stats["total"]:
        range_line = f"range: {fmt_ts(stats['first_ts'])} -> {fmt_ts(stats['last_ts'])}"
    else:
        range_line = "range: no entries"
    by_prio = stats["by_prio"]
    prio_text = " ".join(f"{PRIO_NAMES[i]}={by_prio[i]}" for i in range(8) if by_prio[i])
    out = [
        f"=== {host} ===",
        f"mode: {mode}",
        range_line,
        f"entries read: {stats['total']}  ({prio_text or 'none'})",
        f"dropped as noise: {stats['noise']}",
        f"selected: {selected} entries in {len(patterns)} patterns ({rule_count} with rule matches, {len(new_keys)} new)",
    ]
    if not seen:
        out.append("note: no saved patterns for this host yet, so every pattern is marked new")
    out.append("")
    new = set(new_keys)  # checked once per pattern in each of two passes: a list would make this quadratic
    for k, p in sorted(patterns.items(), key=lambda item: sort_key(*item, new)):
        out.extend(pattern_lines(k, p, new))
    report = "\n".join(out)
    return f"{report}\nreport size: {len(report)} characters\n"


def save_state(seen, new_keys, seen_path, cursor_path, last_cursor):
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    for k in new_keys:
        seen[k] = now
    write_atomic(seen_path, json.dumps(seen, indent=0))
    if last_cursor:
        write_atomic(cursor_path, last_cursor)


def process_host(host, since, state_dir, report_dir):
    host_dir = os.path.join(state_dir, host)
    cursor_path = os.path.join(host_dir, "cursor")
    seen_path = os.path.join(host_dir, "seen.json")
    preview = since is not None

    cmd, mode = journal_command(host, since, None if preview else read_file(cursor_path))
    seen = load_seen(seen_path)
    stats = read_journal(cmd)
    new_keys = [k for k in stats["patterns"] if k not in seen]

    full = render_report(host, mode, stats, seen, new_keys)
    if report_dir:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        write_atomic(os.path.join(report_dir, host, f"{stamp}.txt"), full)
    else:
        print(full)

    # Save state in normal mode only, after the report was produced.
    if not preview:
        save_state(seen, new_keys, seen_path, cursor_path, stats["last_cursor"])


def main():
    ap = argparse.ArgumentParser(description="Condense journald logs per host into patterns.")
    ap.add_argument("hosts", nargs="*", help=f"hosts to process (default: all of {', '.join(HOSTS)})")
    ap.add_argument(
        "--since", help="preview a time window (journalctl --since syntax) without using or updating saved state"
    )
    ap.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help=f"state directory (default: {DEFAULT_STATE_DIR})")
    ap.add_argument("--report-dir", help="write each report to REPORT_DIR/<host>/<timestamp>.txt instead of stdout")
    args = ap.parse_args()
    if args.since and args.report_dir:
        ap.error("--report-dir cannot be used with --since")

    hosts = args.hosts or list(HOSTS)
    unknown = [h for h in hosts if h not in HOSTS]
    if unknown:
        ap.error(f"unknown host(s): {', '.join(unknown)}")

    status = 0
    for host in hosts:
        try:
            process_host(host, args.since, args.state_dir, args.report_dir)
        except Exception as exc:  # noqa: BLE001 - report any failure and continue with the other hosts
            print(f"{host}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
