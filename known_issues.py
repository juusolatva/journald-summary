#!/usr/bin/env python3
"""known_issues: build the known issues file for analyze.py from earlier analyses.

Reads the analysis files that analyze.py wrote, collects the issues the model
did not mark [known] and asks about them one at a time: add a line for the
issue to the known issues file, decline it, or skip it for now. Added and
declined issues are remembered in a reviewed file next to the known issues
file, so later runs ask only about issues not answered yet.
"""

import argparse
import os
import re
import sys
import textwrap
from datetime import datetime, timedelta

try:
    import readline  # prefills the line to edit; input() works without it
except ImportError:  # pragma: no cover - readline is missing only on some platforms
    readline = None

# --- Configuration -----------------------------------------------------------

DEFAULT_REPORT_DIR = "/var/lib/logfilter/reports"
KNOWN_ISSUES = "/etc/logfilter/known-issues.txt"

# Default for --days: only analyses of reports this many days old or newer are read.
DEFAULT_DAYS = 7

# Width of the issue details shown for each question.
WRAP = 78

SEVERITIES = ["critical", "high", "medium", "low"]

ANALYSIS_NAME = re.compile(r"^(\d{8}-\d{6})\.analysis\.txt$")

# Issue heading written by analyze.py's render(): [severity], optional [known], title.
ISSUE_LINE = re.compile(r"^\[(critical|high|medium|low)\]( \[known\])? (.*)$")

PROMPT = "Add to known issues? [y]es, [n]o, [e]dit, [s]kip, [q]uit: "

# --- Analyses ----------------------------------------------------------------


def norm(title):
    """Comparison form of an issue title: lower case, whitespace collapsed."""
    return " ".join(title.lower().split())


def parse_analysis(text):
    """(model, issues) of an analysis file; each issue has severity, known, title and details."""
    model, issues = None, []
    for line in text.splitlines():
        m = ISSUE_LINE.match(line)
        if m:
            issues.append({"severity": m[1], "known": bool(m[2]), "title": m[3], "details": ""})
        elif line.startswith("  ") and issues:
            issues[-1]["details"] = line[2:]
        elif line.startswith("model: ") and model is None:
            model = line.removeprefix("model: ")
    return model, issues


def analyses(report_dir, host, since):
    """Yield (stamp, text) of the host's analysis files whose report time is since or later, oldest first."""
    directory = os.path.join(report_dir, host)
    for name in sorted(os.listdir(directory)):
        m = ANALYSIS_NAME.match(name)
        if not m:
            continue
        try:
            if datetime.strptime(m[1], "%Y%m%d-%H%M%S") < since:
                continue
            with open(os.path.join(directory, name), encoding="utf-8", errors="replace") as f:
                yield m[1], f.read()
        except (ValueError, OSError) as exc:  # impossible date in the name, unreadable file
            print(f"{host}/{name}: skipped: {exc}", file=sys.stderr)


def add_issues(found, skip, host, stamp, issues):
    """Add one analysis's issues to found (oldest analysis first, so the latest details win)."""
    for issue in issues:
        key = (host, norm(issue["title"]))
        if issue["known"]:  # the known issues file already covers it, also in earlier reports
            skip.add(key)
            found.pop(key, None)
        if key in skip:
            continue
        cand = found.setdefault(key, {"host": host, "stamps": set()})
        cand.update(issue, last=stamp)
        cand["stamps"].add(stamp)


def collect(report_dir, hosts, since, reviewed):
    """Issues not reviewed yet and not marked known in any report, one per host and title, latest details."""
    found, skip = {}, set(reviewed)
    for host in hosts:
        for stamp, text in analyses(report_dir, host, since):
            model, issues = parse_analysis(text)
            if model not in (None, "-"):  # without the model (analyze.py wrote it), known issues do not apply
                add_issues(found, skip, host, stamp, issues)
    return sorted(
        found.values(), key=lambda c: (c["host"], SEVERITIES.index(c["severity"]), -len(c["stamps"]), norm(c["title"]))
    )


# --- Files -------------------------------------------------------------------


def load_reviewed(path):
    """(host, normalized title) pairs of a reviewed file with "<host>: <title>" lines; missing file means none."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = [s for s in (line.strip() for line in f) if s and not s.startswith("#")]
    except FileNotFoundError:
        return set()
    return {(host, norm(title)) for host, _, title in (s.partition(": ") for s in lines)}


def append_line(path, line):
    """Append one line, first ending an unterminated last line so the two are not joined."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "ab+") as f:
        if f.seek(0, os.SEEK_END):
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                f.write(b"\n")
        f.write(line.encode("utf-8") + b"\n")


# --- Questions ---------------------------------------------------------------


def show(n, total, cand):
    count = len(cand["stamps"])
    last = f"{cand['last'][:4]}-{cand['last'][4:6]}-{cand['last'][6:8]}"
    print(f"\n[{n}/{total}] {cand['host']}, {count} report{'s' * (count != 1)}, last {last}")
    print(f"[{cand['severity']}] {cand['title']}")
    for line in textwrap.wrap(cand["details"], WRAP - 2):
        print(f"  {line}")


def edit(ask, default):
    """The line to add, prefilled with default where readline can do it. Empty cancels."""
    if readline:
        readline.set_startup_hook(lambda: readline.insert_text(default))
    try:
        return " ".join(ask("Line (empty to cancel): ").split())
    finally:
        if readline:
            readline.set_startup_hook()


def ask_one(cand, ask):
    """Ask about one issue until the answer is valid. Returns (action, known issues line or None)."""
    default = f"{cand['host']}: {cand['title']}"
    actions = {"n": "decline", "no": "decline", "s": "skip", "skip": "skip", "q": "quit", "quit": "quit"}
    while True:
        answer = ask(PROMPT).strip().lower()
        if answer in ("y", "yes"):
            return "add", default
        if answer in ("e", "edit"):
            line = edit(ask, default)
            if line:
                return "add", line
        elif answer in actions:
            return actions[answer], None
        else:
            print("Answer y, n, e, s or q.")


def review(cands, known_path, reviewed_path, ask=input):
    """Ask about each issue in turn and save each answer at once. Returns counts per action."""
    counts = {"add": 0, "decline": 0, "skip": 0}
    for n, cand in enumerate(cands, 1):
        show(n, len(cands), cand)
        try:
            action, line = ask_one(cand, ask)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if action == "quit":
            break
        if action == "add":
            append_line(known_path, line)
            print(f"Added: {line}")
        if action != "skip":
            append_line(reviewed_path, f"{cand['host']}: {cand['title']}")
        counts[action] += 1
    return counts


# --- Main processing ---------------------------------------------------------


def report_hosts(ap, args):
    """The named hosts, or every directory in the report directory (none if it is missing)."""
    if args.hosts:
        unknown = [h for h in args.hosts if not os.path.isdir(os.path.join(args.report_dir, h))]
        if unknown:
            ap.error(f"no report directory for host(s): {', '.join(unknown)}")
        return args.hosts
    try:
        names = os.listdir(args.report_dir)
    except FileNotFoundError:
        return []
    except OSError as exc:
        ap.error(f"cannot read report directory: {exc}")
    return sorted(d for d in names if os.path.isdir(os.path.join(args.report_dir, d)))


def main():
    ap = argparse.ArgumentParser(description="Pick known issues for analyze.py from earlier analyses.")
    ap.add_argument("hosts", nargs="*", help="hosts to review (default: every directory in the report directory)")
    ap.add_argument(
        "--report-dir", default=DEFAULT_REPORT_DIR, help=f"report directory (default: {DEFAULT_REPORT_DIR})"
    )
    ap.add_argument("--known-issues", default=KNOWN_ISSUES, help=f"known issues file (default: {KNOWN_ISSUES})")
    ap.add_argument(
        "--reviewed", help="file of issues already answered (default: the known issues file with .reviewed suffix)"
    )
    ap.add_argument(
        "--days", type=int, default=DEFAULT_DAYS, help=f"read reports this many days back (default: {DEFAULT_DAYS})"
    )
    args = ap.parse_args()
    if args.days < 0:
        ap.error("--days must not be negative")
    reviewed_path = args.reviewed or os.path.splitext(args.known_issues)[0] + ".reviewed"

    hosts = report_hosts(ap, args)
    since = datetime.now() - timedelta(days=args.days)
    cands = collect(args.report_dir, hosts, since, load_reviewed(reviewed_path))
    if not cands:
        print("No issues to review.")
        return
    print(f"{len(cands)} issue(s) to review. Added lines go to {args.known_issues}.")
    counts = review(cands, args.known_issues, reviewed_path)
    left = len(cands) - sum(counts.values())
    print(f"Added {counts['add']}, declined {counts['decline']}, skipped {counts['skip']}, {left} not reached.")


if __name__ == "__main__":
    main()
