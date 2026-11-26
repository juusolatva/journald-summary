import contextlib
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import known_issues

# --- Synthetic data ----------------------------------------------------------


def stamp(days_ago):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y%m%d-%H%M%S")


def analysis(host, st, issues, model="gemma4:e4b"):
    """Analysis text in analyze.py's render() format; issues are (severity, known, title, details)."""
    lines = [f"=== {host} {st} ===", f"model: {model}", "chunks: 1", "summary: Synthetic summary.", ""]
    if not issues:
        lines.append("no issues")
    for severity, known, title, details in issues:
        lines.append(f"[{severity}]" + (" [known]" if known else "") + f" {title}")
        lines.append(f"  {details}")
    return "\n".join(lines) + "\n"


class Dirs(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.reports = os.path.join(tmp.name, "reports")
        self.known = os.path.join(tmp.name, "etc", "known-issues.txt")
        self.reviewed = os.path.join(tmp.name, "etc", "known-issues.reviewed")

    def write(self, host, name, text):
        os.makedirs(os.path.join(self.reports, host), exist_ok=True)
        with open(os.path.join(self.reports, host, name), "w", encoding="utf-8") as f:
            f.write(text)

    def add(self, host, days_ago, issues, model="gemma4:e4b"):
        st = stamp(days_ago)
        self.write(host, f"{st}.analysis.txt", analysis(host, st, issues, model))
        return st

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()


# --- Analyses ----------------------------------------------------------------


class ParseTest(unittest.TestCase):
    def test_issues_and_model(self):
        text = analysis(
            "palvelin",
            "20261007-000000",
            [("high", False, "backup.service failed", "Failed once."), ("low", True, "Clock drift", "Twice.")],
        )
        model, issues = known_issues.parse_analysis(text)
        self.assertEqual(model, "gemma4:e4b")
        self.assertEqual(
            issues,
            [
                {"severity": "high", "known": False, "title": "backup.service failed", "details": "Failed once."},
                {"severity": "low", "known": True, "title": "Clock drift", "details": "Twice."},
            ],
        )

    def test_no_issues(self):
        model, issues = known_issues.parse_analysis(analysis("palvelin", "20261007-000000", []))
        self.assertEqual((model, issues), ("gemma4:e4b", []))

    def test_summary_is_not_an_issue(self):
        text = "=== h s ===\nmodel: m\nchunks: 1\nsummary: [high] looks like a heading\n\nno issues\n"
        self.assertEqual(known_issues.parse_analysis(text), ("m", []))

    def test_norm(self):
        self.assertEqual(known_issues.norm("  Disk  Space\tExhaustion "), "disk space exhaustion")


class CollectTest(Dirs):
    def collect(self, days=7, reviewed=frozenset(), hosts=("palvelin",)):
        return known_issues.collect(self.reports, list(hosts), datetime.now() - timedelta(days=days), reviewed)

    def test_groups_by_title_with_latest_details(self):
        self.add("palvelin", 3, [("high", False, "ATA errors on ata1", "Old details.")])
        last = self.add("palvelin", 1, [("critical", False, "ata  errors ON ata1", "New details.")])
        (cand,) = self.collect()
        self.assertEqual(cand["host"], "palvelin")
        self.assertEqual(cand["title"], "ata  errors ON ata1")
        self.assertEqual(cand["details"], "New details.")
        self.assertEqual(cand["severity"], "critical")
        self.assertEqual(cand["last"], last)
        self.assertEqual(len(cand["stamps"]), 2)

    def test_skips_known_reviewed_old_and_model_less(self):
        self.add("palvelin", 1, [("high", True, "Known one", "d"), ("high", False, "Reviewed one", "d")])
        self.add("palvelin", 2, [("high", False, "No journal entries received", "d")], model="-")
        self.add("palvelin", 10, [("high", False, "Too old", "d")])
        self.add("palvelin", 1, [("low", False, "Fresh", "d")])
        got = self.collect(reviewed={("palvelin", "reviewed one")})
        self.assertEqual([c["title"] for c in got], ["Fresh"])

    def test_known_in_any_report_is_skipped(self):
        self.add("palvelin", 3, [("high", False, "Known later", "d")])
        self.add("palvelin", 2, [("high", True, "known  LATER", "d")])
        self.add("palvelin", 1, [("high", False, "Known later", "d"), ("low", False, "Other", "d")])
        self.assertEqual([c["title"] for c in self.collect()], ["Other"])

    def test_ignores_other_files(self):
        self.write("palvelin", f"{stamp(1)}.txt", analysis("palvelin", "x", [("high", False, "Report", "d")]))
        self.write("palvelin", "notes.analysis.txt", analysis("palvelin", "x", [("high", False, "Notes", "d")]))
        self.assertEqual(self.collect(), [])

    def test_impossible_date_is_skipped(self):
        self.write("palvelin", "20261399-000000.analysis.txt", analysis("palvelin", "x", [("high", False, "T", "d")]))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.collect(), [])
        self.assertIn("20261399-000000.analysis.txt: skipped", err.getvalue())

    def test_same_title_on_two_hosts_stays_separate_and_order(self):
        self.add("vakoilu", 1, [("low", False, "Swap warning", "d")])
        self.add("palvelin", 1, [("low", False, "Swap warning", "d"), ("critical", False, "Zebra", "d")])
        self.add("palvelin", 2, [("low", False, "Alpha", "d"), ("low", False, "Swap warning", "d")])
        got = self.collect(hosts=("palvelin", "vakoilu"))
        self.assertEqual(
            [(c["host"], c["title"]) for c in got],
            [("palvelin", "Zebra"), ("palvelin", "Swap warning"), ("palvelin", "Alpha"), ("vakoilu", "Swap warning")],
        )


# --- Files -------------------------------------------------------------------


class FilesTest(Dirs):
    def test_load_reviewed(self):
        self.assertEqual(known_issues.load_reviewed(self.reviewed), set())
        known_issues.append_line(self.reviewed, "palvelin: Disk  Space Exhaustion")
        known_issues.append_line(self.reviewed, "# comment")
        known_issues.append_line(self.reviewed, "vakoilu: a: b")
        self.assertEqual(
            known_issues.load_reviewed(self.reviewed), {("palvelin", "disk space exhaustion"), ("vakoilu", "a: b")}
        )

    def test_append_creates_directory_and_ends_last_line(self):
        known_issues.append_line(self.known, "first")
        self.assertEqual(self.read(self.known), "first\n")
        with open(self.known, "a", encoding="utf-8") as f:
            f.write("hand-written, no newline")
        known_issues.append_line(self.known, "äöå second")
        self.assertEqual(self.read(self.known), "first\nhand-written, no newline\näöå second\n")


# --- Questions ---------------------------------------------------------------


def answers(*replies):
    it = iter(replies)

    def ask(prompt):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    return ask


def cand(title="Disk Space Exhaustion", host="palvelin"):
    return {
        "host": host,
        "title": title,
        "severity": "critical",
        "details": "d " * 60,
        "last": "20261125-000000",
        "stamps": {"20261125-000000"},
    }


class ReviewTest(Dirs):
    def review(self, cands, *replies):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            counts = known_issues.review(cands, self.known, self.reviewed, answers(*replies))
        return counts, out.getvalue()

    def test_add_decline_edit_skip(self):
        cands = [cand("A"), cand("B"), cand("C"), cand("D", host="vakoilu")]
        counts, out = self.review(cands, "y", "n", "huh", "e", "", "E", "  palvelin:  my   line ", "s")
        self.assertEqual(counts, {"add": 2, "decline": 1, "skip": 1})
        self.assertEqual(self.read(self.known), "palvelin: A\npalvelin: my line\n")
        self.assertEqual(self.read(self.reviewed), "palvelin: A\npalvelin: B\npalvelin: C\n")
        self.assertIn("Answer y, n, e, s or q.", out)
        self.assertIn("[1/4] palvelin, 1 report, last 2026-11-25", out)
        self.assertIn("Added: palvelin: my line", out)
        self.assertTrue(all(len(line) <= known_issues.WRAP for line in out.splitlines()))

    def test_quit_and_eof_stop_without_saving(self):
        counts, _ = self.review([cand("A"), cand("B")], "q")
        self.assertEqual(counts, {"add": 0, "decline": 0, "skip": 0})
        counts, _ = self.review([cand("A"), cand("B")], "yes")
        self.assertEqual(counts["add"], 1)
        self.assertEqual(self.read(self.known), "palvelin: A\n")  # EOF at B stopped the run
        self.assertEqual(self.read(self.reviewed), "palvelin: A\n")

    def test_ctrl_c_stops(self):
        def ask(prompt):
            raise KeyboardInterrupt

        with contextlib.redirect_stdout(io.StringIO()):
            counts = known_issues.review([cand()], self.known, self.reviewed, ask)
        self.assertEqual(counts, {"add": 0, "decline": 0, "skip": 0})
        self.assertFalse(os.path.exists(self.known))


# --- Main processing ---------------------------------------------------------


class MainTest(Dirs):
    def run_main(self, *args, stdin=""):
        argv = ["known_issues.py", "--report-dir", self.reports, "--known-issues", self.known, *args]
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(sys, "stdin", io.StringIO(stdin)),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            try:
                known_issues.main()
                status = 0
            except SystemExit as exc:
                status = exc.code
        return status, out.getvalue(), err.getvalue()

    def test_second_run_asks_only_new_issues(self):
        self.add("palvelin", 1, [("high", False, "A", "d"), ("low", False, "B", "d")])
        status, out, _ = self.run_main(stdin="y\n")
        self.assertEqual(status, 0)
        self.assertIn("2 issue(s) to review", out)
        self.assertIn("Added 1, declined 0, skipped 0, 1 not reached.", out)
        self.assertEqual(self.read(self.known), "palvelin: A\n")
        self.assertEqual(self.read(self.reviewed), "palvelin: A\n")
        _, out, _ = self.run_main(stdin="n\n")
        self.assertIn("1 issue(s) to review", out)
        self.assertIn("[low] B", out)
        _, out, _ = self.run_main()
        self.assertIn("No issues to review.", out)

    def test_reviewed_option_and_days(self):
        self.add("palvelin", 20, [("high", False, "Old", "d")])
        other = os.path.join(self.tmp, "answered.txt")
        _, out, _ = self.run_main("--reviewed", other, stdin="n\n")
        self.assertIn("No issues to review.", out)
        self.run_main("--reviewed", other, "--days", "30", stdin="n\n")
        self.assertEqual(self.read(other), "palvelin: Old\n")
        self.assertFalse(os.path.exists(self.reviewed))

    def test_hosts_argument(self):
        self.add("palvelin", 1, [("high", False, "P", "d")])
        self.add("vakoilu", 1, [("high", False, "V", "d")])
        _, out, _ = self.run_main("vakoilu", stdin="q\n")
        self.assertIn("1 issue(s) to review", out)
        self.assertIn("[high] V", out)

    def test_errors(self):
        os.makedirs(self.reports)
        status, _, err = self.run_main("nosuchhost")
        self.assertEqual(status, 2)
        self.assertIn("no report directory for host(s): nosuchhost", err)
        status, _, err = self.run_main("--days", "-1")
        self.assertEqual(status, 2)
        self.assertIn("--days must not be negative", err)

    def test_report_dir_missing_or_not_a_directory(self):
        status, out, _ = self.run_main()
        self.assertEqual((status, out), (0, "No issues to review.\n"))
        with open(self.reports, "w", encoding="utf-8") as f:
            f.write("not a directory")
        status, _, err = self.run_main()
        self.assertEqual(status, 2)
        self.assertIn("cannot read report directory", err)


if __name__ == "__main__":
    unittest.main()
