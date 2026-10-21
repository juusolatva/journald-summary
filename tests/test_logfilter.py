import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logfilter

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logfilter.py")

BASE_TS = 1760000000000000  # microseconds

FAKE_JOURNALCTL = """#!{python}
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
with open(os.path.join(here, "args.log"), "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\\n")

host = "palvelin"
after = None
for a in args:
    if a.startswith("_HOSTNAME="):
        host = a.split("=", 1)[1]
    elif a.startswith("--after-cursor="):
        after = a.split("=", 1)[1]

path = os.path.join(here, f"entries-{{host}}.json")
entries = []
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)

if after is not None:
    for i, e in enumerate(entries):
        if isinstance(e, dict) and e.get("__CURSOR") == after:
            entries = entries[i + 1:]
            break

for e in entries:
    print(e if isinstance(e, str) else json.dumps(e))
sys.stdout.flush()

if host == os.environ.get("FAKE_FAIL_HOST"):
    sys.exit(3)
"""


def entry(n, msg, prio=4, ident="app", unit="app.service", **extra):
    e = {
        "__CURSOR": f"s=synthetic;i={n:x}",
        "__REALTIME_TIMESTAMP": str(BASE_TS + n * 1_000_000),
        "MESSAGE": msg,
        "SYSLOG_IDENTIFIER": ident,
        "_TRANSPORT": "syslog",
        "_HOSTNAME": "palvelin",
    }
    if prio is not None:
        e["PRIORITY"] = str(prio)
    if unit is not None:
        e["_SYSTEMD_UNIT"] = unit
    e.update(extra)
    return e


def kernel(n, msg, prio=4, **extra):
    return entry(n, msg, prio=prio, ident="kernel", unit=None, _TRANSPORT="kernel", **extra)


def journalctl_calls(bin_dir):
    """Argument lists of the fake journalctl calls logged in bin_dir."""
    path = os.path.join(bin_dir, "args.log")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


# --- Unit tests --------------------------------------------------------------


class NormalizeTest(unittest.TestCase):
    def norm(self, msg):
        return logfilter.normalize(msg)

    def test_ipv4(self):
        self.assertEqual(self.norm("connect from 192.0.2.10 port 22"), ("connect from <IP> port <N>", ["192.0.2.10"]))
        self.assertEqual(self.norm("to 203.0.113.5:443"), ("to <IP>:<N>", ["203.0.113.5"]))

    def test_ipv6(self):
        self.assertEqual(self.norm("peer 2001:db8::1 up"), ("peer <IP> up", ["2001:db8::1"]))
        self.assertEqual(self.norm("peer [2001:db8:1::25]:443"), ("peer [<IP>]:<N>", ["2001:db8:1::25"]))
        self.assertEqual(self.norm("x 2001:db8:0:0:1:2:3:4 y"), ("x <IP> y", ["2001:db8:0:0:1:2:3:4"]))
        self.assertEqual(self.norm("listening on ::"), ("listening on <IP>", ["::"]))

    def test_ip_list_with_duplicates(self):
        _, ips = self.norm("a 192.0.2.1 b 2001:db8::5 c 192.0.2.1 d 198.51.100.2")
        self.assertEqual(sorted(ips), sorted(["192.0.2.1", "192.0.2.1", "198.51.100.2", "2001:db8::5"]))

    def test_invalid_ip_like_strings_not_ip(self):
        tpl, ips = self.norm("version 300.1.2.3")
        self.assertEqual(ips, [])
        self.assertNotIn("<IP>", tpl)
        tpl, ips = self.norm("value dead:beef:cafe here")
        self.assertEqual((tpl, ips), ("value dead:beef:cafe here", []))
        tpl, ips = self.norm("std::vector failed")
        self.assertEqual((tpl, ips), ("std::vector failed", []))

    def test_mac_before_time(self):
        self.assertEqual(self.norm("lease aa:bb:cc:11:22:33 renewed"), ("lease <MAC> renewed", []))
        self.assertEqual(self.norm("lease 00:11:22:33:44:55"), ("lease <MAC>", []))

    def test_uuid(self):
        self.assertEqual(self.norm("mount 123e4567-e89b-12d3-a456-426614174000 ok"), ("mount <UUID> ok", []))
        self.assertEqual(self.norm("id 12345678-1234-1234-1234-123456789ABC"), ("id <UUID>", []))

    def test_hex(self):
        self.assertEqual(self.norm("at 0x1F and 0xdeadbeef"), ("at <HEX> and <HEX>", []))
        self.assertEqual(self.norm("hash a1b2c3d4e5"), ("hash <HEX>", []))
        # bare hex needs at least one digit and one letter and length >= 8
        self.assertEqual(self.norm("word deadbeef"), ("word deadbeef", []))
        self.assertEqual(self.norm("short a1b2c3"), ("short a1b2c3", []))
        self.assertEqual(self.norm("num 12345678"), ("num <N>", []))

    def test_numbers(self):
        self.assertEqual(self.norm("took 1500ms, 3.5GHz, 512MB, 42"), ("took <N>, <N>, <N>, <N>", []))
        self.assertEqual(self.norm("on sda1 eth0"), ("on sda1 eth0", []))
        self.assertEqual(self.norm("version 1.2.3"), ("version <N>", []))

    def test_timestamps(self):
        self.assertEqual(self.norm("at 2026-10-21T10:20:30.123+03:00 x"), ("at <TIME> x", []))
        self.assertEqual(self.norm("at 2026-10-21 10:20:30Z x"), ("at <TIME> x", []))
        self.assertEqual(self.norm("at 10:20:30 x"), ("at <TIME> x", []))
        self.assertEqual(self.norm("at 9:05:01.5 x"), ("at <TIME> x", []))

    def test_ipv6_with_decimal_groups_not_eaten_by_time(self):
        self.assertEqual(self.norm("from 2001:db8::12:34:56 port 22"), ("from <IP> port <N>", ["2001:db8::12:34:56"]))

    def test_ipv6_with_two_char_groups_not_eaten_by_mac(self):
        self.assertEqual(
            self.norm("peer 2001:db8:aa:bb:cc:dd:ee:ff up"), ("peer <IP> up", ["2001:db8:aa:bb:cc:dd:ee:ff"])
        )


class ExtraNormalizersTest(unittest.TestCase):
    def test_invalid_user(self):
        self.assertEqual(
            logfilter.normalize("Invalid user someone from 192.0.2.7 port 2222"),
            ("Invalid user <USER> from <IP> port <N>", ["192.0.2.7"]),
        )

    def test_veth(self):
        self.assertEqual(
            logfilter.normalize("veth1a2b3c4: entered promiscuous mode")[0], "veth<ID>: entered promiscuous mode"
        )

    def test_dumped_core_truncated(self):
        msg = "Process 4321 (worker) of user 1000 dumped core.\n\nStack trace of thread 4321:\n#0 0x00007f in foo"
        self.assertEqual(logfilter.normalize(msg)[0], "Process <N> (worker) of user <N> dumped core.")

    def test_libata_regs(self):
        msg = "ata1.00: cmd 60/08:00:00:00:00/00:00:00:00:00/40 tag 0 ncq dma 4096 in"
        self.assertEqual(logfilter.normalize(msg)[0], "ata1.<N>: cmd <REGS> tag <N> ncq dma <N> in")
        msg = "ata1.00: status: { DRDY ERR } res 41/40:00:00:00:00/00:00:00:00:00/00 Emask 0x9"
        self.assertEqual(logfilter.normalize(msg)[0], "ata1.<N>: status: { DRDY ERR } res <REGS> Emask <HEX>")


class HelpersTest(unittest.TestCase):
    def test_text(self):
        self.assertIsNone(logfilter.text(None))
        self.assertEqual(logfilter.text("plain"), "plain")
        self.assertEqual(logfilter.text(list(b"hi there")), "hi there")
        self.assertEqual(logfilter.text([0xFF, 0x41]), "�A")
        self.assertEqual(logfilter.text(["first", "second"]), "first")
        self.assertIsNone(logfilter.text([]))
        self.assertEqual(logfilter.text(5), "5")

    def test_source_of(self):
        so = logfilter.source_of
        self.assertEqual(so({"_TRANSPORT": "kernel", "_SYSTEMD_UNIT": "x.service"}, "kernel"), "kernel")
        self.assertEqual(so({"_SYSTEMD_UNIT": "nginx.service"}, "nginx"), "nginx.service")
        self.assertEqual(so({"_SYSTEMD_UNIT": "init.scope"}, "systemd"), "systemd")
        self.assertEqual(so({"_SYSTEMD_USER_UNIT": "app.service"}, "app"), "app.service")
        self.assertEqual(so({"_SYSTEMD_UNIT": "session-12.scope"}, "sshd"), "session-<N>.scope")
        self.assertEqual(so({}, "worker2"), "worker<N>")
        self.assertEqual(so({}, ""), "unknown")
        self.assertEqual(so({"_SYSTEMD_UNIT": ["a1.service", "b.service"]}, "x"), "a<N>.service")

    def test_one_line(self):
        self.assertEqual(logfilter.one_line("a\nb\nc"), "a | b | c")
        self.assertEqual(logfilter.one_line("x" * 400), "x" * 400)
        self.assertEqual(logfilter.one_line("x" * 401), "x" * 400 + " …")
        self.assertEqual(logfilter.one_line("abcdef", limit=3), "abc …")


class RulesTest(unittest.TestCase):
    SAMPLES = types.MappingProxyType(
        {
            "unit_failed": "app.service: Failed with result 'exit-code'.",
            "oom": "Out of memory: Killed process 1234 (worker)",
            "disk_full": "write failed: No space left on device",
            "io_error": "blk_update_request: I/O error, dev sdz, sector 2048",
            "fs_readonly": "EXT4-fs (sdz1): Remounting filesystem read-only",
            "kernel_crash": "Kernel panic - not syncing: Fatal exception",
            "crash": "worker[1234]: segfault at 0 ip 00005 sp 00007 error 4",
            "hardware": "mce: [Hardware Error]: Machine check events logged",
            "undervoltage": "hwmon hwmon1: Undervoltage detected!",
            "thermal": "CPU0: Core temperature above threshold, cpu clock throttled",
        }
    )

    def matched(self, msg, ident="app"):
        return {name for name, i, rx in logfilter.RULES_RX if (i is None or i == ident) and rx.search(msg)}

    def test_every_rule_has_a_sample(self):
        self.assertEqual({r[0] for r in logfilter.RULES}, set(self.SAMPLES))

    def test_rules_match(self):
        for name, msg in self.SAMPLES.items():
            with self.subTest(rule=name):
                self.assertIn(name, self.matched(msg))

    def test_extra_rule_variants(self):
        self.assertIn("oom", self.matched("worker invoked oom-killer: gfp_mask=0x140cca"))
        self.assertIn("io_error", self.matched("BTRFS critical (device sdz1): corrupt leaf"))
        self.assertIn("crash", self.matched("Process 1 (x) of user 0 dumped core."))
        self.assertIn("kernel_crash", self.matched("Call Trace:"))
        self.assertIn("unit_failed", self.matched("Unit app.service entered failed state."))
        self.assertIn("hardware", self.matched("EDAC MC0: 1 CE memory read error"))

    def test_plain_message_matches_no_rule(self):
        self.assertEqual(self.matched("Started Daily Cleanup."), set())

    def test_always_include(self):
        msg = "Startup finished in 3.1s (firmware) + 2.0s (loader) + 1.5s (kernel) + 4s (userspace) = 10s."
        self.assertTrue(logfilter.match_any(logfilter.ALWAYS_RX, "systemd", msg))
        self.assertFalse(logfilter.match_any(logfilter.ALWAYS_RX, "systemd", "Startup finished in 1s (userspace)"))


class NoiseTest(unittest.TestCase):
    DROPPED = (
        (None, "s6-rc: info: service legacy-cont-init: starting"),
        ("firewalld", "WARNING: COMMAND_FAILED: '/usr/sbin/iptables -w10 -t nat -D DOCKER -i x' failed"),
        ("firewalld", "WARNING: COMMAND_FAILED: '/usr/sbin/ip6tables -w10 -t nat -D OUTPUT' failed: no chain"),
        ("firewalld", "ERROR: NAME_CONFLICT: new_policy_object(): 'docker-forwarding'"),
        ("sudo", "pam_unix(sudo:auth): conversation failed"),
        ("sudo", "pam_unix(sudo-i:auth): auth could not identify password for [someone]"),
        ("x", "\x01garbled ident\npam_unix(sudo:auth): conversation failed"),
        ("sshd", "error: mm_reap: preauth child terminated by signal 15"),
        ("app", ""),
        ("app", "  \n "),
        ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP"),
        ("kernel", " ? do_syscall_64+0x5d/0x90"),
        ("kernel", " __schedule+0x3c1/0x1430"),
        ("kernel", " <TASK>"),
        ("kernel", " </TASK>"),
        ("kernel", "RIP: 0010:some_func+0x12/0x30 [mod]"),
        ("kernel", "RSP: 0018:ffffb00000000000 EFLAGS: 00010246"),
        ("kernel", "RAX: 0000000000000000 RBX: 0000000000000001 RCX: 0000000000000002"),
        ("kernel", "RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000"),
        ("kernel", "RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000"),
        ("kernel", "R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000"),
        ("kernel", "R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000"),
        ("kernel", "CR2: 0000000000000000 CR3: 0000000000001000 CR4: 0000000000350ef0"),
        ("kernel", "PKRU: 55555554"),
        ("kernel", "Code: 48 89 e5 41 57 41 56 <0f> 0b 90"),
        ("kernel", "CPU: 3 UID: 0 PID: 1234 Comm: worker Tainted: G O 6.0.0 #1"),
        ("kernel", "CPU: 3 PID: 1234 Comm: worker Not tainted 6.0.0 #1"),
        ("kernel", "Hardware name: Example Vendor Board/Board, BIOS 1.0 01/01/2024"),
        ("kernel", "examplemod: loading out-of-tree module taints kernel."),
        ("kernel", "examplemod: module license 'Proprietary' taints kernel."),
        ("kernel", "examplemod: module uses symbols from proprietary module othermod, inheriting taint."),
        ("kernel", "Disabling lock debugging due to kernel taint"),
        ("kernel", "NVRM: loading NVIDIA UNIX x86_64 Kernel Module  999.99  Synthetic"),
        (
            "kernel",
            "ACPI BIOS Error (bug): Could not resolve symbol [\\_SB.PCI0.XYZ], AE_NOT_FOUND (20240101/dswload2-162)",
        ),
        (
            "kernel",
            "ACPI Error: Aborting method \\_SB.PCI0.XYZ due to previous error (AE_NOT_FOUND) (20240101/psparse-529)",
        ),
        ("kernel", "ACPI Warning: SystemIO range 0x0B00-0x0B08 conflicts with OpRegion 0x0B00-0x0B0F (\\GSA1.SMBI)"),
        ("kernel", "MDS CPU bug present. See https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html"),
        ("kernel", "ENERGY_PERF_BIAS: Set to 'normal', was 'performance'"),
        ("kernel", "amd_pstate: the _CPC object is not present in SBIOS or ACPI disabled"),
        ("kernel", "example-dev 1-0001: supply vcc not found, using dummy regulator"),
        ("kernel", "ata1.00: supports DRM functions and may not be fully accessible"),
        ("kernel", "ata2.00: LPM support broken, forcing max_power"),
        ("kernel", "NOTICE: Automounting of tracing to debugfs is deprecated and will be removed in 2030"),
        ("kernel", "asus_wmi: failed to register LPS0 sleep handler in asus-wmi"),
        ("kernel", "device-mapper: core: CONFIG_IMA_DISABLE_HTABLE is disabled. Duplicate IMA measurements."),
        ("kernel", "kauditd_printk_skb: 12 callbacks suppressed"),
        ("systemd", "lm_sensors.service: Referenced but unset environment variable evaluates to an empty string: X"),
        ("systemd-oomd", "No swap; memory pressure usage will be degraded"),
        (
            "systemd-networkd",
            "eth0: Found matching .network file, based on potentially unpredictable interface name: /x",
        ),
        ("irqbalance", "Cannot change IRQ 42 affinity: Permission denied"),
        ("irqbalance", "IRQ 42 affinity is now unmanaged"),
        ("kernel", "Mem-Info:"),
        ("kernel", "Node 0 DMA free:1024kB"),
        ("app", "/package/admin/s6-overlay/libexec/preinit: info: container starting"),
        ("app", '{"level":"info","msg":"synthetic"}'),
    )

    KEPT = (
        ("kernel", "sd 0:0:0:0: Power-on or device reset occurred"),
        (
            "systemd-journald",
            ("File /var/log/journal/x/system.journal corrupted or uncleanly shut down, renaming and replacing."),
        ),
        ("kernel", "ACPI Error: something else"),
        ("kernel", "ACPI Error: Aborting method \\_SB.X due to previous error (AE_AML_OPERAND_TYPE)"),
        ("(udev-worker)", "sdz: Process '/usr/lib/udev/hdparm' failed with exit code 5."),
        ("hdparm", "/dev/sdz: HDIO_DRIVE_CMD failed: Input/output error"),
        ("kernel", "ata1.00: failed command: READ FPDMA QUEUED"),
        ("kernel", "CPU: 3 temperature high"),
        ("kernel", "examplemod: tainting kernel"),
        ("app", '{"level":"error","msg":"synthetic"}'),
        ("app", "Started Daily Cleanup."),
    )

    # kernel-scoped NOISE entries must not drop the same text from other identifiers
    KERNEL_ONLY = (
        "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.1",
        "RIP: 0010:x+0x1/0x2",
        "Code: 48 89",
        "Hardware name: Example",
        "kauditd_printk_skb: 1 callbacks suppressed",
        "ENERGY_PERF_BIAS: Set to 'normal'",
    )

    def test_every_noise_entry_has_a_sample(self):
        for i, (ident, rx) in enumerate(logfilter.NOISE_RX):
            with self.subTest(noise=rx.pattern):
                self.assertTrue(
                    any((ident is None or ident == (d or "anything")) and rx.search(m) for d, m in self.DROPPED),
                    f"NOISE[{i}] has no sample",
                )

    def test_noise_drops(self):
        for ident, msg in self.DROPPED:
            with self.subTest(msg=msg):
                self.assertTrue(logfilter.match_any(logfilter.NOISE_RX, ident or "anything", msg))

    def test_noise_keeps(self):
        for ident, msg in self.KEPT:
            with self.subTest(msg=msg):
                self.assertFalse(logfilter.match_any(logfilter.NOISE_RX, ident, msg))

    def test_kernel_noise_scoped_to_kernel_ident(self):
        for msg in self.KERNEL_ONLY:
            with self.subTest(msg=msg):
                self.assertTrue(logfilter.match_any(logfilter.NOISE_RX, "kernel", msg))
                self.assertFalse(logfilter.match_any(logfilter.NOISE_RX, "myapp", msg))


# --- End-to-end tests --------------------------------------------------------


class E2EBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = self._tmp.name
        self.bin = os.path.join(root, "bin")
        self.state = os.path.join(root, "state")
        self.reports = os.path.join(root, "reports")
        os.mkdir(self.bin)
        fake = os.path.join(self.bin, "journalctl")
        with open(fake, "w", encoding="utf-8") as f:
            f.write(FAKE_JOURNALCTL.format(python=sys.executable))
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.env = dict(
            os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""), PYTHONDONTWRITEBYTECODE="1"
        )
        self.env.pop("FAKE_FAIL_HOST", None)

    def set_entries(self, entries, host="palvelin"):
        with open(os.path.join(self.bin, f"entries-{host}.json"), "w", encoding="utf-8") as f:
            json.dump(entries, f)

    def run_lf(self, *args, state=True, fail_host=None):
        cmd = [sys.executable, SCRIPT, *args]
        if state:
            cmd.append(f"--state-dir={self.state}")
        env = dict(self.env)
        if fail_host:
            env["FAKE_FAIL_HOST"] = fail_host
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30, check=False)

    def state_path(self, name, host="palvelin"):
        return os.path.join(self.state, host, name)

    def read_state(self, name, host="palvelin"):
        with open(self.state_path(name, host), encoding="utf-8") as f:
            return f.read()

    def pattern_lines(self, out):
        return [line for line in out.splitlines() if line and not line.startswith(" ") and re.search(r" x\d+  ", line)]

    def pattern_line(self, out, text):
        """The pattern header line whose following 'pattern:' line contains text."""
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("  pattern: ") and text in line:
                return lines[i - 1]
        self.fail(f"no pattern containing {text!r} in:\n{out}")

    def assertOk(self, res):
        self.assertEqual(res.returncode, 0, res.stderr)


class NormalModeTest(E2EBase):
    def first_entries(self):
        return [
            entry(1, "disk check failed code 5", prio=3),
            entry(2, "cache nearly full", prio=4),
            entry(3, "routine info message", prio=6),
        ]

    def test_first_run(self):
        self.set_entries(self.first_entries())
        res = self.run_lf("palvelin")
        self.assertOk(res)
        calls = journalctl_calls(self.bin)
        self.assertEqual(len(calls), 1)
        self.assertIn(f"--since={logfilter.INITIAL_SINCE}", calls[0])
        self.assertFalse(any(a.startswith("--after-cursor") for a in calls[0]))
        self.assertIn("--output=json", calls[0])
        self.assertFalse(any(a.startswith("--directory") for a in calls[0]))

        out = res.stdout
        self.assertIn(f"mode: normal (first run, since {logfilter.INITIAL_SINCE})", out)
        self.assertIn("entries read: 3  (err=1 warning=1 info=1)", out)
        self.assertIn("selected: 2 entries in 2 patterns (0 with rule matches, 2 new)", out)
        self.assertIn("note: no saved patterns for this host yet, so every pattern is marked new", out)
        heads = self.pattern_lines(out)
        self.assertEqual(len(heads), 2)
        for h in heads:
            self.assertIn("[NEW]", h)

        self.assertEqual(self.read_state("cursor"), "s=synthetic;i=3")
        seen = json.loads(self.read_state("seen.json"))
        self.assertEqual(len(seen), 2)
        for v in seen.values():
            self.assertIsNotNone(datetime.fromisoformat(v).tzinfo, v)
        self.assertFalse(os.path.exists(self.state_path("cursor.tmp")))

    def test_second_run_continues_from_cursor(self):
        first = self.first_entries()
        self.set_entries(first)
        self.assertOk(self.run_lf("palvelin"))
        # old first-seen times, so overwriting them is detectable even within the same second
        seen1 = {k: "2000-01-01T00:00:00+00:00" for k in json.loads(self.read_state("seen.json"))}
        with open(self.state_path("seen.json"), "w", encoding="utf-8") as f:
            json.dump(seen1, f)

        second = [
            entry(4, "disk check failed code 7", prio=3),  # same pattern as entry 1
            entry(5, "brand new warning", prio=4),
            entry(6, "another info", prio=6),
        ]
        self.set_entries(first + second)
        res = self.run_lf("palvelin")
        self.assertOk(res)
        calls = journalctl_calls(self.bin)
        self.assertEqual(len(calls), 2)
        self.assertIn("--after-cursor=s=synthetic;i=3", calls[1])
        self.assertFalse(any(a.startswith("--since") for a in calls[1]))

        out = res.stdout
        self.assertIn("mode: normal (after saved cursor)", out)
        self.assertIn("entries read: 3  (err=1 warning=1 info=1)", out)
        self.assertIn("selected: 2 entries in 2 patterns (0 with rule matches, 1 new)", out)
        self.assertNotIn("note: no saved patterns", out)
        self.assertNotIn("[NEW]", self.pattern_line(out, "disk check failed code <N>"))
        self.assertIn("[NEW]", self.pattern_line(out, "brand new warning"))
        self.assertNotIn("cache nearly full", out)

        self.assertEqual(self.read_state("cursor"), "s=synthetic;i=6")
        seen2 = json.loads(self.read_state("seen.json"))
        self.assertEqual(len(seen2), 3)
        for k, v in seen1.items():
            self.assertEqual(seen2[k], v)
        (new_ts,) = [v for k, v in seen2.items() if k not in seen1]
        self.assertNotEqual(new_ts, "2000-01-01T00:00:00+00:00")
        datetime.fromisoformat(new_ts)

    def test_zero_entries(self):
        entries = self.first_entries()
        self.set_entries(entries)
        self.assertOk(self.run_lf("palvelin"))
        cursor_before = self.read_state("cursor")
        seen_before = json.loads(self.read_state("seen.json"))
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertIn("range: no entries", res.stdout)
        self.assertEqual(json.loads(self.read_state("seen.json")), seen_before)
        self.assertIn("entries read: 0  (none)", res.stdout)
        self.assertIn("selected: 0 entries in 0 patterns (0 with rule matches, 0 new)", res.stdout)
        self.assertEqual(self.read_state("cursor"), cursor_before)

    def test_zero_entries_first_run_writes_no_cursor(self):
        self.set_entries([])
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertIn("range: no entries", res.stdout)
        self.assertFalse(os.path.exists(self.state_path("cursor")))


class PreviewModeTest(E2EBase):
    def test_no_state_written_in_empty_state_dir(self):
        self.set_entries([entry(1, "a warning", prio=4)])
        res = self.run_lf("palvelin", "--since=1 hour ago")
        self.assertOk(res)
        self.assertIn("mode: preview (since 1 hour ago; state not updated)", res.stdout)
        self.assertIn("[NEW]", res.stdout)
        self.assertFalse(os.path.exists(self.state))
        call = journalctl_calls(self.bin)[0]
        self.assertIn("--since=1 hour ago", call)
        self.assertFalse(any(a.startswith("--after-cursor") for a in call))

    def test_existing_state_unchanged_and_used_for_new(self):
        old = [entry(1, "old warning", prio=4), entry(2, "other", prio=6)]
        self.set_entries(old)
        self.assertOk(self.run_lf("palvelin"))
        with open(self.state_path("cursor"), "rb") as f:
            cursor = f.read()
        with open(self.state_path("seen.json"), "rb") as f:
            seen = f.read()
        files = sorted(os.listdir(os.path.join(self.state, "palvelin")))

        self.set_entries(old + [entry(3, "fresh warning", prio=4)])
        res = self.run_lf("palvelin", "--since=2 days ago")
        self.assertOk(res)
        call = journalctl_calls(self.bin)[1]
        self.assertIn("--since=2 days ago", call)
        self.assertFalse(any(a.startswith("--after-cursor") for a in call))
        self.assertIn("entries read: 3", res.stdout)
        self.assertNotIn("[NEW]", self.pattern_line(res.stdout, "old warning"))
        self.assertIn("[NEW]", self.pattern_line(res.stdout, "fresh warning"))
        self.assertNotIn("note: no saved patterns", res.stdout)

        with open(self.state_path("cursor"), "rb") as f:
            self.assertEqual(f.read(), cursor)
        with open(self.state_path("seen.json"), "rb") as f:
            self.assertEqual(f.read(), seen)
        self.assertEqual(sorted(os.listdir(os.path.join(self.state, "palvelin"))), files)


class CliTest(E2EBase):
    def test_since_with_report_dir_rejected(self):
        res = self.run_lf("palvelin", "--since=1 hour ago", f"--report-dir={self.reports}")
        self.assertEqual(res.returncode, 2)
        self.assertIn("--report-dir cannot be used with --since", res.stderr)
        self.assertEqual(journalctl_calls(self.bin), [])
        self.assertFalse(os.path.exists(self.reports))

    def test_unknown_host_rejected(self):
        res = self.run_lf("palvelin", "nosuchhost")
        self.assertEqual(res.returncode, 2)
        self.assertIn("unknown host(s): nosuchhost", res.stderr)
        self.assertEqual(journalctl_calls(self.bin), [])
        self.assertFalse(os.path.exists(self.state))


class FilteringTest(E2EBase):
    def test_rule_overrides_noise(self):
        self.set_entries(
            [
                entry(1, "s6-rc: info: service x: Failed with result 'exit-code'", prio=6),
                entry(2, "s6-rc: info: service y successfully started", prio=6),
            ]
        )
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertIn("dropped as noise: 1", res.stdout)
        head = self.pattern_line(res.stdout, "Failed with result")
        self.assertTrue(head.startswith("[rule:unit_failed] [NEW] info "), head)
        self.assertIn("(1 with rule matches, 1 new)", res.stdout)

    def test_noise_dropped_regardless_of_priority(self):
        self.set_entries(
            [
                entry(1, '{"level":"info","msg":"x"}', prio=3),
                entry(2, "pam_unix(sudo:auth): conversation failed", prio=2, ident="sudo", unit=None),
                # matches ALWAYS_INCLUDE as well as NOISE: NOISE wins
                entry(3, "Startup finished in 1s (kernel) pam_unix(sudo:auth): x", prio=6),
                kernel(4, "[UFW BLOCK] IN=eth0 SRC=192.0.2.9", prio=0),
                entry(5, "real problem", prio=3),
            ]
        )
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertIn("dropped as noise: 4", res.stdout)
        self.assertIn("selected: 1 entries in 1 patterns", res.stdout)
        self.assertIn("real problem", res.stdout)
        self.assertNotIn("UFW", res.stdout)

    def test_priority_selection(self):
        self.set_entries(
            [
                entry(1, "warn message", prio=4),
                entry(2, "notice message", prio=5),
                entry(3, "info message", prio=6),
                entry(
                    4,
                    "Startup finished in 2.5s (kernel) + 3s (userspace) = 5.5s.",
                    prio=6,
                    ident="systemd",
                    unit="init.scope",
                ),
                entry(5, "missing prio message", prio=None),
                entry(6, "garbage prio message", PRIORITY="bogus"),
                entry(7, "emerg message", prio=0),
            ]
        )
        res = self.run_lf("palvelin")
        self.assertOk(res)
        out = res.stdout
        self.assertIn("entries read: 7  (emerg=1 warning=1 notice=1 info=4)", out)
        self.assertIn("dropped as noise: 0", out)
        self.assertIn("selected: 3 entries in 3 patterns", out)
        self.assertIn("warn message", out)
        self.assertIn("emerg message", out)
        for gone in ("notice message", "info message", "missing prio", "garbage prio"):
            self.assertNotIn(gone, out)
        head = self.pattern_line(out, "Startup finished")
        self.assertIn(" info systemd x1", head)

    def test_normalization_collapses_patterns(self):
        tpl = "peer {ip4} {ip6} mac {mac} id {uuid} at {hexv} {hexb} n={n} {ts} {clock}"
        values = [
            (
                "192.0.2.10",
                "2001:db8::1",
                "00:11:22:33:44:55",
                "123e4567-e89b-12d3-a456-426614174000",
                "0x1f",
                "a1b2c3d4e5",
                "15ms",
                "2026-10-21T10:00:00Z",
                "10:00:00",
            ),
            (
                "198.51.100.7",
                "2001:db8:1::2",
                "66:77:88:99:aa:bb",
                "00000000-1111-2222-3333-44444444abcd",
                "0xFFFF",
                "0123456789abcdef",
                "2048kB",
                "2026-10-22 11:22:33.5+03:00",
                "23:59:59",
            ),
            (
                "192.0.2.10",
                "2001:db8::1",
                "00:11:22:33:44:56",
                "123e4567-e89b-12d3-a456-426614174001",
                "0x2",
                "ffff0000a",
                "7",
                "2026-10-23T01:02:03",
                "1:02:03",
            ),
        ]
        keys = ("ip4", "ip6", "mac", "uuid", "hexv", "hexb", "n", "ts", "clock")
        self.set_entries([entry(i + 1, tpl.format(**dict(zip(keys, v))), prio=3) for i, v in enumerate(values)])
        res = self.run_lf("palvelin")
        self.assertOk(res)
        out = res.stdout
        self.assertIn("selected: 3 entries in 1 patterns", out)
        self.assertIn("  pattern: peer <IP> <IP> mac <MAC> id <UUID> at <HEX> <HEX> n=<N> <TIME> <TIME>", out)
        self.assertIn(" x3  ", self.pattern_lines(out)[0])
        self.assertIn("  top IPs: ", out)
        top = next(line for line in out.splitlines() if line.startswith("  top IPs: "))
        m = re.fullmatch(r"  top IPs: (.*) \((\d+) distinct\)", top)
        self.assertIsNotNone(m, top)
        self.assertEqual(m.group(2), "4")
        parts = m.group(1).split(", ")
        self.assertEqual(sorted(parts[:2]), ["192.0.2.10 x2", "2001:db8::1 x2"])
        self.assertEqual(sorted(parts[2:]), ["198.51.100.7 x1", "2001:db8:1::2 x1"])
        # the example is the first message seen
        self.assertIn(f"  example: {tpl.format(**dict(zip(keys, values[0])))}", out)

    def test_no_top_ips_without_ips(self):
        self.set_entries([entry(1, "no address here", prio=3)])
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertNotIn("top IPs", res.stdout)

    def test_binary_and_repeated_fields(self):
        self.set_entries(
            [
                entry(1, list(b"disk sdz: I/O error \xff here"), prio=3),
                entry(
                    2,
                    ["first value", "second value"],
                    PRIORITY=["3", "3"],
                    ident=["myident", "other"],
                    unit=["one.service", "two.service"],
                ),
                kernel(3, list(b"multi\nline kernel"), prio=2),
            ]
        )
        res = self.run_lf("palvelin")
        self.assertOk(res)
        out = res.stdout
        self.assertIn("entries read: 3  (crit=1 err=2)", out)
        self.assertIn("  example: disk sdz: I/O error � here", out)
        self.assertIn("[rule:io_error]", self.pattern_line(out, "I/O error"))
        self.assertIn("  example: first value", out)
        self.assertNotIn("second value", out)
        self.assertIn(" err one.service x1", self.pattern_line(out, "first value"))
        self.assertIn("  example: multi | line kernel", out)
        self.assertIn(" crit kernel x1", self.pattern_line(out, "multi | line kernel"))

    def test_non_json_lines_skipped(self):
        self.set_entries(
            [
                "this is not json",
                entry(1, "valid warning", prio=4),
                "{broken",
                "",
            ]
        )
        res = self.run_lf("palvelin")
        self.assertOk(res)
        self.assertIn("entries read: 1  (warning=1)", res.stdout)
        self.assertIn("valid warning", res.stdout)
        self.assertEqual(self.read_state("cursor"), "s=synthetic;i=1")


class ReportFormatTest(E2EBase):
    def test_header_order_and_sort_and_size(self):
        self.set_entries([entry(1, "old crit thing", prio=2)])
        self.assertOk(self.run_lf("palvelin"))

        entries = [
            entry(1, "old crit thing", prio=2),
            entry(2, "old crit thing", prio=2),
            entry(3, "new warn single", prio=4),
            entry(4, "new warn triple", prio=4),
            entry(5, "new warn triple", prio=4),
            entry(6, "new warn triple", prio=4),
            entry(7, "new err single", prio=3),
            entry(8, "x.service: Failed with result 'timeout'.", prio=5, ident="systemd", unit="init.scope"),
            entry(9, "noise", prio=6),
        ]
        self.set_entries(entries)
        res = self.run_lf("palvelin", f"--report-dir={self.reports}")
        self.assertOk(res)
        self.assertEqual(res.stdout, "")
        files = os.listdir(os.path.join(self.reports, "palvelin"))
        self.assertEqual(len(files), 1)
        with open(os.path.join(self.reports, "palvelin", files[0]), encoding="utf-8") as f:
            full = f.read()

        lines = full.split("\n")
        self.assertEqual(lines[0], "=== palvelin ===")
        self.assertEqual(lines[1], "mode: normal (after saved cursor)")
        self.assertEqual(
            lines[2], f"range: {logfilter.fmt_ts(BASE_TS + 2_000_000)} -> {logfilter.fmt_ts(BASE_TS + 9_000_000)}"
        )
        self.assertEqual(lines[3], "entries read: 8  (crit=1 err=1 warning=4 notice=1 info=1)")
        self.assertEqual(lines[4], "dropped as noise: 0")
        self.assertEqual(lines[5], "selected: 7 entries in 5 patterns (1 with rule matches, 4 new)")
        self.assertEqual(lines[6], "")

        heads = [lines[i] for i in range(7, 7 + 5 * 3, 3)]
        self.assertTrue(heads[0].startswith("[rule:unit_failed] [NEW] notice systemd x1  "), heads[0])
        self.assertTrue(heads[1].startswith("[NEW] err app.service x1  "), heads[1])
        self.assertTrue(heads[2].startswith("[NEW] warning app.service x3  "), heads[2])
        self.assertTrue(heads[3].startswith("[NEW] warning app.service x1  "), heads[3])
        self.assertTrue(heads[4].startswith("crit app.service x1  "), heads[4])
        self.assertEqual(
            heads[2],
            f"[NEW] warning app.service x3  {logfilter.fmt_ts(BASE_TS + 4_000_000)} -> "
            f"{logfilter.fmt_ts(BASE_TS + 6_000_000)}",
        )
        for i in range(7, 7 + 5 * 3, 3):
            self.assertTrue(lines[i + 1].startswith("  pattern: "), lines[i + 1])
            self.assertTrue(lines[i + 2].startswith("  example: "), lines[i + 2])
        self.assertEqual(lines[8], "  pattern: x.service: Failed with result 'timeout'.")

        self.assertTrue(full.endswith(" characters\n"))
        body, footer = full[:-1].rsplit("\n", 1)
        m = re.fullmatch(r"report size: (\d+) characters", footer)
        self.assertIsNotNone(m, footer)
        self.assertEqual(int(m.group(1)), len(body))

    def test_report_size_on_stdout(self):
        self.set_entries([entry(1, "a warning with ünïcode", prio=4)])
        res = self.run_lf("palvelin")
        self.assertOk(res)
        out = res.stdout
        self.assertTrue(out.endswith("\n\n"))  # print() adds a newline after the report's own
        body, footer = out[:-2].rsplit("\n", 1)
        m = re.fullmatch(r"report size: (\d+) characters", footer)
        self.assertIsNotNone(m, footer)
        self.assertEqual(int(m.group(1)), len(body))


class ReportDirTest(E2EBase):
    def test_report_written_and_state_saved(self):
        self.set_entries([entry(1, "a warning", prio=4)])
        start = datetime.now().replace(microsecond=0)
        res = self.run_lf("palvelin", f"--report-dir={self.reports}")
        end = datetime.now()
        self.assertOk(res)
        self.assertEqual(res.stdout, "")
        files = os.listdir(os.path.join(self.reports, "palvelin"))
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0], r"^\d{8}-\d{6}\.txt$")
        stamp = datetime.strptime(files[0], "%Y%m%d-%H%M%S.txt")
        self.assertTrue(start <= stamp <= end, (start, stamp, end))
        self.assertEqual(sorted(os.listdir(os.path.join(self.state, "palvelin"))), ["cursor", "seen.json"])
        with open(os.path.join(self.reports, "palvelin", files[0]), encoding="utf-8") as f:
            content = f.read()
        self.assertTrue(content.startswith("=== palvelin ===\n"))
        self.assertIn("a warning", content)
        self.assertEqual(self.read_state("cursor"), "s=synthetic;i=1")
        self.assertTrue(os.path.exists(self.state_path("seen.json")))

    def test_report_write_failure_saves_no_state(self):
        self.set_entries([entry(1, "a warning", prio=4)])
        blocker = os.path.join(self._tmp.name, "not-a-dir")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        res = self.run_lf("palvelin", f"--report-dir={blocker}")
        self.assertEqual(res.returncode, 1)
        self.assertIn("palvelin: ", res.stderr)
        self.assertEqual(res.stdout, "")
        self.assertFalse(os.path.exists(self.state_path("cursor")))
        self.assertFalse(os.path.exists(self.state_path("seen.json")))

    def test_report_write_failure_keeps_existing_state(self):
        self.set_entries([entry(1, "a warning", prio=4)])
        self.assertOk(self.run_lf("palvelin"))
        cursor = self.read_state("cursor")
        seen = self.read_state("seen.json")
        self.set_entries([entry(1, "a warning", prio=4), entry(2, "new warning", prio=4)])
        blocker = os.path.join(self._tmp.name, "not-a-dir")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        res = self.run_lf("palvelin", f"--report-dir={blocker}")
        self.assertEqual(res.returncode, 1)
        self.assertEqual(self.read_state("cursor"), cursor)
        self.assertEqual(self.read_state("seen.json"), seen)


class MultiHostTest(E2EBase):
    def test_failure_of_one_host(self):
        for i, host in enumerate(logfilter.HOSTS):
            self.set_entries([entry(10 * i + 1, f"warning from {host}", prio=4, _HOSTNAME=host)], host=host)
        res = self.run_lf(fail_host="vakoilu")
        self.assertEqual(res.returncode, 1)
        self.assertIn("vakoilu: journalctl exited with status 3", res.stderr)
        self.assertIn("=== palvelin ===", res.stdout)
        self.assertIn("=== seuranta ===", res.stdout)
        self.assertNotIn("=== vakoilu ===", res.stdout)
        self.assertIn("warning from seuranta", res.stdout)
        self.assertNotIn("warning from vakoilu", res.stdout)
        for host, n in (("palvelin", 1), ("seuranta", 21)):
            with self.subTest(host=host):
                self.assertEqual(self.read_state("cursor", host), f"s=synthetic;i={n:x}")
                self.assertEqual(len(json.loads(self.read_state("seen.json", host))), 1)
        self.assertFalse(os.path.exists(os.path.join(self.state, "vakoilu")))

        calls = journalctl_calls(self.bin)
        self.assertEqual(len(calls), len(logfilter.HOSTS))
        local = [c for c in calls if not any(a.startswith("_HOSTNAME=") for a in c)]
        self.assertEqual(len(local), 1)
        self.assertFalse(any(a.startswith("--directory") for a in local[0]))
        for host in ("vakoilu", "seuranta"):
            with self.subTest(host=host):
                call = [c for c in calls if f"_HOSTNAME={host}" in c]
                self.assertEqual(len(call), 1)
                self.assertIn("--directory=/var/log/journal/remote", call[0])
                self.assertIn("--output=json", call[0])


if __name__ == "__main__":
    unittest.main()
