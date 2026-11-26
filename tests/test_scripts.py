import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "look-before-retry")
SCRIPTS = os.path.join(SKILL, "scripts")
sys.path.insert(0, SCRIPTS)

import check_port  # noqa: E402
import fail_log  # noqa: E402

NETSTAT_GERMAN = """
Aktive Verbindungen

  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    0.0.0.0:3000           0.0.0.0:0              ABH\u00d6REN          4120
  TCP    0.0.0.0:30000          0.0.0.0:0              ABH\u00d6REN          999
  TCP    127.0.0.1:52011        127.0.0.1:3000         HERGESTELLT      777
  TCP    [::]:3000              [::]:0                 ABH\u00d6REN          4120
  TCP    [::1]:5173             [::]:0                 ABH\u00d6REN          5555
  UDP    0.0.0.0:3000           *:*                                     111
"""

SS_SAMPLE = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      511          0.0.0.0:3000       0.0.0.0:*     users:(("node",pid=42,fd=20))
LISTEN 0      511                *:30000            *:*     users:(("node",pid=43,fd=20))
LISTEN 0      128             [::]:8080          [::]:*
"""


def run_script(name, *args, env=None, cwd=None, data=None):
    done = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, name), *args],
        capture_output=True,
        env=env,
        cwd=cwd,
        input=data if data is not None else b"",
        timeout=90,
    )
    done.stdout = done.stdout.decode("utf-8", errors="replace")
    done.stderr = done.stderr.decode("utf-8", errors="replace")
    return done


class SkillFileTests(unittest.TestCase):
    def read(self):
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as handle:
            return handle.read()

    def test_frontmatter(self):
        head = self.read().split("---")[1].strip().splitlines()
        fields = dict(line.split(": ", 1) for line in head)
        self.assertEqual(sorted(fields), ["description", "name"])
        self.assertEqual(fields["name"], os.path.basename(SKILL))
        self.assertLessEqual(len(fields["description"]), 1024)
        # ": " or " #" would break an unquoted YAML value.
        self.assertNotIn(": ", fields["description"])
        self.assertNotIn(" #", fields["description"])

    def test_length_and_referenced_files(self):
        self.assertLess(len(self.read().splitlines()), 500)
        for name in ("scripts/check_port.py", "scripts/fail_log.py", "references/recovery.md"):
            self.assertTrue(os.path.isfile(os.path.join(SKILL, name)), name)

    def test_no_error_text_as_argument_or_heredoc(self):
        text = self.read()
        self.assertNotIn('--error "', text)
        self.assertNotIn("<<", text)


class ParserTests(unittest.TestCase):
    def test_netstat_works_with_translated_state(self):
        self.assertEqual(check_port.parse_netstat(NETSTAT_GERMAN, 3000), [4120])
        self.assertEqual(check_port.parse_netstat(NETSTAT_GERMAN, 5173), [5555])

    def test_netstat_ignores_clients_and_longer_ports(self):
        self.assertEqual(check_port.parse_netstat(NETSTAT_GERMAN, 52011), [])
        self.assertEqual(check_port.parse_netstat(NETSTAT_GERMAN, 300), [])

    def test_ss(self):
        self.assertEqual(check_port.parse_ss(SS_SAMPLE, 3000), (True, [42]))
        self.assertEqual(check_port.parse_ss(SS_SAMPLE, 8080), (True, []))
        self.assertEqual(check_port.parse_ss(SS_SAMPLE, 80), (False, []))

    def test_lsof(self):
        self.assertEqual(check_port.parse_lsof("12\n12\n13\n"), [12, 13])


class RedactTests(unittest.TestCase):
    def hidden(self, command, secret):
        self.assertNotIn(secret, check_port.redact(command), command)

    def test_assignments_and_flags(self):
        self.hidden("node s.js --token=abc123", "abc123")
        self.hidden("API_KEY=zzz9 node s.js", "zzz9")
        self.hidden("AWS_SECRET_ACCESS_KEY=qqq node s.js", "qqq")
        self.hidden("tool --password hunter2", "hunter2")
        self.hidden('curl -H "Authorization: Bearer abc.def" x', "abc.def")

    def test_urls_and_known_token_shapes(self):
        self.hidden("x postgres://user:pw9@host/db", "pw9")
        self.hidden("git clone https://tok3n@example.com/r.git", "tok3n")
        token = "ghp_" + "a" * 30
        self.hidden("node s.js " + token, token)

    def test_more_secret_shapes(self):
        self.hidden("DB_PASS=s3cr3t node s.js", "s3cr3t")
        self.hidden("PRIVATE_KEY=pk999 node s.js", "pk999")
        self.hidden("SESSION=sess42 node s.js", "sess42")
        self.hidden("curl -u admin:hunter3 http://x", "hunter3")
        self.hidden('curl --header "X-Key: Bearer abcdefgh123" x', "abcdefgh123")
        for token in ("xoxb-" + "1" * 20, "AIza" + "b" * 35, "npm_" + "c" * 36):
            self.hidden("node s.js " + token, token)

    def test_long_command_keeps_project_path_at_the_end(self):
        command = "C:\\node\\node.exe " + "--flag " * 120 + "C:\\Users\\me\\myapp\\server.js"
        text = check_port.redact(command)
        self.assertIn("myapp", text)
        self.assertLessEqual(len(text), 600)

    def test_keeps_names_needed_to_identify_a_process(self):
        for command in (
            "node C:\\work\\auth-service server.js",
            "python token_server.py --port 3000",
            "node node_modules/.bin/vite --host",
        ):
            self.assertEqual(check_port.redact(command), command)

    def test_control_characters_and_length(self):
        self.assertNotIn("\n", check_port.redact("a\nb\x1b[31m"))
        self.assertLessEqual(len(check_port.redact("x" * 1000)), 600)


class LivePortTests(unittest.TestCase):
    def bound(self, family=socket.AF_INET, host="127.0.0.1", listen=True):
        sock = socket.socket(family, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind((host, 0))
        if listen:
            sock.listen(5)
        return sock, sock.getsockname()[1]

    def test_busy_port_and_owner(self):
        _, port = self.bound()
        result = check_port.check(port)
        self.assertTrue(result["in_use"])
        self.assertIsNone(result["blocked"])
        if result["owner_lookup"] is None:
            self.skipTest("no lookup tool on this system")
        owners = [p for p in result["processes"] if p["pid"] == os.getpid()]
        self.assertEqual(len(owners), 1, result)
        self.assertIn("python", (owners[0]["name"] + owners[0]["command"]).lower())

    def test_ipv6_listener(self):
        try:
            _, port = self.bound(socket.AF_INET6, "::1")
        except OSError:
            self.skipTest("no IPv6")
        self.assertTrue(check_port.check(port)["in_use"])

    def test_taken_but_not_listening_is_blocked(self):
        _, port = self.bound(listen=False)
        done = run_script("check_port.py", str(port))
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertIn("BLOCKED", done.stdout)

    def test_free_port_and_exit_codes(self):
        sock, port = self.bound()
        busy = run_script("check_port.py", str(port))
        self.assertEqual(busy.returncode, 1, busy.stdout + busy.stderr)
        self.assertIn("IN USE", busy.stdout)
        sock.close()
        free = run_script("check_port.py", str(port))
        self.assertEqual(free.returncode, 0, free.stdout + free.stderr)
        self.assertIn("FREE", free.stdout)

    def test_bad_arguments(self):
        for args in ((), ("abc",), ("0",), ("70000",), ("\u00b2",)):
            self.assertEqual(run_script("check_port.py", *args).returncode, 2, args)


class SignatureTests(unittest.TestCase):
    def same(self, first, second):
        self.assertEqual(fail_log.signature(first), fail_log.signature(second))

    def differ(self, first, second):
        self.assertNotEqual(fail_log.signature(first), fail_log.signature(second))

    def test_ignores_positions_times_and_colour(self):
        self.same(
            "12:00:01 \x1b[31mError\x1b[0m: boom at src/a.js:10:5 after 1.2s",
            "13:59:59 Error: boom at src/a.js:88:1 after 950ms",
        )
        self.same("a.ts(4,7): error TS2322: x", "a.ts(90,2): error TS2322: x")
        self.same("error: x\n> 12 | const a", "error: x\n> 48 | const a")

    def test_keeps_meaningful_differences(self):
        self.differ("Error: Cannot find module 'react'", "Error: Cannot find module 'vue'")
        self.differ("a.ts(1,1): error TS2322: x", "a.ts(1,1): error TS2345: x")
        self.differ(
            "Error: connect ECONNREFUSED 127.0.0.1:5432",
            "Error: connect ECONNREFUSED 127.0.0.1:6379",
        )
        self.differ("error: shape (3, 4) expected", "error: shape (4, 3) expected")
        self.differ("error: no host db.com:443", "error: no host db.com:80")

    def test_uses_detail_lines_after_the_error(self):
        template = "A.java:3: error: cannot find symbol\n  Foo x;\n  ^\n  symbol: class %s"
        self.differ(template % "Foo", template % "Bar")
        self.differ("npm ERR! code\nERESOLVE", "npm ERR! code\nENOENT")

    def test_ignores_unrelated_progress_lines(self):
        self.same("step 1 of 9\nerror: broken", "step 4 of 9\nerror: broken")

    def test_harmless_lines_do_not_hide_the_real_error(self):
        noise = "Compiling src/errorBoundary.ts\n" + "0 errors, 0 failed\n" * 60
        self.differ(noise + "error: real A", noise + "error: real B")
        early = "".join("warning: failed to fetch mirror %d\n" % i for i in range(60))
        self.differ(early + "fatal: out of memory", early + "fatal: disk full")

    def test_traceback_end_without_keyword(self):
        frames = "".join(
            '  File "app/m%d.py", line %d, in f\n    g()\n' % (i, i) for i in range(6)
        )
        start = "Traceback (most recent call last):\n" + frames
        self.differ(start + "ConfigMismatch: port", start + "StopIteration")

    def test_german_positions_and_changing_paths(self):
        self.same("Fehler in Zeile 12: x", "Fehler in Zeile 14: x")
        self.same(
            "error: cannot open /tmp/pytest-of-u/pytest-12/a.txt",
            "error: cannot open /tmp/pytest-of-u/pytest-13/a.txt",
        )
        self.same(
            "npm ERR! log: C:\\Users\\me\\AppData\\Local\\Temp\\2026-11-26T22_01_33_123Z-debug.log",
            "npm ERR! log: C:\\Users\\me\\AppData\\Local\\Temp\\2026-11-26T22_09_01_456Z-debug.log",
        )
        self.same("error in chunk 3f9a1c2b7d", "error in chunk 8e0b4d6a1f")

    def test_long_output_keeps_the_end(self):
        filler = "info: building module\n" * 30_000
        self.assertGreater(len(filler), fail_log.HEAD_CHARS + fail_log.TAIL_CHARS)
        first = fail_log.clip(filler + "error: real A")
        second = fail_log.clip(filler + "error: real B")
        self.assertNotEqual(fail_log.signature(first), fail_log.signature(second))

    def test_large_file_keeps_the_end(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        saved = fail_log.FILE_HEAD_BYTES, fail_log.FILE_TAIL_BYTES
        fail_log.FILE_HEAD_BYTES, fail_log.FILE_TAIL_BYTES = 200, 400
        self.addCleanup(setattr, fail_log, "FILE_HEAD_BYTES", saved[0])
        self.addCleanup(setattr, fail_log, "FILE_TAIL_BYTES", saved[1])
        for encoding in ("utf-8", "utf-16"):
            path = os.path.join(folder, encoding + ".log")
            with open(path, "w", encoding=encoding) as handle:
                handle.write("info: step\n" * 500 + "error: the end\n")
            self.assertIn("error: the end", fail_log.read_file(path), encoding)


class LogTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        self.project = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.project, ignore_errors=True)
        self.env = dict(os.environ, LBR_STATE_DIR=self.folder)

    def call(self, *args, cwd=None, data=None):
        return run_script(
            "fail_log.py", *args, env=self.env, cwd=cwd or self.project, data=data
        )

    def fail(self, error, cmd="npm run build", cwd=None):
        return self.call("record", "--cmd", cmd, cwd=cwd, data=error.encode("utf-8"))

    def codes(self, *errors):
        return [self.fail(error).returncode for error in errors]

    def test_same_error_three_times_stops(self):
        self.assertEqual(self.codes("error: a", "error: a", "error: a"), [0, 0, 1])

    def test_flip_flop_stops(self):
        self.assertEqual(self.codes("error: a", "error: b", "error: a"), [0, 0, 1])

    def test_progress_with_new_errors_continues_until_eight(self):
        errors = ["error: %s" % letter for letter in "abcdefgh"]
        self.assertEqual(self.codes(*errors), [0] * 7 + [1])

    def test_label_with_shell_characters_rejected(self):
        for label in ("npm run $(x)", "make `id`", 'a"b'):
            done = self.call("record", "--cmd", label, data=b"error: a")
            self.assertEqual(done.returncode, 2, label)

    def test_commands_counted_separately(self):
        self.codes("error: a", "error: a")
        self.assertEqual(self.fail("error: a", cmd="npm test").returncode, 0)

    def test_spacing_does_not_reset_count(self):
        self.codes("error: a", "error: a")
        self.assertEqual(self.fail("error: a", cmd="npm   run  build").returncode, 1)

    def test_folders_counted_separately(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        self.codes("error: a", "error: a")
        self.assertEqual(self.fail("error: a", cwd=other).returncode, 0)

    def test_reset_after_success(self):
        self.codes("error: a", "error: a")
        self.assertEqual(self.call("reset", "--cmd", "npm run build").returncode, 0)
        self.assertEqual(self.codes("error: a"), [0])

    def test_error_file_in_utf8_and_utf16(self):
        marks = []
        for encoding in ("utf-8", "utf-16"):
            path = os.path.join(self.folder, encoding + ".log")
            with open(path, "w", encoding=encoding) as handle:
                handle.write("error: from file\n")
            done = self.call("record", "--cmd", "make", "--error-file", path)
            self.assertEqual(done.returncode, 0, done.stderr)
            marks.append(done.stdout.split("error ")[1].split()[0])
        self.assertEqual(marks[0], marks[1])
        self.assertIn("make: 2 failure(s), 1 different", self.call("status").stdout)

    def test_shell_characters_are_only_text(self):
        done = self.fail("error: $(echo hi) `whoami` \"quoted\"")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_bad_input_rejected(self):
        self.assertEqual(self.fail("   ").returncode, 2)
        missing = os.path.join(self.folder, "missing.log")
        done = self.call("record", "--cmd", "make", "--error-file", missing)
        self.assertEqual(done.returncode, 2)

    def test_nothing_written_into_project(self):
        self.fail("error: a")
        self.assertEqual(os.listdir(self.project), [])

    def test_old_entries_expire(self):
        previous = os.environ.get("LBR_STATE_DIR")
        os.environ["LBR_STATE_DIR"] = self.folder
        try:
            fail_log.record("x", "error: a", now=1000.0)
            later = 1000.0 + fail_log.MAX_AGE_SECONDS + 1
            self.assertEqual(fail_log.record("x", "error: a", now=later)["same"], 1)
        finally:
            if previous is None:
                os.environ.pop("LBR_STATE_DIR", None)
            else:
                os.environ["LBR_STATE_DIR"] = previous

    def test_broken_state_file_is_ignored(self):
        self.fail("error: a")
        for name in os.listdir(self.folder):
            with open(os.path.join(self.folder, name), "w") as handle:
                handle.write("not json")
        self.assertEqual(self.codes("error: a"), [0])


if __name__ == "__main__":
    unittest.main()
