#!/usr/bin/env python3
"""Count repeated failures of a command so that blind retry loops become visible.

  fail_log.py record --cmd "npm run build" --error-file build.log
  fail_log.py record --cmd "npm run build" < build.log
  fail_log.py reset  --cmd "npm run build"
  fail_log.py status

`record` prints CONTINUE or STOP. STOP means one of:
  - the same error appeared three times,
  - an earlier error came back after a different one (A, B, A),
  - the command failed eight times in total.

Error text is only read from a file or standard input, never from an argument,
because a shell could execute parts of it. Long output keeps its start and its
end, where the real error usually is.

Exit codes: 0 = continue, 1 = stop, 2 = bad arguments or unreadable input.
Counters are kept per working folder in the system temp folder.
Python standard library only.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time

SAME_ERROR_LIMIT = 3
TOTAL_LIMIT = 8
MAX_AGE_SECONDS = 2 * 60 * 60
HEAD_CHARS = 20_000
TAIL_CHARS = 180_000
FILE_HEAD_BYTES = 1_000_000
FILE_TAIL_BYTES = 4_000_000
CONTEXT_LINES = 3
TAIL_LINES = 3
MAX_CHOSEN = 40
LABEL = re.compile(r"[\w .:/=+@,-]{1,200}")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# "0 errors" or "0 failed" in a summary is not an error.
ZERO_COUNT = re.compile(r"(?i)\b0\s+(?:errors?|failed|failures?|failing|fehler)\b")
# Word boundaries, so that names like errorBoundary.ts do not count.
# TypeError and RuntimeException do count.
KEYWORDS = re.compile(
    r"(?i)(?:\b|(?<=[a-z]))(?:errors?|exception)\b"
    r"|\b(?:failed|failure|failing|fatal|cannot|not found|fehler|panic|traceback"
    r"|assert\w*|undefined|err)\b"
)
SOURCE_FILE = (
    r"\.(?:js|jsx|mjs|cjs|ts|tsx|vue|svelte|py|java|kt|kts|go|rs|rb|php|cs|c|cc"
    r"|cpp|h|hpp|swift|dart|json|yaml|yml|toml|gradle|xml|html|css|scss)"
)
# Remove only things that change between runs of the same error. Port numbers,
# error codes and other numbers must stay.
NOISE = (
    (re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d[:_]\d\d[:_]\d\d(?:[._]\d+)?(?:Z|[+-]\d\d:?\d\d)?"), "<time>"),
    (re.compile(r"\b\d\d:\d\d:\d\d(?:\.\d+)?\b"), "<time>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s|sec|seconds|sekunden)\b"), "<duration>"),
    (re.compile(r"(?i)(?:/tmp/|/var/folders/|[\\/]temp[\\/])[^\s\"']*"), "<tmp>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<addr>"),
    (re.compile(r"\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b"), "<hash>"),
    (re.compile(r"(?i)\bpid[ :=]*\d+"), "pid <n>"),
    (re.compile(r"(?i)(%s)(?::\d+(?::\d+)?\b|\(\d+,\s?\d+\))" % SOURCE_FILE), r"\1:<pos>"),
    (re.compile(r"(?i)\b(line|zeile|char|zeichen|column|col|spalte)[ :]*\d+"), r"\1 <n>"),
    (re.compile(r"^>?\s*\d+\s*\|"), "<n> |"),
    (re.compile(r"\s+"), " "),
)


def is_error_line(line):
    return bool(KEYWORDS.search(ZERO_COUNT.sub("", line)))


def signature(text):
    """A short fingerprint of the error that ignores times, paths and positions."""
    lines = [ANSI.sub("", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    wanted = set()
    for index, line in enumerate(lines):
        if is_error_line(line):
            wanted.update(range(index, min(index + CONTEXT_LINES + 1, len(lines))))
    # The last error lines matter most, so keep those if there are many.
    chosen = set(sorted(wanted)[-MAX_CHOSEN:])
    tail = range(max(0, len(lines) - TAIL_LINES), len(lines))
    # The final line often names the problem without a keyword, for example
    # the exception at the end of a Python traceback.
    if not chosen or not any(is_error_line(lines[i]) for i in tail):
        chosen.update(tail)
    cleaned = set()
    for index in chosen:
        line = lines[index]
        for pattern, replacement in NOISE:
            line = pattern.sub(replacement, line)
        cleaned.add(line)
    joined = "\n".join(sorted(cleaned))
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:12]


def decode(raw):
    """Windows PowerShell 5.1 redirects output as UTF-16, most tools use UTF-8."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def clip(text):
    if len(text) > HEAD_CHARS + TAIL_CHARS:
        return text[:HEAD_CHARS] + "\n" + text[-TAIL_CHARS:]
    return text


def read_file(path):
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        if size <= FILE_HEAD_BYTES + FILE_TAIL_BYTES:
            return clip(decode(handle.read()))
        head = handle.read(FILE_HEAD_BYTES)
        start = size - FILE_TAIL_BYTES
        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            start -= start % 2  # stay aligned with UTF-16 characters
            handle.seek(start)
            encoding = "utf-16-le" if head.startswith(b"\xff\xfe") else "utf-16-be"
            tail = handle.read().decode(encoding, errors="replace")
        else:
            handle.seek(start)
            tail = handle.read().decode("utf-8", errors="replace")
        return clip(decode(head) + "\n" + tail)


def read_error(path):
    if path:
        return read_file(path)
    if sys.stdin is None or sys.stdin.isatty():
        return ""
    return clip(decode(sys.stdin.buffer.read()))


def state_path():
    folder = os.environ.get("LBR_STATE_DIR") or os.path.join(
        tempfile.gettempdir(),
        "look-before-retry-%s" % (os.getuid() if hasattr(os, "getuid") else "user"),
    )
    os.makedirs(folder, mode=0o700, exist_ok=True)
    key = os.path.normcase(os.path.realpath(os.getcwd()))
    name = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:16]
    return os.path.join(folder, name + ".json")


def load(now):
    try:
        with open(state_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        return {
            cmd: [entry for entry in entries if now - entry["at"] < MAX_AGE_SECONDS]
            for cmd, entries in data.items()
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def save(data):
    """Write the state. Return False if it could not be written.

    Windows may lock the file for a moment (virus scanner, a second session),
    so a few retries are made. Parallel sessions can still overwrite each
    other's last entry; that only makes the counter a little too low.
    """
    target = state_path()
    temporary = "%s.%d.tmp" % (target, os.getpid())
    payload = {cmd: entries for cmd, entries in data.items() if entries}
    for _ in range(5):
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(temporary, target)
            return True
        except OSError:
            time.sleep(0.1)
    try:
        os.remove(temporary)
    except OSError:
        pass
    return False


def normalise_command(command):
    return " ".join(command.split())


def record(command, error, now=None):
    now = time.time() if now is None else now
    data = load(now)
    entries = data.setdefault(normalise_command(command), [])
    previous = entries[-1]["signature"] if entries else None
    mark = signature(error)
    entries.append({"at": now, "signature": mark})
    saved = save(data)
    same = sum(1 for entry in entries if entry["signature"] == mark)
    total = len(entries)
    reasons = []
    if same >= SAME_ERROR_LIMIT:
        reasons.append("the same error has now appeared %d times" % same)
    elif same >= 2 and previous != mark:
        reasons.append("an earlier error came back after a different one")
    if total >= TOTAL_LIMIT:
        reasons.append("this command has now failed %d times" % total)
    return {"signature": mark, "same": same, "total": total, "reasons": reasons, "saved": saved}


def reset(command=None):
    data = load(time.time())
    if command is None:
        data = {}
    else:
        data.pop(normalise_command(command), None)
    return save(data)


def bad_label(command):
    if command is not None and not LABEL.fullmatch(command):
        print(
            "--cmd must be a plain label: letters, digits, spaces and . : / = + @ , -",
            file=sys.stderr,
        )
        return True
    return False


def main(argv):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(prog="fail_log.py")
    actions = parser.add_subparsers(dest="action", required=True)
    add = actions.add_parser("record", help="log one failed run")
    add.add_argument("--cmd", required=True, help="short label, the same for the same goal")
    add.add_argument("--error-file", help="file with the output; default is stdin")
    clear = actions.add_parser("reset", help="forget failures of a command")
    group = clear.add_mutually_exclusive_group(required=True)
    group.add_argument("--cmd")
    group.add_argument("--all", action="store_true")
    actions.add_parser("status", help="show open failures")
    args = parser.parse_args(argv)

    if args.action == "record":
        if bad_label(args.cmd):
            return 2
        try:
            error = read_error(args.error_file)
        except OSError as problem:
            print("cannot read the error file: %s" % problem, file=sys.stderr)
            return 2
        if not error.strip():
            print("record needs the error output (--error-file or stdin)", file=sys.stderr)
            return 2
        result = record(args.cmd, error)
        if not result["saved"]:
            print("warning: the counter could not be saved", file=sys.stderr)
        print(
            "failure %d of this command, error %s seen %d time(s)"
            % (result["total"], result["signature"], result["same"])
        )
        if result["reasons"]:
            print("STOP: " + " and ".join(result["reasons"]) + ".")
            print("Do not edit or retry. Report to the user and wait for an answer.")
            print("After the answer, run reset for this command.")
            return 1
        print("CONTINUE: state one hypothesis, change one thing, then rerun.")
        return 0

    if args.action == "reset":
        if bad_label(args.cmd):
            return 2
        if not reset(None if args.all else args.cmd):
            print("warning: the counter could not be saved", file=sys.stderr)
        print("cleared")
        return 0

    data = {cmd: entries for cmd, entries in load(time.time()).items() if entries}
    if not data:
        print("no open failures")
    for command, entries in data.items():
        kinds = len({entry["signature"] for entry in entries})
        print("%s: %d failure(s), %d different error(s)" % (command, len(entries), kinds))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
