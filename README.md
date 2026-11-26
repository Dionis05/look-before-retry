# look-before-retry

An Agent Skill for Claude Code against two everyday annoyances:

1. **A second dev server** gets started although one is already running.
2. **Blind fix loops:** a build fails, something gets changed, it fails again, and so on.

The idea in one line: *check what is true right now before acting again.*

## What is inside

| Part | What it does |
|---|---|
| `SKILL.md` | Rules for when to check, when to stop and how to report |
| `scripts/check_port.py` | Says whether a port is free, in use (and by whom) or blocked |
| `scripts/fail_log.py` | Says STOP after the same error three times, when an old error comes back, or after eight failures |
| `references/recovery.md` | Short notes for common error types |

The scripts need Python 3 and no extra packages. They never stop processes and write
nothing into your project. The limits (3 and 8) are a judgement call, not a measured
optimum.

**Status:** the unit tests pass on Ubuntu, Windows and macOS (GitHub Actions). In addition
there were manual runs on Windows 11 (German) with Python 3.13 and Claude Code: the port
check reported a busy port correctly, Claude loaded the skill, left the running server
alone, and stopped after three identical failures. That is two runs, not a measurement
of how often the skill helps. macOS was only tested in CI.

## Install

Needs Python 3. On Windows: `winget install Python.Python.3.13`, then open a **new**
terminal window so that `py` is found.

With the `skills` CLI (needs Node.js, not tested with this repo yet):

```bash
npx skills add Dionis05/look-before-retry
```

By hand: copy the folder `skills/look-before-retry` to `~/.claude/skills/` (all
projects) or to `.claude/skills/` inside one project.

Claude decides from the description when to load a skill, so it may not load every time.
To make it more likely, add this to your `CLAUDE.md`:

```
Use the look-before-retry skill before starting a server and when a build or test fails.
```

## Limits

- A skill is guidance, not enforcement. Nothing is blocked if Claude does not follow it.
- Whether this measurably reduces loops or duplicate servers has **not** been measured.
- `check_port.py` looks at TCP ports on this machine only. It does not look inside
  containers or at remote hosts. Without extra permissions the owner may stay unknown,
  and on Windows the process folder is not shown.
- Secrets in printed command lines are hidden on a best-effort basis. Some can slip
  through (for example `mysql -pSECRET`).
- The error fingerprint is a heuristic. It can treat two errors as equal or different
  when a person would not.
- The failure counter is shared by all sessions in the same folder and expires after
  two hours. Two sessions writing at the same moment can lose one count.
- When no full socket table is available (for example `lsof` without extra rights),
  `check_port.py` falls back to a short test connection, which the listening program
  will notice.

## Tests

```bash
python -m unittest discover -s tests -v
```

A GitHub Actions workflow runs them on Ubuntu, Windows and macOS. The tests cover the
scripts and the format of `SKILL.md`, not how Claude behaves.

## Related work

Worth a look, and some of it goes further:

- [obra/superpowers](https://github.com/obra/superpowers) (systematic debugging)
- [Shiroe-95/groundhog](https://github.com/Shiroe-95/groundhog) (loop detection)

## Credits and license

Written with the help of Claude (AI). See [LICENSE](LICENSE): free to download, use and
adapt for yourself, not to be re-published as a repository, package or listing.
