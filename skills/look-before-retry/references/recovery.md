# Recovery notes

Each case: what to look at first, and what not to do.

## Port already in use (`EADDRINUSE`, "address already in use")

Look first:
- Your own background tasks.
- Who holds the port.

Manual commands if Python is not available (all read-only):

```powershell
# Windows PowerShell
Get-NetTCPConnection -LocalPort 3000 -State Listen | Select-Object OwningProcess
Get-Process -Id <pid>
```

```bash
lsof -nP -iTCP:3000 -sTCP:LISTEN   # macOS
ss -ltnp | grep ':3000 '           # Linux
```

Do not: stop the process just because it blocks you.

## Port held by Docker

If the owner is `docker-proxy` or a Docker backend process, a container publishes the
port. Look first: `docker ps`. Do not: stop the Docker process itself.

## Port cannot be opened although nothing listens (Windows)

Windows can reserve port ranges. Look first:
`netsh interface ipv4 show excludedportrange protocol=tcp`. Use a port outside the listed
ranges. Do not: change system network settings without the user asking for it.

## Server "runs" but the page does not load

Look first: the server output, the printed URL and port, whether the process is still alive.
Do not: start a second copy to "see if that works".

## Module or command not found

Look first: is the dependency listed, is it installed, are you in the right folder, is the
right runtime or virtual environment active, is the import spelled exactly (case matters
on Linux).
Do not: install a similarly named package without checking that it is the intended one.

## Dependency or version conflict

Look first: the two requirements that disagree, and who asks for each (`npm ls <name>`,
`pip show <name>`, the build tool's dependency report).
Do not: force the install, delete the lockfile, or try versions one after another.

## Type or compile errors

Look first: the first reported error and the definition of the types involved.
Do not: silence it with a cast, an ignore comment or a looser compiler setting.

## Suspected stale cache

Look first: evidence that something old is being used (old file path, old version number).
Clear only the specific cache you suspect, and say which one.
Do not: delete caches, `node_modules` and lockfiles together "to be safe". You will not
learn what was wrong.

## Failing test

Look first: the expected and actual values, and whether the test failed before your change
(check in a separate checkout, for example `git worktree add`, so uncommitted work stays
untouched).
Do not: change the expected value to match the output without understanding why it differs.

## Passes locally, fails in CI (or the other way round)

Look first: runtime versions, operating system, environment variable **names** (not their
values), clean checkout versus local leftovers.
Do not: push a series of guess commits. Reproduce one difference at a time.

## Install or download fails

Look first: is it the network, permissions, disk space or a missing version?
Retrying once is reasonable for a network error. Retrying an unchanged permission error
is not.
Do not: switch to an unknown mirror or run the installer with elevated rights on your own.
