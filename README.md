# Recursive Search Guard

A [Claude Code](https://code.claude.com) plugin that blocks accidental
recursive filesystem scans outside the current project. Coding agents
occasionally fall back to commands like `find /`, `rg foo ~`, or `du /`
when they don't immediately know where a file lives; those scans walk
huge directory trees, hit mounted volumes, and waste time and I/O. This
plugin denies them before they run and feeds the agent a reason, so it
retries with a targeted, project-local search instead.

It is a performance guardrail against accidental broad scans — **not** a
security sandbox or a complete shell parser.

## Install

In Claude Code:

```
/plugin marketplace add jasongill/recursive-search-guard
/plugin install recursive-search-guard@recursive-search-guard
```

Restart Claude Code (or run `/hooks`) and verify the PreToolUse hook is
listed. Quick live check: ask Claude to run `find ~ -maxdepth 0`
(denied) and `find . -maxdepth 0` (allowed).

To install from a local clone instead, use
`/plugin marketplace add ~/path/to/recursive-search-guard` followed by
the same install command.

**Requirements:** `python3` >= 3.9 on PATH (stock on modern macOS via
Xcode CLT and on most Linux distros); standard library only.

**Configuration:** none. The project root is taken from
`$CLAUDE_PROJECT_DIR` (falling back to the session's working directory),
so the guard follows whatever project the session is in.

## What is guarded

Claude Code native tools:

- **Grep** — directory searches outside the project are denied
- **Glob** — search roots outside the project are denied

Bash commands (via a lightweight shell analysis):

- `find`, `gfind`, `bfs`
- `rg`, `rga`
- `grep` when recursive (`-r`/`-R`/`--recursive`/`--dereference-recursive`)
- `fd`, `fdfind`
- `ack`, `ag`, `pt`
- `du`, `ncdu`, `gdu`, `dust`, `dua`
- `ls` when recursive (`-R`/`--recursive`)
- `tree`, and `eza`/`exa` in tree mode (`-T`/`--tree`)

The analysis also understands common wrappers (`sudo`, `env`, `command`,
`nice`, `time`, `nohup`), compound commands (`cd / && find .`), shell
`-c` payloads and `eval`, and `$()` / backtick command substitutions.

### Examples

Allowed (project-local or non-recursive):

```
find ./app
rg TODO .
grep -R TODO src/
du -sh ./tmp
rg TODO /etc/hosts     # single existing file; no directory walk
ls -la /               # not recursive
```

Denied (recursive walk outside the project):

```
find /
find ..
rg TODO ~
grep -R TODO ../
cd / && find .
echo $(find /Users)
du -sh /
tree /Users
```

Existing individual files outside the project are allowed because they
do not cause a recursive traversal. Denials fail the tool call with a
structured `permissionDecision: "deny"` and an explanatory reason; on
anything the parser cannot understand, the hook **fails open** and
leaves normal permission handling unchanged.

## Design notes

- One `Bash|Grep|Glob` matcher instead of handler-level `if` filters:
  permission rules would need several handlers and could run the script
  multiple times for one compound Bash command.
- Denials exit 0 with structured JSON so Claude Code cancels the call
  and the model sees the reason; the reason nudges it toward `rg`,
  `git ls-files`, or a targeted project-local path.
- Paths are expanded (`~`, `$HOME`, `$CLAUDE_PROJECT_DIR`, ...),
  glob-prefixed, and resolved through symlinks before comparison.

## Tests

Development-only: the hook itself stays Python 3.9 / stdlib-only, but
the test suite has no such constraint.

```
uv run pytest              # or: pip install pytest && pytest
```

The suite runs the hook as a subprocess, so the pytest interpreter and
the hook interpreter are independent. Point `HOOK_PYTHON` at a specific
Python to verify the hook under it:

```
HOOK_PYTHON=/usr/bin/python3 uv run pytest
```

Machine-independent (builds its own sandbox under a temp dir). CI runs
the suite on Python 3.9 and 3.13 on Ubuntu, and on macOS against the
runner's stock `/usr/bin/python3`.

## Releasing

Publish a GitHub release tagged `vX.Y.Z` — that's the whole procedure.
A workflow then runs `scripts/set_version.py` to write the version into
`plugin.json`, `marketplace.json`, and `pyproject.toml` and commits the
result to the default branch. Installs track the default branch, so
that commit is what users see (the tag itself keeps the previous
version, which is cosmetic). To bump by hand: `python3
scripts/set_version.py X.Y.Z`. A test guards against the manifests
disagreeing with each other.

## Limitations

- Not a security boundary; use Claude Code permissions/sandboxing for
  that. The shell analysis is intentionally lightweight.
- `cd` is not tracked across `||` or pipes (documented in the script).
- Commands not on the guarded list (e.g. `git grep -r`) are not judged.
