# Recursive Search Guard for Claude Code

A Claude Code plugin that blocks accidental recursive filesystem scans
outside the current project. Coding agents occasionally fall back to
commands like `find /`, `rg foo ~`, or `du /` when they don't
immediately know where a file lives; those scans walk huge directory
trees, hit mounted volumes, and waste time and I/O.

This plugin denies them before they run and feeds the agent a reason,
so it retries with a targeted, project-local search instead.

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

Requires only `python3` >= 3.9 in your PATH (stock on modern macOS via
Xcode CLT and on most Linux distros). No configuration is required.

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
find ~/.claude         # .claude dirs hold Claude Code's own config/state
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
do not cause a recursive traversal. Searches rooted inside a `.claude`
directory (`~/.claude/`, another project's `.claude/`) are allowed too:
those directories hold Claude Code's own bounded config and state. Denials fail the tool call with a
structured `permissionDecision: "deny"` and an explanatory reason; on
anything the parser cannot understand, the hook **fails open** and
leaves normal permission handling unchanged.