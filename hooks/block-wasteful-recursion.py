#!/usr/bin/env python3
"""
Claude Code PreToolUse guard: deny accidental recursive filesystem scans
outside the current project checkout.

Coding agents occasionally fall back to commands such as `find /`,
`rg foo ~`, or `du /` when they do not immediately know where a file
lives; those scans walk huge directory trees, hit mounted volumes, and
waste time and I/O. This hook blocks recursive directory traversal
outside the current project while leaving project-local searches alone.
It is a performance guardrail, NOT a security sandbox or a complete
shell parser.

Guarded: the native Grep and Glob tools, plus Bash commands that walk
directories -- find/gfind/bfs, rg/rga, recursive grep, fd/fdfind,
ack/ag/pt, du/ncdu/gdu/dust/dua, recursive ls, tree, and eza/exa in
tree mode -- including common wrappers (sudo, env, nice, time, ...),
compound commands (`cd / && find .`), shell `-c` / eval payloads, and
`$()` / backtick substitutions.

Path policy: the project root is ${CLAUDE_PROJECT_DIR}, falling back to
the hook payload's cwd. Candidate paths are variable-expanded,
glob-prefixed, and resolved through symlinks before comparison. Paths
inside a .claude directory (such as ~/.claude/) are allowed: they hold
Claude Code's own bounded config and state. A single existing file
outside the project is allowed (no directory walk); an existing
directory outside is denied; a nonexistent literal path fails fast on
its own and is left alone.

On a blocked operation the hook exits 0 and prints PreToolUse JSON with
permissionDecision "deny", so Claude Code cancels the call and the model
retries with a targeted, project-local search. Anything this lightweight
parser cannot understand fails open, leaving normal permission handling
unchanged.

Ships as the `recursive-search-guard` plugin; hooks/hooks.json registers
this file for Bash|Grep|Glob in a single matcher, so one compound command
is judged exactly once. Install steps, tests, and design notes:
https://github.com/jasongill/recursive-search-guard

Requires Python >= 3.9. Standard library only.
"""

import json
import os
import re
import shlex
import sys
from typing import Iterable, List, Optional, Sequence, Tuple


# Commands that recursively walk directories by default or in the indicated mode.
FIND_COMMANDS = {"find", "gfind", "bfs"}
RG_COMMANDS = {"rg", "rga"}
GREP_COMMANDS = {"grep", "egrep", "fgrep"}
FD_COMMANDS = {"fd", "fdfind"}
SEARCH_COMMANDS = {"ack", "ag", "pt"}
TREE_COMMANDS = {"tree"}
TREE_LIST_COMMANDS = {"eza", "exa"}
DISK_USAGE_COMMANDS = {"du", "ncdu", "gdu", "dust", "dua"}
SHELL_COMMANDS = {"sh", "bash", "zsh", "dash", "ksh"}

# Shell wrappers we can cheaply unwrap to find the real command.
WRAPPERS = {"sudo", "env", "command", "nice", "time", "nohup"}

# rg options that consume the following argument when not written as --opt=value.
RG_VALUE_OPTIONS = {
    "-A", "-B", "-C", "-E", "-M", "-T", "-e", "-f", "-g", "-j", "-m",
    "-r", "-t",
    "--after-context", "--before-context", "--context", "--encoding",
    "--engine", "--file", "--glob", "--iglob", "--ignore-file",
    "--max-columns", "--max-count", "--max-depth", "--max-filesize",
    "--pre", "--pre-glob", "--regexp", "--replace", "--sort", "--sortr",
    "--threads", "--type", "--type-add", "--type-not",
}
RG_PATTERN_OPTIONS = {"-e", "--regexp", "-f", "--file"}

GREP_VALUE_OPTIONS = {
    "-A", "-B", "-C", "-D", "-d", "-e", "-f", "-m",
    "--after-context", "--before-context", "--binary-files", "--context",
    "--devices", "--directories", "--exclude", "--exclude-dir", "--include",
    "--label", "--max-count", "--regexp", "--file",
}
GREP_PATTERN_OPTIONS = {"-e", "--regexp", "-f", "--file"}

FD_VALUE_OPTIONS = {
    "-d", "-E", "-e", "-j", "-t", "-x", "-X",
    "--base-directory", "--changed-before", "--changed-within", "--exclude",
    "--extension", "--exec", "--exec-batch", "--max-depth", "--max-results",
    "--min-depth", "--owner", "--search-path", "--size", "--threads", "--type",
}
FD_ROOT_OPTIONS = {"--base-directory", "--search-path"}

GENERIC_SEARCH_VALUE_OPTIONS = {
    "-A", "-B", "-C", "-G", "-g", "-m", "-t",
    "--after", "--before", "--context", "--file-search-regex", "--ignore",
    "--ignore-dir", "--ignore-file", "--max-count", "--type",
}

DU_VALUE_OPTIONS = {
    "-B", "-d", "-t", "--block-size", "--exclude", "--exclude-from",
    "--max-depth", "--threshold", "--time-style",
}

TREE_VALUE_OPTIONS = {
    "-L", "-P", "-I", "--charset", "--filelimit", "--sort", "--timefmt",
}

LS_VALUE_OPTIONS = {"-I", "--ignore", "--quoting-style", "--time-style"}

EZA_VALUE_OPTIONS = {
    "-I", "-L", "-s", "--color", "--color-scale", "--git-repos",
    "--group-directories-first", "--icons", "--ignore-glob", "--level",
    "--sort", "--time-style",
}

# Shell punctuation used to divide a command into simple commands. This is not a
# complete shell grammar; it is intentionally only enough for normal agent output.
SHELL_PUNCTUATION = ";&|\n()"
GLOB_CHARS = "*?["


def deny(reason: str) -> None:
    """Return a structured PreToolUse denial; exit 0 so Claude reads the JSON."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(out, separators=(",", ":")))
    raise SystemExit(0)


def basename(token: str) -> str:
    return os.path.basename(token.rstrip("/"))


def is_assignment(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token))


def is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except (ValueError, OSError):
        return False


def within_claude_dir(path: str) -> bool:
    """True when path is a .claude directory or lives inside one."""
    return ".claude" in path.split(os.sep)


def expand_known_vars(value: str, cwd: str, repo: str, home: str) -> str:
    """Expand the path variables agents commonly emit in Bash commands."""
    replacements = {
        "$HOME": home,
        "${HOME}": home,
        "$PWD": cwd,
        "${PWD}": cwd,
        "$CLAUDE_PROJECT_DIR": repo,
        "${CLAUDE_PROJECT_DIR}": repo,
    }
    for needle, replacement in replacements.items():
        if replacement:
            value = value.replace(needle, replacement)

    value = os.path.expanduser(value)
    # Expand any other environment variable that is actually present. Unknown
    # variables remain literal; we do not guess their runtime value.
    value = os.path.expandvars(value)
    return value


def glob_prefix(path: str) -> Tuple[str, bool]:
    """Return the non-glob prefix and whether a shell glob was present."""
    indexes = [path.find(ch) for ch in GLOB_CHARS if ch in path]
    if not indexes:
        return path, False
    first = min(i for i in indexes if i >= 0)
    prefix = path[:first]
    if not prefix:
        prefix = "."
    # If the prefix ends in a partial filename component, use its parent; the
    # shell will enumerate that directory to expand the glob.
    if not prefix.endswith(os.sep):
        prefix = os.path.dirname(prefix) or "."
    return prefix, True


def resolve_candidate(raw: str, cwd: str, repo: str, home: str) -> Tuple[Optional[str], bool]:
    """Resolve a candidate search path. Returns (resolved_path, had_glob)."""
    if not raw or raw == "-":
        return None, False

    value = expand_known_vars(raw, cwd, repo, home)

    # If an unresolved variable remains at the beginning, its location is
    # unknowable without executing the shell. Fail open rather than guess.
    if re.match(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value):
        return None, False

    value, had_glob = glob_prefix(value)
    if not os.path.isabs(value):
        value = os.path.join(cwd, value)

    try:
        return os.path.realpath(value), had_glob
    except OSError:
        return os.path.abspath(value), had_glob


def outside_recursive_root(
    raw: str,
    cwd: str,
    repo: str,
    home: str,
    *,
    allow_existing_file: bool = True,
) -> Optional[Tuple[str, str]]:
    """Return (raw, resolved) when raw is an unsafe recursive directory root."""
    resolved, had_glob = resolve_candidate(raw, cwd, repo, home)
    if not resolved:
        return None
    if is_within(resolved, repo):
        return None

    # .claude directories (~/.claude, other projects' .claude/) hold Claude
    # Code's own bounded config and state, so scanning them is cheap and
    # usually intentional.
    if within_claude_dir(resolved):
        return None

    # A direct read/search of one known file is not a recursive traversal.
    if allow_existing_file and not had_glob and os.path.isfile(resolved):
        return None

    # A nonexistent literal path will fail quickly rather than walk a tree.
    # Globs are different: the shell may enumerate the existing prefix broadly.
    if not had_glob and not os.path.exists(resolved):
        return None

    return raw, resolved


def format_denial(command_name: str, raw: str, resolved: str, repo: str) -> str:
    return (
        f"Blocked recursive {command_name} scan outside the project root. "
        f"Search root {raw!r} resolves to {resolved!r}; project root is {repo!r}. "
        "Restrict the search to $CLAUDE_PROJECT_DIR (prefer rg, git ls-files, "
        "or a targeted project-local path). If the requested resource is "
        "genuinely expected outside the project, ask the user before scanning it."
    )


def strip_command_substitutions(text: str) -> Tuple[str, List[str]]:
    """
    Extract executable $() and backtick substitutions while replacing them in
    the parent command with a harmless placeholder.

    Single-quoted text is ignored because shell substitutions do not execute
    there. This is intentionally a lightweight parser, not a full shell AST.
    """
    out: List[str] = []
    subs: List[str] = []
    i = 0
    quote: Optional[str] = None

    while i < len(text):
        c = text[i]

        if c == "\\":
            out.append(c)
            if i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue

        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue

        if c == "'" and quote is None:
            quote = "'"
            out.append(c)
            i += 1
            continue

        if c == '"':
            quote = None if quote == '"' else '"'
            out.append(c)
            i += 1
            continue

        # $() executes both unquoted and inside double quotes.
        if text.startswith("$(", i):
            start = i + 2
            depth = 1
            j = start
            sub_quote: Optional[str] = None
            while j < len(text):
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if sub_quote == "'":
                    if ch == "'":
                        sub_quote = None
                    j += 1
                    continue
                if ch == "'" and sub_quote is None:
                    sub_quote = "'"
                    j += 1
                    continue
                if ch == '"':
                    sub_quote = None if sub_quote == '"' else '"'
                    j += 1
                    continue
                if sub_quote is None and text.startswith("$(", j):
                    depth += 1
                    j += 2
                    continue
                if sub_quote is None and ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1

            if depth == 0:
                subs.append(text[start:j])
                out.append("__CLAUDE_CMD_SUB__")
                i = j + 1
                continue

        # Backticks also execute unquoted and inside double quotes.
        if c == "`":
            j = i + 1
            buf: List[str] = []
            while j < len(text):
                ch = text[j]
                if ch == "\\" and j + 1 < len(text):
                    buf.append(ch)
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if ch == "`":
                    break
                buf.append(ch)
                j += 1
            if j < len(text) and text[j] == "`":
                subs.append("".join(buf))
                out.append("__CLAUDE_CMD_SUB__")
                i = j + 1
                continue

        out.append(c)
        i += 1

    return "".join(out), subs


def shell_tokens(command: str) -> Optional[List[str]]:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=SHELL_PUNCTUATION)
        lex.whitespace_split = True
        lex.commenters = ""
        # Preserve newline as punctuation so it separates simple commands.
        lex.whitespace = " \t\r"
        return list(lex)
    except ValueError:
        return None


def split_simple_commands(tokens: Sequence[str]) -> List[Tuple[List[str], str]]:
    """Split tokenized shell input into (simple_command, following_separator)."""
    result: List[Tuple[List[str], str]] = []
    current: List[str] = []
    for token in tokens:
        if token and all(ch in SHELL_PUNCTUATION for ch in token):
            if current:
                result.append((current, token))
                current = []
            else:
                result.append(([], token))
        else:
            current.append(token)
    if current:
        result.append((current, ""))
    return result


def skip_option_with_value(args: Sequence[str], i: int, value_options: Iterable[str]) -> int:
    """Return the next index after an option, consuming its value when known."""
    token = args[i]
    value_options = set(value_options)
    if token == "--":
        return i + 1
    if token.startswith("--"):
        name = token.split("=", 1)[0]
        if "=" not in token and name in value_options and i + 1 < len(args):
            return i + 2
        return i + 1
    if token in value_options and i + 1 < len(args):
        return i + 2
    # Handle common attached short option values such as -g*.py, -ePATTERN,
    # -A3. Do not attempt to decode arbitrary short-option bundles here.
    if len(token) > 2 and token[:2] in value_options:
        return i + 1
    return i + 1


def positionals(args: Sequence[str], value_options: Iterable[str]) -> List[str]:
    result: List[str] = []
    i = 0
    options_done = False
    while i < len(args):
        token = args[i]
        if options_done:
            result.append(token)
            i += 1
            continue
        if token == "--":
            options_done = True
            i += 1
            continue
        if token.startswith("-") and token != "-":
            i = skip_option_with_value(args, i, value_options)
            continue
        result.append(token)
        i += 1
    return result


def option_present(args: Sequence[str], short: str, long_names: Iterable[str]) -> bool:
    longs = set(long_names)
    for token in args:
        if token in longs:
            return True
        if token == short:
            return True
        if token.startswith("-") and not token.startswith("--") and short.startswith("-"):
            # Detect short flag bundles: -RIn contains R.
            if short[1:] and short[1] in token[1:]:
                return True
    return False


def option_supplies_pattern(args: Sequence[str], pattern_options: Iterable[str]) -> bool:
    opts = set(pattern_options)
    for token in args:
        if token in opts:
            return True
        if token.startswith("--") and token.split("=", 1)[0] in opts:
            return True
        if len(token) > 2 and token[:2] in opts:
            return True
    return False


def find_roots(args: Sequence[str]) -> List[str]:
    """Extract find/bfs search roots before the expression begins."""
    roots: List[str] = []
    i = 0

    # GNU and BSD/macOS find both permit traversal/global options before paths.
    # In particular, macOS commonly accepts `find -E PATH ...`; treating every
    # leading dash token as an expression would miss that form.
    leading_flags = {"-E", "-H", "-L", "-P", "-X", "-d", "-s", "-x"}
    while i < len(args):
        token = args[i]
        if token in leading_flags or re.match(r"^-O\d+$", token):
            i += 1
            continue
        if token == "-D" and i + 1 < len(args):
            i += 2
            continue
        # BSD find's -f path form names a search path explicitly.
        if token == "-f" and i + 1 < len(args):
            roots.append(args[i + 1])
            i += 2
            continue
        if token == "--":
            i += 1
        break

    while i < len(args):
        token = args[i]
        if token in {"!", "(", ")", ","} or (token.startswith("-") and token != "-"):
            break
        roots.append(token)
        i += 1
    return roots or ["."]


def rg_roots(args: Sequence[str]) -> List[str]:
    pos = positionals(args, RG_VALUE_OPTIONS)
    files_mode = any(a == "--files" for a in args)
    supplied_pattern = option_supplies_pattern(args, RG_PATTERN_OPTIONS)
    if files_mode or supplied_pattern:
        return pos or ["."]
    if not pos:
        return ["."]
    return pos[1:] or ["."]


def grep_is_recursive(args: Sequence[str]) -> bool:
    return option_present(args, "-r", {"--recursive"}) or option_present(
        args, "-R", {"--dereference-recursive"}
    )


def grep_roots(args: Sequence[str]) -> List[str]:
    pos = positionals(args, GREP_VALUE_OPTIONS)
    supplied_pattern = option_supplies_pattern(args, GREP_PATTERN_OPTIONS)
    if supplied_pattern:
        return pos or ["."]
    if not pos:
        return ["."]
    return pos[1:] or ["."]


def fd_roots(args: Sequence[str]) -> List[str]:
    roots: List[str] = []

    # Everything after fd's exec options is command/template argv, not another
    # search path. Exclude that tail before extracting fd operands.
    scan_args = list(args)
    for i, token in enumerate(scan_args):
        if token in {"-x", "-X", "--exec", "--exec-batch"}:
            scan_args = scan_args[:i]
            break

    # Capture explicit root-like options before generic positional parsing.
    i = 0
    while i < len(scan_args):
        token = scan_args[i]
        if token.startswith("--"):
            name, sep, attached = token.partition("=")
            if name in FD_ROOT_OPTIONS:
                if sep:
                    roots.append(attached)
                    i += 1
                    continue
                if i + 1 < len(scan_args):
                    roots.append(scan_args[i + 1])
                    i += 2
                    continue
        i += 1

    pos = positionals(scan_args, FD_VALUE_OPTIONS)
    # fd's first positional is PATTERN; subsequent positionals are search paths.
    if len(pos) > 1:
        roots.extend(pos[1:])
    if not roots:
        roots.append(".")
    return roots


def generic_search_roots(args: Sequence[str]) -> List[str]:
    pos = positionals(args, GENERIC_SEARCH_VALUE_OPTIONS)
    # ack/ag filename-only modes (-g / --file-search-regex) supply the pattern
    # via an option, so every remaining positional is a search root.
    pattern_via_option = any(
        a == "-g" or a == "--file-search-regex" or a.startswith("--file-search-regex=")
        for a in args
    )
    if pattern_via_option:
        return pos or ["."]
    # Normal mode uses PATTERN followed by optional paths.
    if not pos:
        return ["."]
    return pos[1:] or ["."]


def du_roots(args: Sequence[str]) -> List[str]:
    return positionals(args, DU_VALUE_OPTIONS) or ["."]


def ls_is_recursive(args: Sequence[str]) -> bool:
    return option_present(args, "-R", {"--recursive"})


def simple_file_roots(args: Sequence[str], value_options: Iterable[str]) -> List[str]:
    return positionals(args, value_options) or ["."]


def eza_is_tree(args: Sequence[str]) -> bool:
    return option_present(args, "-T", {"--tree"})


def unwrap_command(tokens: Sequence[str]) -> Tuple[Optional[str], List[str]]:
    """Strip simple assignments/wrappers and return (command_basename, argv)."""
    i = 0
    while i < len(tokens) and is_assignment(tokens[i]):
        i += 1

    while i < len(tokens):
        cmd = basename(tokens[i])
        if cmd not in WRAPPERS:
            return cmd, list(tokens[i + 1 :])

        i += 1
        if cmd == "sudo":
            # Common sudo flags with separate arguments.
            value_flags = {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u", "--chdir", "--group", "--host", "--prompt", "--user"}
            while i < len(tokens):
                t = tokens[i]
                if t == "--":
                    i += 1
                    break
                if not t.startswith("-") or t == "-":
                    break
                name = t.split("=", 1)[0]
                if "=" not in t and name in value_flags and i + 1 < len(tokens):
                    i += 2
                else:
                    i += 1
            continue

        if cmd == "env":
            while i < len(tokens):
                t = tokens[i]
                if t == "--":
                    i += 1
                    break
                if is_assignment(t):
                    i += 1
                    continue
                if t in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"} and i + 1 < len(tokens):
                    i += 2
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                break
            continue

        if cmd == "command":
            while i < len(tokens) and tokens[i] in {"-p", "-v", "-V", "--"}:
                i += 1
            continue

        if cmd == "nice":
            if i < len(tokens) and tokens[i] in {"-n", "--adjustment"} and i + 1 < len(tokens):
                i += 2
            elif i < len(tokens) and tokens[i].startswith("--adjustment="):
                i += 1
            elif i < len(tokens) and re.match(r"^-\d+$", tokens[i]):
                i += 1
            continue

        if cmd == "time":
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            continue

        if cmd == "nohup":
            continue

    return None, []


def check_roots(command_name: str, roots: Sequence[str], cwd: str, repo: str, home: str) -> None:
    for root in roots:
        bad = outside_recursive_root(root, cwd, repo, home)
        if bad:
            raw, resolved = bad
            deny(format_denial(command_name, raw, resolved, repo))


def analyze_simple_command(tokens: Sequence[str], cwd: str, repo: str, home: str, depth: int) -> Optional[str]:
    """Analyze one simple command. Returns a new cwd for `cd`, else None."""
    cmd, args = unwrap_command(tokens)
    if not cmd:
        return None

    if cmd == "busybox" and args:
        cmd, args = basename(args[0]), args[1:]

    # Track simple `cd` so `cd / && find .` is judged against `/`.
    if cmd in {"cd", "pushd"}:
        target = args[0] if args else home
        resolved, _ = resolve_candidate(target, cwd, repo, home)
        return resolved or cwd

    # Recursively inspect shell -c strings and eval payloads. Limit recursion to
    # avoid pathological self-referential input.
    if depth < 8 and cmd in SHELL_COMMANDS:
        for i, arg in enumerate(args):
            if arg == "-c" and i + 1 < len(args):
                analyze_bash(args[i + 1], cwd, repo, home, depth + 1)
                break
        return None

    if depth < 8 and cmd == "eval" and args:
        analyze_bash(" ".join(args), cwd, repo, home, depth + 1)
        return None

    if cmd in FIND_COMMANDS:
        check_roots(cmd, find_roots(args), cwd, repo, home)
    elif cmd in RG_COMMANDS:
        check_roots(cmd, rg_roots(args), cwd, repo, home)
    elif cmd in GREP_COMMANDS and grep_is_recursive(args):
        check_roots(cmd, grep_roots(args), cwd, repo, home)
    elif cmd in FD_COMMANDS:
        check_roots(cmd, fd_roots(args), cwd, repo, home)
    elif cmd in SEARCH_COMMANDS:
        check_roots(cmd, generic_search_roots(args), cwd, repo, home)
    elif cmd in DISK_USAGE_COMMANDS:
        check_roots(cmd, du_roots(args), cwd, repo, home)
    elif cmd == "ls" and ls_is_recursive(args):
        check_roots(cmd, simple_file_roots(args, LS_VALUE_OPTIONS), cwd, repo, home)
    elif cmd in TREE_COMMANDS:
        check_roots(cmd, simple_file_roots(args, TREE_VALUE_OPTIONS), cwd, repo, home)
    elif cmd in TREE_LIST_COMMANDS and eza_is_tree(args):
        check_roots(cmd, simple_file_roots(args, EZA_VALUE_OPTIONS), cwd, repo, home)

    return None


def analyze_bash(command: str, cwd: str, repo: str, home: str, depth: int = 0) -> None:
    if depth > 8:
        return

    stripped, substitutions = strip_command_substitutions(command)
    for sub in substitutions:
        analyze_bash(sub, cwd, repo, home, depth + 1)

    tokens = shell_tokens(stripped)
    if tokens is None:
        return  # fail open on shell parse errors

    effective_cwd = cwd
    group_cwds: List[str] = []
    for simple, separator in split_simple_commands(tokens):
        if simple:
            new_cwd = analyze_simple_command(simple, effective_cwd, repo, home, depth)
            if new_cwd:
                # `cd DIR && ...`, `cd DIR; ...`, and newline-separated commands
                # share cwd. Pipeline and `||` cases do not reliably do so.
                if "|" not in separator:
                    effective_cwd = new_cwd

        # Parenthesized shell groups run in a subshell. Preserve/restore cwd so
        # `(cd / && pwd); find .` does not poison the later project-local find.
        for ch in separator:
            if ch == "(":
                group_cwds.append(effective_cwd)
            elif ch == ")" and group_cwds:
                effective_cwd = group_cwds.pop()


def check_native_path(tool_name: str, tool_input: dict, cwd: str, repo: str, home: str) -> None:
    raw = tool_input.get("path") or cwd
    if not isinstance(raw, str):
        return

    # Grep can target one file; Glob always treats path as a search directory.
    allow_file = tool_name == "Grep"
    bad = outside_recursive_root(raw, cwd, repo, home, allow_existing_file=allow_file)
    if bad:
        original, resolved = bad
        deny(format_denial(tool_name, original, resolved, repo))


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        raise SystemExit(0)  # fail open: never block on malformed hook input

    if not isinstance(data, dict):
        raise SystemExit(0)

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    cwd = data.get("cwd") or os.getcwd()
    if not isinstance(cwd, str) or not cwd:
        cwd = os.getcwd()

    repo = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    home = os.path.expanduser("~")

    try:
        cwd = os.path.realpath(cwd)
        repo = os.path.realpath(repo)
        home = os.path.realpath(home)
    except OSError:
        # realpath is normally non-failing, but a guardrail should not brick the
        # session on an unusual filesystem condition.
        raise SystemExit(0)

    if tool_name == "Bash":
        command = tool_input.get("command") or ""
        if isinstance(command, str) and command:
            analyze_bash(command, cwd, repo, home)
    elif tool_name in {"Grep", "Glob"}:
        check_native_path(tool_name, tool_input, cwd, repo, home)

    raise SystemExit(0)


if __name__ == "__main__":
    main()
