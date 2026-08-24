"""Pytest suite for the recursive-search-guard PreToolUse hook.

Development-only: the hook itself must stay Python 3.9 / stdlib-only
(it runs on end users' machines), but this suite has no such constraint.
It runs the hook as a subprocess, so the pytest interpreter and the hook
interpreter are independent. Point HOOK_PYTHON at a specific Python to
verify the hook under it:

    HOOK_PYTHON=/usr/bin/python3 uv run pytest

Machine-independent: builds a throwaway project root and an "outside"
directory under a temp dir, overrides HOME for the hook subprocess, and
feeds hook payloads via stdin exactly as Claude Code would.
"""
import json
import os
import subprocess
import sys

import pytest

HOOK = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "hooks",
    "block-wasteful-recursion.py",
)
HOOK_PYTHON = os.environ.get("HOOK_PYTHON") or sys.executable


@pytest.fixture(scope="session")
def sandbox(tmp_path_factory):
    """Fake home containing the project, plus a sibling tree outside it."""
    home = tmp_path_factory.mktemp("home")
    proj = home / "project"
    (proj / "app").mkdir(parents=True)
    outside = home / "elsewhere"
    (outside / "docs").mkdir(parents=True)
    outside_file = outside / "notes.txt"
    outside_file.write_text("hello\n")
    (home / ".claude" / "plugins").mkdir(parents=True)
    (outside / ".claude").mkdir()
    return {
        "home": str(home),
        "proj": str(proj),
        "proj_app": str(proj / "app"),
        "outside": str(outside),
        "outside_file": str(outside_file),
        "home_claude": str(home / ".claude"),
    }


def run_hook(stdin_text, home, proj_env):
    env = dict(os.environ)
    env["HOME"] = home  # so ~ resolves inside the sandbox
    env.pop("CLAUDE_PROJECT_DIR", None)
    if proj_env:
        env["CLAUDE_PROJECT_DIR"] = proj_env
    r = subprocess.run(
        [HOOK_PYTHON, HOOK], input=stdin_text, env=env,
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    got = "deny" if '"permissionDecision":"deny"' in r.stdout else "allow"
    return got, r


# (id, bash command template, expected decision, set CLAUDE_PROJECT_DIR?)
# Templates may reference {outside} and {outside_file} from the sandbox.
BASH_CASES = [
    # --- recursive scans outside the project: denied ---
    ("find-root", "find /", "deny", True),
    ("find-parent", "find ..", "deny", True),
    ("find-tilde", "find ~", "deny", True),
    ("find-abs-outside", "find {outside}", "deny", True),
    ("find-multi-root", "find . {outside}", "deny", True),
    ("cd-root-then-find", "cd / && find .", "deny", True),
    ("cd-outside-then-find", "cd {outside} && find .", "deny", True),
    ("rg-root", "rg TODO /", "deny", True),
    ("rg-tilde", "rg TODO ~", "deny", True),
    ("rg-outside-dir", "rg TODO {outside}", "deny", True),
    ("grep-R-parent", "grep -R TODO ../", "deny", True),
    ("grep-rn-bundle", "grep -rn TODO {outside}", "deny", True),
    ("fd-root", "fd . /", "deny", True),
    ("du-root", "du -sh /", "deny", True),
    ("du-outside", "du -sh {outside}", "deny", True),
    ("ls-R-tilde", "ls -R ~", "deny", True),
    ("tree-outside", "tree {outside}", "deny", True),
    ("eza-tree-outside", "eza --tree {outside}", "deny", True),
    ("ag-outside", "ag foo {outside}", "deny", True),
    ("rg-files-outside", "rg --files {outside}", "deny", True),
    ("find-leading-L-flag", "find -L {outside} -name x", "deny", True),
    ("glob-prefix-outside", "rg TODO {outside}/*", "deny", True),
    # --- wrappers / substitutions / nested shells: denied ---
    ("sudo-find-outside", "sudo find {outside} -name x", "deny", True),
    ("sudo-u-flag", "sudo -u root find {outside}", "deny", True),
    ("env-wrapper", "env FOO=1 find {outside}", "deny", True),
    ("time-wrapper", "time find {outside}", "deny", True),
    ("bash-c-payload", "bash -c 'find {outside}'", "deny", True),
    ("eval-payload", 'eval "find {outside}"', "deny", True),
    ("dollar-substitution", "echo $(find {outside})", "deny", True),
    ("backtick-substitution", "echo `find {outside}`", "deny", True),
    ("pipe-separator", "find {outside} | head", "deny", True),
    # --- project-local and non-recursive work: allowed ---
    ("find-cwd", "find .", "allow", True),
    ("find-subdir", "find ./app", "allow", True),
    ("find-no-path", "find -name x", "allow", True),
    ("rg-cwd", "rg TODO .", "allow", True),
    ("rg-project-var", 'rg TODO "$CLAUDE_PROJECT_DIR"', "allow", True),
    ("grep-R-relative", "grep -R TODO src/", "allow", True),
    ("du-project-subdir", "du -sh ./tmp", "allow", True),
    ("rg-single-outside-file", "rg TODO {outside_file}", "allow", True),
    ("grep-nonrecursive-outside", "grep TODO {outside_file}", "allow", True),
    ("ls-nonrecursive-root", "ls -la /", "allow", True),
    ("ls-R-inside", "ls -R .", "allow", True),
    ("eza-non-tree", "eza -la {outside}", "allow", True),
    ("nonexistent-fails-fast", "find /nonexistent-zzz-123", "allow", True),
    # --- .claude directories hold Claude Code's own bounded state: allowed ---
    ("find-home-claude", "find ~/.claude", "allow", True),
    ("rg-home-claude-subdir", "rg TODO ~/.claude/plugins", "allow", True),
    ("rg-home-claude-glob", "rg TODO ~/.claude/*", "allow", True),
    ("du-other-claude-dir", "du -sh {outside}/.claude", "allow", True),
    ("cd-claude-then-find", "cd ~/.claude && find .", "allow", True),
    ("find-claude-dotdot-escape", "find ~/.claude/..", "deny", True),
    ("single-quoted-sub-inert", "echo 'find / is slow'", "allow", True),
    ("subshell-cwd-restored", "(cd / && pwd); find .", "allow", True),
    ("or-does-not-track-cwd", "cd {outside} || find .", "allow", True),
    ("unguarded-command", "git grep -r x /", "allow", True),
    # --- CLAUDE_PROJECT_DIR fallback to payload cwd ---
    ("fallback-deny", "find {outside}", "deny", False),
    ("fallback-allow", "find .", "allow", False),
]

# (id, tool, sandbox key for path or None, expected decision)
NATIVE_CASES = [
    ("grep-dir-outside", "Grep", "outside", "deny"),
    ("grep-single-outside-file", "Grep", "outside_file", "allow"),
    ("grep-inside-project", "Grep", "proj_app", "allow"),
    ("grep-home-claude", "Grep", "home_claude", "allow"),
    ("glob-outside", "Glob", "outside", "deny"),
    ("glob-home-claude", "Glob", "home_claude", "allow"),
    ("glob-default-path", "Glob", None, "allow"),
    ("glob-project-root", "Glob", "proj", "allow"),
]

# (id, raw stdin) -- malformed input must fail open (allow, exit 0)
RAW_CASES = [
    ("empty-stdin", ""),
    ("garbage-stdin", "not json"),
    ("non-dict-json", '"just a string"'),
]


@pytest.mark.parametrize(
    "cmd_template,expect,with_proj",
    [c[1:] for c in BASH_CASES],
    ids=[c[0] for c in BASH_CASES],
)
def test_bash_command(sandbox, cmd_template, expect, with_proj):
    cmd = cmd_template.format(**sandbox)
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": sandbox["proj"]}
    )
    proj_env = sandbox["proj"] if with_proj else None
    got, r = run_hook(payload, sandbox["home"], proj_env)
    assert got == expect, r.stdout


@pytest.mark.parametrize(
    "tool,path_key,expect",
    [c[1:] for c in NATIVE_CASES],
    ids=[c[0] for c in NATIVE_CASES],
)
def test_native_tool(sandbox, tool, path_key, expect):
    tool_input = {} if path_key is None else {"path": sandbox[path_key]}
    payload = json.dumps(
        {"tool_name": tool, "tool_input": tool_input, "cwd": sandbox["proj"]}
    )
    got, r = run_hook(payload, sandbox["home"], sandbox["proj"])
    assert got == expect, r.stdout


@pytest.mark.parametrize(
    "stdin_text",
    [c[1] for c in RAW_CASES],
    ids=[c[0] for c in RAW_CASES],
)
def test_malformed_input_fails_open(sandbox, stdin_text):
    got, r = run_hook(stdin_text, sandbox["home"], sandbox["proj"])
    assert got == "allow", r.stdout


def test_missing_tool_input_fails_open(sandbox):
    payload = json.dumps({"tool_name": "Bash", "cwd": sandbox["proj"]})
    got, r = run_hook(payload, sandbox["home"], sandbox["proj"])
    assert got == "allow", r.stdout
