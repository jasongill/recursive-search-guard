#!/usr/bin/env python3
"""Set the plugin version everywhere it is recorded.

Usage: python3 scripts/set_version.py X.Y.Z

Updates .claude-plugin/plugin.json, .claude-plugin/marketplace.json, and
pyproject.toml. Used by the release workflow to keep versions in sync with
GitHub release tags; safe to run by hand. Idempotent.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        sys.exit("usage: set_version.py X.Y.Z")
    version = sys.argv[1]

    plugin = ROOT / ".claude-plugin" / "plugin.json"
    data = json.loads(plugin.read_text())
    data["version"] = version
    plugin.write_text(json.dumps(data, indent=2) + "\n")

    marketplace = ROOT / ".claude-plugin" / "marketplace.json"
    data = json.loads(marketplace.read_text())
    for entry in data["plugins"]:
        entry["version"] = version
    marketplace.write_text(json.dumps(data, indent=2) + "\n")

    # Regex, not tomllib: the test suite still runs on Python 3.9 in CI.
    pyproject = ROOT / "pyproject.toml"
    text, n = re.subn(
        r'^version = "[^"]+"$',
        'version = "%s"' % version,
        pyproject.read_text(),
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        sys.exit("pyproject.toml: version line not found")
    pyproject.write_text(text)

    print("version set to %s" % version)


if __name__ == "__main__":
    main()
