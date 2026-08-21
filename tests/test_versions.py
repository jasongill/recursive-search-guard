"""Guard against version drift between the plugin manifests."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_manifest_versions_match():
    with open(os.path.join(ROOT, ".claude-plugin", "plugin.json")) as f:
        plugin_version = json.load(f)["version"]
    with open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")) as f:
        marketplace = json.load(f)
    for entry in marketplace["plugins"]:
        assert entry["version"] == plugin_version, (
            "marketplace.json plugin version does not match plugin.json; "
            "run scripts/set_version.py"
        )
