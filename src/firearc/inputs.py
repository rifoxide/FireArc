"""Project input locks and upstream provenance validation."""

import re

from .integrity import SafetyError, SHA256, public_name, read_json, regular_file, verify_file


def load_lock(root, name):
    value = read_json(regular_file(root, f"locks/{name}.json"))
    if value.get("schema") != 1:
        raise SafetyError(f"Unsupported {name} lock schema")
    return value


def validate_locks(root):
    spec = load_lock(root, "specification")
    verify_file(regular_file(root, str(public_name(spec["path"]))), spec["sha256"])
    sources = load_lock(root, "firmware-sources")["sources"]
    if not sources or len({source["name"] for source in sources}) != len(sources):
        raise SafetyError("Missing or duplicate firmware source pins")
    for source in sources:
        if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]) or not source["repository"].startswith("https://"):
            raise SafetyError("Invalid firmware source commit/URL")
    for tool in load_lock(root, "host-tools")["tools"].values():
        if not SHA256.fullmatch(tool["sha256"]):
            raise SafetyError("Invalid host compatibility pin")
    return spec
