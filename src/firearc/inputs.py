"""Project input locks and upstream provenance validation."""

import re

from .integrity import SafetyError, SHA256, public_name, read_json, regular_file, verify_file


LOCK_SCHEMAS = {"firmware-sources": 2}


def load_lock(root, name):
    value = read_json(regular_file(root, f"locks/{name}.json"))
    if value.get("schema") != LOCK_SCHEMAS.get(name, 1):
        raise SafetyError(f"Unsupported {name} lock schema")
    return value


def destination_path(path):
    """True for a safe relative checkout path inside a parent source tree."""
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    return all(part not in ("", ".", "..", ".git") for part in path.split("/"))


def validate_firmware_sources(lock):
    """Structural closure check: pins, destinations and gitlink census agree."""
    sources = lock["sources"]
    if not sources or len({source["name"] for source in sources}) != len(sources):
        raise SafetyError("Missing or duplicate firmware source pins")
    for source in sources:
        if not isinstance(source.get("repository"), str) or not source["repository"] \
                or set(source) - {"name", "repository", "commit", "destinations"}:
            raise SafetyError("Unexpected firmware source pin fields")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", source["name"]) \
                or not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
            raise SafetyError("Invalid firmware source pin")
    top = {source["name"] for source in sources if not source.get("destinations")}
    census = lock.get("gitlink_census")
    if not isinstance(census, dict) or set(census) != top:
        raise SafetyError("Gitlink census must cover exactly the top-level sources")
    for name, entries in census.items():
        if not isinstance(entries, dict):
            raise SafetyError(f"Invalid gitlink census for {name}")
        for path, commit in entries.items():
            if not destination_path(path) or not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
                raise SafetyError(f"Invalid gitlink census entry for {name}")
    paths = set()
    for source in sources:
        for destination in source.get("destinations", []):
            if not isinstance(destination, dict) or set(destination) != {"repository", "path"} \
                    or destination["repository"] not in top or destination["repository"] == source["name"] \
                    or not destination_path(destination["path"]):
                raise SafetyError(f"Invalid submodule destination: {source['name']}")
            if destination["path"] in paths:
                raise SafetyError(f"Duplicate submodule destination path: {destination['path']}")
            if census[destination["repository"]].get(destination["path"]) != source["commit"]:
                raise SafetyError(f"Submodule pin not bound to its parent gitlink: {source['name']}")
            paths.add(destination["path"])
    return sources


def validate_locks(root):
    spec = load_lock(root, "specification")
    verify_file(regular_file(root, str(public_name(spec["path"]))), spec["sha256"])
    sources = validate_firmware_sources(load_lock(root, "firmware-sources"))
    for source in sources:
        if not source["repository"].startswith("https://"):
            raise SafetyError("Invalid firmware source commit/URL")
    for tool in load_lock(root, "host-tools")["tools"].values():
        if not SHA256.fullmatch(tool["sha256"]):
            raise SafetyError("Invalid host compatibility pin")
    return spec
