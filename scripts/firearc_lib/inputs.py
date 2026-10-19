"""Explicitly allowlisted research reuse; never execute the reference scripts."""

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from .integrity import (
    SafetyError, SHA256, parse_manifest, private_directory, public_name, read_json,
    regular_file, relative_name, sha256, verify_archive, verify_file, write_json,
)


def load_lock(root, name):
    value = read_json(regular_file(root, f"locks/{name}.json"))
    if value.get("schema") != 1:
        raise SafetyError(f"Unsupported {name} lock schema")
    return value


def validate_locks(root):
    baseline = load_lock(root, "research-baseline")
    if baseline.get("experiment") != "EXP-029":
        raise SafetyError("Wrong research baseline")
    spec = baseline["specification"]
    verify_file(regular_file(root, str(public_name(spec["path"]))), spec["sha256"])
    relative_name(baseline["archive_base"])
    for name, pin in baseline["manifests"].items():
        if len(relative_name(name).parts) != 1 or not SHA256.fullmatch(pin):
            raise SafetyError("Invalid archive pin")
    for name, entry in baseline["files"].items():
        if len(public_name(name).parts) != 1 or entry["archive"] not in baseline["manifests"]:
            raise SafetyError("Invalid imported file mapping")
        public_name(entry["path"])
    sources = load_lock(root, "firmware-sources")["sources"]
    if len(sources) != 9 or len({s["name"] for s in sources}) != 9:
        raise SafetyError("Expected nine distinct firmware sources")
    for source in sources:
        if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]) or not source["repository"].startswith("https://"):
            raise SafetyError("Invalid source pin/repository")
        relative_name(source["reference_path"])
    for tool in load_lock(root, "lab-tools")["tools"].values():
        if not SHA256.fullmatch(tool["sha256"]):
            raise SafetyError("Invalid tool pin")
    return baseline


def verify_reference(root, reference, *, check_sources=True):
    lock = validate_locks(root)
    reference = Path(reference).absolute()
    base = reference / lock["archive_base"]
    # Only the five explicitly pinned PUBLIC archives are visited. Never walk
    # the whole reference tree, external lab-key directories or TPM state.
    manifests = {}
    for name, pin in lock["manifests"].items():
        manifests[name] = verify_archive(base / name, pin)
    for entry in lock["files"].values():
        if entry["path"] not in manifests[entry["archive"]]:
            raise SafetyError("Selected file is absent from its pinned manifest")
    sources = []
    if check_sources:
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
        for source in load_lock(root, "firmware-sources")["sources"]:
            path = reference / source["reference_path"]
            # git status is read-only here: do not refresh/lock its index.
            command = ["git", "-C", str(path)]
            head = subprocess.check_output(command + ["rev-parse", "HEAD"], env=env, text=True).strip()
            dirty = subprocess.check_output(command + ["status", "--porcelain", "--untracked-files=no"], env=env, text=True)
            if head != source["commit"] or dirty:
                raise SafetyError(f"Wrong commit or tracked modifications in {source['name']}")
            sources.append({"name": source["name"], "commit": head, "tracked_clean": True})
    return {"passed": True, "manifest_files_checked": sum(map(len, manifests.values())),
            "manifests": dict(lock["manifests"]), "sources": sources,
            "publisher_signatures_verified": False, "private_keys_accessed": False}


def imported_path(root):
    return Path(root) / "artifacts/research/exp-029"


def import_baseline(root, reference):
    lock = validate_locks(root)
    target = imported_path(root)
    if target.exists() or target.is_symlink():
        raise SafetyError("Baseline already exists; refusing to replace it")
    report = verify_reference(root, reference)
    parent = Path(root)
    for name in ("artifacts", "research"):
        parent = private_directory(parent / name, create=True)
    stage = parent / (".exp-029-import-" + uuid.uuid4().hex[:12])
    stage.mkdir(mode=0o700)
    # An interrupted import remains an unaccepted staging directory for review;
    # no automatic recursive cleanup or overwrite of existing state.
    (stage / "manifests").mkdir(mode=0o700)
    base = Path(reference).absolute() / lock["archive_base"]
    manifests = {}
    for name, pin in lock["manifests"].items():
        source = regular_file(base / name, "SHA256SUMS")
        destination = stage / "manifests" / (name + ".sha256")
        shutil.copyfile(source, destination)
        verify_file(destination, pin)
        manifests[name] = parse_manifest(destination.read_bytes())
    for name, entry in lock["files"].items():
        source = regular_file(base / entry["archive"], entry["path"])
        with source.open("rb") as stream, (stage / name).open("xb") as output:
            shutil.copyfileobj(stream, output)
            output.flush()
            os.fsync(output.fileno())
        verify_file(stage / name, manifests[entry["archive"]][entry["path"]], scan_private=True)
        (stage / name).chmod(0o400)
    report.update(imported_at=datetime.now(timezone.utc).isoformat(),
                  reference=str(Path(reference).absolute()),
                  imported_files=sorted(lock["files"]),
                  scope="Curated public runtime fixture; original complete archives verified, not copied in full")
    write_json(stage / "import.json", report)
    stage.rename(target)
    return {"passed": True, "imported_to": str(target), "files": len(lock["files"]),
            "manifest_files_checked": report["manifest_files_checked"], "private_keys_accessed": False}


def verify_import(root):
    lock = validate_locks(root)
    target = imported_path(root)
    manifests = {}
    for name, pin in lock["manifests"].items():
        path = regular_file(target, f"manifests/{name}.sha256")
        verify_file(path, pin)
        manifests[name] = parse_manifest(path.read_bytes())
    hashes = {}
    for name, entry in lock["files"].items():
        expected = manifests[entry["archive"]][entry["path"]]
        verify_file(regular_file(target, name), expected, scan_private=True)
        hashes[name] = expected
    return hashes


def tool_paths(root, names):
    pins = load_lock(root, "lab-tools")["tools"]
    found = {}
    for name in names:
        path = shutil.which(name)
        if not path:
            raise SafetyError(f"Required tool missing: {name}; doctor does not install packages")
        verify_file(path, pins[name]["sha256"])
        found[name] = path
    return found
