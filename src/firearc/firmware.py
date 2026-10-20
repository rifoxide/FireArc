"""Acquisition of pinned upstream firmware source repositories.

Exact-commit checkout only, with recorded tree inventories. Submodule
repositories named by the lock are materialized inside their parent
checkouts; the lock's gitlink census must match each pinned parent tree
exactly, so any other upstream submodule is explicitly declined rather than
silently fetched. Nothing is built: firmware compilation, patch review and
trust qualification are separate, later steps. Host Git is a trusted tool
here.
"""

import os
from pathlib import Path
import re
import subprocess

from .inputs import load_lock, validate_firmware_sources
from .integrity import SafetyError, identifier, private_directory, read_json, regular_file, sha256, write_json


def git(work, name, *arguments, timeout=600):
    command = ["git", "--no-pager", *arguments]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        (work / f"{name}.exit").write_text(str(result.returncode))
        (work / f"{name}.stderr").write_text(result.stderr)
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostics"
        raise SafetyError(f"{name} failed ({result.returncode}): {detail}")
    return result.stdout


def inventory(repository):
    """Deterministic commit/tree record for one checked-out source tree."""
    commit = git(repository.parent, "record", "-C", str(repository), "rev-parse", "HEAD").strip()
    tree = git(repository.parent, "record", "-C", str(repository), "rev-parse", "HEAD^{tree}").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise SafetyError("Unexpected Git object identity")
    return {"commit": commit, "tree": tree, "dirty": bool(git(
        repository.parent, "record", "-C", str(repository), "status", "--porcelain").strip())}


def gitlinks(work, repository):
    """Map every gitlink path recorded in HEAD to its pinned commit."""
    listing = git(work, "gitlinks", "-C", str(repository), "ls-tree", "-r", "-z", "HEAD")
    entries = {}
    for record in listing.split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        mode, kind, commit = meta.split(" ")
        if mode == "160000":
            if kind != "commit" or not re.fullmatch(r"[0-9a-f]{40}", commit) or not path:
                raise SafetyError("Unexpected Git gitlink identity")
            entries[path] = commit
    return entries


def embedded_repositories(repository):
    """Relative paths below a parent checkout that hold their own .git."""
    found = set()
    for current, directories, _files in os.walk(repository):
        current = Path(current)
        keep = []
        for entry in sorted(directories):
            if entry == ".git":
                continue
            keep.append(entry)
            if (current / entry / ".git").exists():
                found.add((current / entry).relative_to(repository).as_posix())
        directories[:] = keep
    return found


def checkout_paths(source):
    """Every checkout location (relative to sources/) for one pinned source."""
    places = [Path("sources") / source["name"]]
    return [Path("sources") / destination["repository"] / destination["path"]
            for destination in source.get("destinations", [])] or places


def acquire(work, relative, source, sequence):
    """Clone one pinned source at one location and verify its checkout."""
    repository = work / relative
    repository.parent.mkdir(parents=True, exist_ok=True)
    if repository.exists() and (not repository.is_dir() or any(repository.iterdir())):
        raise SafetyError("Firmware source already acquired for this attempt")
    label = f"{source['name']}-{sequence}"
    git(work, f"clone-{label}", "clone", "--quiet", "--no-checkout",
        source["repository"], str(repository), timeout=1800)
    git(work, f"checkout-{label}", "-C", str(repository), "checkout", "--quiet", "--detach",
        source["commit"])
    record = inventory(repository)
    if record["commit"] != source["commit"] or record["dirty"]:
        raise SafetyError(f"Acquired firmware source does not match its pin: {source['name']}")
    return record


def fetch(root, label, *, allow_network=False):
    """Clone each pinned repository, verify commits and materialize listed submodules."""
    identifier(label)
    lock = load_lock(root, "firmware-sources")
    validate_firmware_sources(lock)
    if not allow_network:
        raise SafetyError("Firmware sources absent; pass --allow-network for explicit acquisition")
    private_directory(Path(root) / "build", create=True)
    work = private_directory(Path(root) / "build/firmware", create=True) / label
    work.mkdir(mode=0o700)
    records = {}
    output = work / "output"
    output.mkdir(mode=0o700)
    parents = [source for source in lock["sources"] if not source.get("destinations")]
    submodules = [source for source in lock["sources"] if source.get("destinations")]
    census = {}
    for source in parents:
        repository = work / "sources" / source["name"]
        records[source["name"]] = acquire(work, Path("sources") / source["name"], source, 0)
        census[source["name"]] = gitlinks(work, repository)
        if census[source["name"]] != lock["gitlink_census"][source["name"]]:
            raise SafetyError(f"Pinned tree gitlinks differ from the locked census: {source['name']}")
    materialized = []
    for source in submodules:
        record = None
        for sequence, destination in enumerate(source["destinations"], 1):
            if census[destination["repository"]][destination["path"]] != source["commit"]:
                raise SafetyError(f"Locked submodule pin disagrees with the parent gitlink: {source['name']}")
            relative = Path("sources") / destination["repository"] / destination["path"]
            current = acquire(work, relative, source, sequence)
            if record is None:
                record = current
            elif current != record:
                raise SafetyError(f"Submodule checkouts disagree for one pin: {source['name']}")
            materialized.append(f"{destination['repository']}:{destination['path']}")
        records[source["name"]] = record
    for source in parents:
        repository = work / "sources" / source["name"]
        if git(work, "parent-status", "-C", str(repository), "status", "--porcelain").strip():
            raise SafetyError(f"Materialized submodules diverge from the parent gitlinks: {source['name']}")
        expected = {destination["path"] for other in submodules
                    for destination in other["destinations"] if destination["repository"] == source["name"]}
        if embedded_repositories(repository) != expected:
            raise SafetyError(f"Unexpected materialized submodule below {source['name']}")
    materialized.sort()
    write_json(output / "sources.json", {"schema": 2, "sources": records, "gitlink_census": census,
                                         "materialized": materialized, "submodules_fetched": True,
                                         "scope": "Pinned upstream checkouts with listed submodules materialized; "
                                                  "not reviewed, built or trusted"})
    write_json(work / "result.json", {"passed": True, "artifacts": {"sources.json": sha256(output / "sources.json")},
                                      "sources": len(records), "submodules": len(materialized),
                                      "scope": "Exact-commit acquisition incl. pinned submodule closure; "
                                               "no build or security qualification"})
    return {"passed": True, "evidence": str(work), "sources": len(records), "submodules": len(materialized),
            "scope": "Pinned firmware sources acquired with submodule closure; nothing built or trusted"}


def verify(root, label):
    """Re-check an existing acquisition against the pins without network."""
    identifier(label)
    work = private_directory(Path(root) / "build/firmware")
    records = read_json(regular_file(work / label, "output/sources.json"))
    lock = load_lock(root, "firmware-sources")
    validate_firmware_sources(lock)
    if records.get("schema") != 2 or not records.get("submodules_fetched"):
        raise SafetyError("Acquisition predates submodule closure; re-acquire with just firmware-sources --online")
    census = {}
    for source in lock["sources"]:
        record = records["sources"].get(source["name"])
        if not record or record["commit"] != source["commit"]:
            raise SafetyError(f"Acquired firmware source drift: {source['name']}")
        for relative in checkout_paths(source):
            repository = work / label / relative
            if not repository.is_dir():
                raise SafetyError(f"Acquired firmware checkout missing: {source['name']} at {relative}")
            if inventory(repository) != record:
                raise SafetyError(f"Acquired firmware tree changed after acquisition: {source['name']}")
        if not source.get("destinations"):
            repository = work / label / "sources" / source["name"]
            census[source["name"]] = gitlinks(work, repository)
            if census[source["name"]] != lock["gitlink_census"][source["name"]]:
                raise SafetyError(f"Acquired tree gitlinks differ from the locked census: {source['name']}")
            if git(work, "parent-status", "-C", str(repository), "status", "--porcelain").strip():
                raise SafetyError(f"Materialized submodules diverge from the parent gitlinks: {source['name']}")
    if census != records.get("gitlink_census"):
        raise SafetyError("Recorded gitlink census no longer matches the acquired trees")
    for source in [source for source in lock["sources"] if not source.get("destinations")]:
        expected = {destination["path"] for other in lock["sources"]
                    for destination in other.get("destinations", []) if destination["repository"] == source["name"]}
        if embedded_repositories(work / label / "sources" / source["name"]) != expected:
            raise SafetyError(f"Unexpected materialized submodule below {source['name']}")
    return records
