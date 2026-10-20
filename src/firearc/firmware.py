"""Acquisition of pinned upstream firmware source repositories.

Exact-commit checkout only, with recorded tree inventories. No submodules are
fetched yet and nothing is built: firmware compilation, patch review and trust
qualification are separate, later steps. Host Git is a trusted tool here.
"""

import json
from pathlib import Path
import re
import subprocess

from .inputs import load_lock
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


def fetch(root, label, *, allow_network=False):
    """Clone each pinned repository and verify its exact commit."""
    identifier(label)
    sources = load_lock(root, "firmware-sources")["sources"]
    for source in sources:
        name = re.fullmatch(r"[a-z0-9][a-z0-9-]*", source["name"])
        if not name or (source.get("edk2_path") and not source["edk2_path"].startswith(("Mde", "Crypto", "Security"))):
            raise SafetyError("Unexpected firmware source pin")
    if not allow_network:
        raise SafetyError("Firmware sources absent; pass --allow-network for explicit acquisition")
    private_directory(Path(root) / "build", create=True)
    work = private_directory(Path(root) / "build/firmware", create=True) / label
    work.mkdir(mode=0o700)
    records = {}
    output = work / "output"
    output.mkdir(mode=0o700)
    for source in sources:
        repository = work / "sources" / source["name"]
        repository.parent.mkdir(parents=True, exist_ok=True)
        if repository.exists():
            raise SafetyError("Firmware source already acquired for this attempt")
        git(work, f"clone-{source['name']}", "clone", "--quiet", "--no-checkout",
            source["repository"], str(repository), timeout=1800)
        git(work, f"checkout-{source['name']}", "-C", str(repository), "checkout", "--quiet", "--detach",
            source["commit"])
        record = inventory(repository)
        if record["commit"] != source["commit"] or record["dirty"]:
            raise SafetyError(f"Acquired firmware source does not match its pin: {source['name']}")
        records[source["name"]] = record
    write_json(output / "sources.json", {"schema": 1, "sources": records,
                                         "submodules_fetched": False,
                                         "scope": "Pinned upstream checkouts only; not reviewed, built or trusted"})
    write_json(work / "result.json", {"passed": True, "artifacts": {"sources.json": sha256(output / "sources.json")},
                                      "sources": len(records),
                                      "scope": "Exact-commit acquisition; no build or security qualification"})
    return {"passed": True, "evidence": str(work), "sources": len(records),
            "scope": "Pinned firmware sources acquired; nothing built or trusted"}


def verify(root, label):
    """Re-check an existing acquisition against the pins without network."""
    identifier(label)
    work = private_directory(Path(root) / "build/firmware")
    records = read_json(regular_file(work / label, "output/sources.json"))
    if records.get("submodules_fetched"):
        raise SafetyError("Unexpected submodule state for a sources-only acquisition")
    for source in load_lock(root, "firmware-sources")["sources"]:
        record = records["sources"].get(source["name"])
        if not record or record["commit"] != source["commit"]:
            raise SafetyError(f"Acquired firmware source drift: {source['name']}")
        current = inventory(work / label / "sources" / source["name"])
        if current != record:
            raise SafetyError(f"Acquired firmware tree changed after acquisition: {source['name']}")
    return records
