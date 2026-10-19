"""Offline root filesystem payloads and explicit headerless verity authority.

No device activation/mounting, signing, provisioning or host block-device access.
This consumes the pinned, already-built project root stage.
"""

import hashlib
import os
from pathlib import Path
import re
import shutil

from . import builder
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, sha256,
    verify_file, write_json,
)

ROOT_BYTES = 4 * 1024**3
HASH_BYTES = 128 * 1024**2
BLOCK_SIZE = 4096


def verity_args(authority):
    """Geometry is fixed by this format, not accepted from an on-disk header."""
    integers = ("schema", "format", "data_bytes", "hash_bytes", "data_blocks",
                "data_block_size", "hash_block_size", "hash_offset")
    if (not isinstance(authority, dict) or any(type(authority.get(key)) is not int for key in integers)
            or not isinstance(authority.get("salt"), str)
            or "root_hash" in authority and not isinstance(authority["root_hash"], str)):
        raise SafetyError("Invalid root-payload authority types")
    if (authority.get("schema") != 1 or authority.get("format") != 1
            or authority.get("algorithm") != "sha256"
            or authority.get("data_bytes") != ROOT_BYTES
            or authority.get("hash_bytes") != HASH_BYTES
            or authority.get("data_blocks") != ROOT_BYTES // BLOCK_SIZE
            or authority.get("data_block_size") != BLOCK_SIZE
            or authority.get("hash_block_size") != BLOCK_SIZE
            or authority.get("hash_offset") != 0
            or not re.fullmatch(r"[0-9a-f]{64}", authority.get("salt", ""))
            or "root_hash" in authority and not re.fullmatch(r"[0-9a-f]{64}", authority["root_hash"])):
        raise SafetyError("Invalid root-payload verity authority/geometry")
    return ["--no-superblock", "--format=1", "--hash=sha256",
            f"--data-blocks={authority['data_blocks']}", f"--data-block-size={BLOCK_SIZE}",
            f"--hash-block-size={BLOCK_SIZE}", "--hash-offset=0", "--salt=" + authority["salt"]]


def parse_root_hash(text):
    rows = re.findall(r"^Root hash:\s*([0-9a-f]{64})\s*$", text, re.MULTILINE)
    if len(rows) != 1:
        raise SafetyError("Expected exactly one SHA-256 verity root hash")
    return rows[0]


def render_initrd_authority(authority, slot):
    """Strict text for the trusted initrd parser, never sourced as shell code."""
    verity_args(authority)
    if slot not in {"A", "B"} or not re.fullmatch(r"[0-9a-f]{64}", authority.get("root_hash", "")):
        raise SafetyError("Expected an explicit A/B slot and complete verity digest")
    fields = {"schema": 1, "layout_version": 1, "slot": slot, **authority}
    keys = ("schema", "layout_version", "slot", "root_hash", "salt", "format", "algorithm",
            "data_bytes", "data_blocks", "data_block_size", "hash_bytes", "hash_block_size", "hash_offset")
    # Do not allow optional metadata in a JSON record to replace slot/layout.
    fields["slot"], fields["layout_version"] = slot, 1
    return "".join(f"{key}={fields[key]}\n" for key in keys)


def expect_integrity_denial(work, name, command):
    try:
        builder.logged(work, name, command, timeout=600)
    except SafetyError:
        status = read_json(regular_file(work, name + ".exit.json"))
        stderr = regular_file(work, name + ".stderr").read_text()
        # cryptsetup distinguishes damaged data/tree (2) from a coherent tree
        # with a different top digest (1). Neither a generic exit 1 nor 2 is
        # sufficient: require the corresponding explicit integrity diagnostic.
        if ((status.get("returncode") == 2 and re.search(r"^Verification failed at position [0-9]+\.", stderr, re.MULTILINE))
                or (status.get("returncode") == 1 and "Verification of root hash failed." in stderr.splitlines())):
            return
        raise SafetyError(f"{name} did not produce an expected verity integrity denial")
    raise SafetyError(f"{name} unexpectedly accepted corrupted/substituted payloads")


def flip_byte(path, offset):
    if not 0 <= offset < path.stat().st_size:
        raise SafetyError("Corruption offset is outside the copied fixture")
    with path.open("r+b") as stream:
        stream.seek(offset)
        value = stream.read(1)
        stream.seek(offset)
        stream.write(bytes([value[0] ^ 1]))
        stream.flush()
        os.fsync(stream.fileno())


def check(root, tools_label, source_label, label):
    """Full userspace verification and corruption controls on copied payloads."""
    identifier(source_label)
    identifier(label)
    builder.verify_tools(root, tools_label)
    source = private_directory(Path(root) / "build/images" / source_label)
    result = read_json(regular_file(source, "result.json"))
    if not result.get("passed") or not result.get("full_verity_verified"):
        raise SafetyError("Expected successfully frozen and verified root payloads")
    output = private_directory(source / "output")
    for name, digest in result["artifacts"].items():
        verify_file(regular_file(output, name), digest)
    data = regular_file(output, result["root_payload"])
    tree = regular_file(output, "root.verity")
    authority = read_json(regular_file(output, "verity-authority.json"))
    args = verity_args(authority)
    if (not re.fullmatch(r"[0-9a-f]{64}", authority.get("root_hash", ""))
            or data.stat().st_size != ROOT_BYTES or tree.stat().st_size != HASH_BYTES):
        raise SafetyError("Root-payload size/digest authority is invalid")
    tools_work = builder.parent(root) / identifier(tools_label)
    exported = read_json(regular_file(tools_work, "export-result.json"))
    source_inputs = read_json(regular_file(source, "inputs.json"))
    if source_inputs["tools_inventory_sha256"] != sha256(tools_work / "tools-inventory.json"):
        raise SafetyError("Payload and verification tools differ")
    image = exported["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid verification tools-image identity")
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    fixtures = work / "fixtures"
    fixtures.mkdir(mode=0o700)
    options = builder.docker_args(image) + ["--env", "LC_ALL=C", "--mount",
               f"type=bind,src={output},dst=/source,readonly", "--mount",
               f"type=bind,src={fixtures},dst=/fixtures", image]
    write_json(work / "inputs.json", {"source_result_sha256": sha256(source / "result.json"),
                                      "authority_sha256": sha256(output / "verity-authority.json"),
                                      "tools_image_id": image})
    good = ["veritysetup", "verify", "/source/" + data.name, "/source/root.verity", authority["root_hash"], *args]
    try:
        builder.logged(work, "ext4-check-readonly", options + ["e2fsck", "-f", "-n", "/source/" + data.name], timeout=600)
        builder.logged(work, "verify-good-before", options + good, timeout=600)
        builder.logged(work, "copy-data", options + ["cp", "--reflink=auto", "--sparse=always", "--",
                                                     "/source/" + data.name, "/fixtures/root.raw"], timeout=600)
        builder.logged(work, "copy-tree", options + ["cp", "--reflink=auto", "--sparse=always", "--",
                                                     "/source/root.verity", "/fixtures/root.verity"], timeout=600)
        flip_byte(regular_file(fixtures, "root.raw"), ROOT_BYTES - 1)
        expect_integrity_denial(work, "reject-data-tail", options + ["veritysetup", "verify", "/fixtures/root.raw",
                                "/source/root.verity", authority["root_hash"], *args])
        flip_byte(regular_file(fixtures, "root.verity"), 0)
        expect_integrity_denial(work, "reject-hash-tree", options + ["veritysetup", "verify", "/source/" + data.name,
                                "/fixtures/root.verity", authority["root_hash"], *args])
        # Reformatting this private COPY proves a replacement root/tree pair is
        # internally coherent, while the original authority must still deny it.
        text = builder.logged(work, "format-replacement", options + ["veritysetup", "format", "/fixtures/root.raw",
                              "/fixtures/root.verity", *args], timeout=600)
        replacement = parse_root_hash(text)
        if replacement == authority["root_hash"]:
            raise SafetyError("Substituted root unexpectedly has the original digest")
        builder.logged(work, "verify-replacement-own-digest", options + ["veritysetup", "verify", "/fixtures/root.raw",
                       "/fixtures/root.verity", replacement, *args], timeout=600)
        expect_integrity_denial(work, "reject-replacement-original-authority", options + ["veritysetup", "verify",
                                "/fixtures/root.raw", "/fixtures/root.verity", authority["root_hash"], *args])
        builder.logged(work, "verify-good-after", options + good, timeout=600)
        for name, digest in result["artifacts"].items():
            verify_file(regular_file(output, name), digest)
        builder.verify_tools(root, tools_label)
        write_json(work / "result.json", {"passed": True, "full_range_bytes": ROOT_BYTES,
                                          "ext4_readonly_check_passed": True,
                                          "negative_controls": ["data-tail", "hash-tree", "replacement-pair"],
                                          "originals_unchanged": True, "boot_chain_qualified": False,
                                          "scope": "Userspace verification only; no initrd/runtime-dm-verity qualification"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error), "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work), "scope": "Offline verity corruption controls"}


def create(root, tools_label, source_label, label):
    identifier(source_label)
    identifier(label)
    tools = builder.verify_tools(root, tools_label)
    source = private_directory(Path(root) / "build/images" / source_label)
    result = read_json(regular_file(source, "result.json"))
    inputs = read_json(regular_file(source, "inputs.json"))
    if (not result.get("passed") or not result.get("built") or result.get("profile") != "root"
            or inputs.get("builder_lock_sha256") != sha256(Path(root) / "locks/debian-build.json")):
        raise SafetyError("Expected a successful appliance-root stage with matching builder inputs")
    archive = regular_file(source / "output", "firearc-root.tar")
    verify_file(archive, result["artifacts"][archive.name])
    builder.inspect_root_tar(archive, builder.root_lock(root))
    tools_work = builder.parent(root) / identifier(tools_label)
    exported = read_json(regular_file(tools_work, "export-result.json"))
    if inputs.get("tools_inventory_sha256") != sha256(tools_work / "tools-inventory.json"):
        raise SafetyError("Source and payload tools inventories differ")
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    for name in ("output", "workspace", "cache", "package-cache", "home", "tmp", "sandbox"):
        (work / name).mkdir(mode=0o700)
    shutil.copytree(Path(root) / "images/rootfs", work / "config")
    inventory = builder.tree_inventory(work / "config")
    write_json(work / "config-inventory.json", inventory)
    write_json(work / "inputs.json", {"source_label": source_label, "source_tar_sha256": sha256(archive),
                                      "source_inputs_sha256": sha256(source / "inputs.json"),
                                      "tools_inventory_sha256": sha256(tools_work / "tools-inventory.json"),
                                      "config_inventory_sha256": sha256(work / "config-inventory.json"),
                                      "scope": "Unsigned payload assembly; not installed-disk or boot qualification"})
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
           "XDG_CACHE_HOME": str(work / "cache"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONPATH": str(tools / "usr/lib/python3/dist-packages"), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    command = builder.mkosi_command(tools, work, build=True)
    command[-1:-1] = ["--base-tree", str(archive)]
    try:
        builder.logged(work, "mkosi-rootfs", command, env=env, timeout=1800)
        output = work / "output"
        candidates = [p for p in output.iterdir() if p.is_file() and not p.is_symlink()
                      and p.name.endswith(".root-x86-64.raw")]
        if len(candidates) != 1 or candidates[0].stat().st_size != ROOT_BYTES:
            raise SafetyError("Expected exactly one full-size 4 GiB root partition payload")
        data = candidates[0]
        digest = sha256(data)
        authority = {"schema": 1, "format": 1, "algorithm": "sha256", "data_bytes": ROOT_BYTES,
                     "hash_bytes": HASH_BYTES, "data_blocks": ROOT_BYTES // BLOCK_SIZE,
                     "data_block_size": BLOCK_SIZE, "hash_block_size": BLOCK_SIZE, "hash_offset": 0,
                     "salt": hashlib.sha256(b"firearc-root-verity-v1\0" + bytes.fromhex(digest)).hexdigest()}
        image = exported["image_id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise SafetyError("Invalid pinned tools-image identity")
        options = builder.docker_args(image) + ["--env", "LC_ALL=C", "--mount",
                   f"type=bind,src={output},dst=/payload", image, "veritysetup"]
        tree = output / "root.verity"
        with tree.open("xb") as stream:
            stream.truncate(HASH_BYTES)
        text = builder.logged(work, "verity-format", options + ["format", "/payload/" + data.name,
                              "/payload/root.verity", *verity_args(authority)], timeout=600)
        authority["root_hash"] = parse_root_hash(text)
        builder.logged(work, "verity-verify", options + ["verify", "/payload/" + data.name,
                       "/payload/root.verity", authority["root_hash"], *verity_args(authority)], timeout=600)
        if data.stat().st_size != ROOT_BYTES or tree.stat().st_size != HASH_BYTES or sha256(data) != digest:
            raise SafetyError("Verity construction changed the frozen root or payload geometry")
        builder.verify_tools(root, tools_label)
        verify_file(archive, result["artifacts"][archive.name])
        if builder.tree_inventory(work / "config") != inventory:
            raise SafetyError("Payload recipe changed during assembly")
        write_json(output / "verity-authority.json", authority)
        artifacts = {p.name: sha256(p) for p in output.iterdir() if p.is_file() and not p.is_symlink()}
        write_json(work / "result.json", {"passed": True, "artifacts": artifacts,
                                          "root_payload": data.name, "full_verity_verified": True,
                                          "boot_chain_qualified": False,
                                          "scope": "Unsigned payload; authority must be embedded in a signed UKI before boot"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error), "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work), "root_hash": authority["root_hash"],
            "scope": "Offline root payload only; not authenticated boot"}
