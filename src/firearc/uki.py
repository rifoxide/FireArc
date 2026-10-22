"""Slot-A Unified Kernel Image construction from the frozen OS payloads.

The unsigned UKI is the single PE file the development device boots: the
pinned ukify from the tools image combines the exact linuxx64.efi stub
carried by the root archive with the frozen kernel, the dracut initramfs
and an appended cpio segment holding the verity authority and the
development boot unit. UKI, systemd-boot and stub therefore stay the same
systemd version from the same Debian snapshot. The kernel command line is
slot-specific (rauc.slot=A) and embedded in the .cmdline section, so the
verity authority rides inside the file the signing step will later sign —
after which nothing between the loader and the verified root is unsigned.

Construction is verified in-stage: the UKI is built twice and must be
byte-identical, and every payload section is checked against its input
file. This is still unsigned development content: it is not Secure Boot,
not a signing qualification and not a release artifact.
"""

from pathlib import Path
import hashlib
import re
import shutil
import struct

from . import builder, device, rootfs
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, sha256, write_json,
)

# Sections a FireArc UKI must carry. .sbat is recorded as inventory; its
# policy meaning belongs to the signing qualification, not construction.
REQUIRED_SECTIONS = (".osrel", ".cmdline", ".uname", ".linux", ".initrd")

REBUILD_NAME = "rebuild.efi"


def segment_padding(size):
    """Zero bytes needed before an appended cpio segment (4-byte alignment)."""
    return -size % 4


def pe_sections(binary):
    """Section table of an amd64 PE image, with each section's sha256.

    This reads only structural fields; it is not a PE security parser.
    """
    if len(binary) < 0x40 or not binary.startswith(b"MZ"):
        raise SafetyError("Not a PE image (missing MZ header)")
    signature = struct.unpack_from("<I", binary, 0x3C)[0]
    if signature + 24 > len(binary) or binary[signature:signature + 4] != b"PE\0\0":
        raise SafetyError("Not a PE image (bad signature)")
    machine, count, timestamp = struct.unpack_from("<HHI", binary, signature + 4)
    if machine != 0x8664:
        raise SafetyError(f"PE image is not amd64 (machine={machine:#x})")
    optional = struct.unpack_from("<H", binary, signature + 20)[0]
    table = signature + 24 + optional
    sections = []
    for index in range(count):
        offset = table + index * 40
        if offset + 40 > len(binary):
            raise SafetyError("PE section table is truncated")
        name = binary[offset:offset + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, _, raw_size, raw_pointer = struct.unpack_from("<IIII", binary, offset + 8)
        if raw_pointer + raw_size > len(binary):
            raise SafetyError(f"Section {name} points outside the PE image")
        if virtual_size > raw_size:
            raise SafetyError(f"Section {name} has VirtualSize beyond its raw data")
        digest = hashlib.sha256(binary[raw_pointer:raw_pointer + raw_size]).hexdigest()
        sections.append({"name": name, "bytes": raw_size, "offset": raw_pointer,
                         "virtual_size": virtual_size, "sha256": digest})
    return sections, timestamp


def section_carries(binary, section, content):
    """True when the section payload is exactly content plus zero padding."""
    raw = binary[section["offset"]:section["offset"] + section["bytes"]]
    return raw.startswith(content) and not raw[len(content):].strip(b"\0")


def build(root, tools_label, root_label, rootfs_label, label, *, shell=False):
    """Build the unsigned slot-A UKI from frozen, verified stage outputs."""
    builder.verify_tools(root, tools_label)
    _, root_output, _ = device._stage_outputs(root, root_label, "appliance-root")
    _, payload_output, payload_result = device._stage_outputs(root, rootfs_label, "rootfs")
    if not payload_result.get("full_verity_verified"):
        raise SafetyError("Expected verified verity payloads for UKI construction")
    kernel = regular_file(root_output, "firearc-root.vmlinuz")
    initrd = regular_file(root_output, "firearc-initrd.img")
    archive = regular_file(root_output, "firearc-root.tar")
    authority = read_json(regular_file(payload_output, "verity-authority.json"))
    rootfs.verity_args(authority)
    release = builder.root_lock(root)["kernel_release"]
    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    staging = work / "payload"
    staging.mkdir(mode=0o700)
    workspace = work / "workspace"
    workspace.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={root_output},dst=/root-output,readonly",
        "--mount", f"type=bind,src={payload_output},dst=/payload,readonly",
        "--mount", f"type=bind,src={staging},dst=/staging",
        "--mount", f"type=bind,src={workspace},dst=/workspace",
        image]
    try:
        # The stub and os-release come from the exact root archive this UKI
        # is built for, keeping UKI, loader and stub one systemd version.
        builder.logged(work, "extract-stub", options + [
            "tar", "--extract", "--wildcards", "--file", "/root-output/firearc-root.tar",
            "--directory", "/workspace",
            "*/systemd/boot/efi/linuxx64.efi.stub", "*/usr/lib/os-release"], timeout=300)
        stub = regular_file(workspace / "usr/lib/systemd/boot/efi", "linuxx64.efi.stub")
        if not stub.read_bytes().startswith(b"MZ"):
            raise SafetyError("Pinned stub is not a PE image")
        osrel = regular_file(workspace / "usr/lib", "os-release")
        shutil.copyfile(stub, staging / "linuxx64.efi.stub")
        shutil.copyfile(osrel, staging / "os-release")
        shutil.copyfile(kernel, staging / "kernel")
        (staging / "cmdline").write_text(device.KERNEL_CMDLINE)
        # The dev cpio (verity authority + development unit) becomes part of
        # the .initrd section: inside the file the signing step will sign.
        (work / "dev.cpio").write_bytes(device.dev_cpio(authority, shell=shell))
        with initrd.open("rb") as source, (staging / "initrd.img").open("xb") as target:
            shutil.copyfileobj(source, target, 16 * 1024 * 1024)
            target.write(b"\0" * segment_padding(initrd.stat().st_size))
            with (work / "dev.cpio").open("rb") as cpio:
                shutil.copyfileobj(cpio, target)
        arguments = ["ukify", "build", "--linux=/staging/kernel",
                     "--initrd=/staging/initrd.img", "--cmdline=@/staging/cmdline",
                     "--os-release=@/staging/os-release", "--uname=" + release,
                     "--stub=/staging/linuxx64.efi.stub", "--efi-arch=x64"]
        version = builder.logged(work, "ukify-version", options + ["ukify", "--version"],
                                 timeout=120).strip().splitlines()[-1]
        builder.logged(work, "ukify-build", options + arguments
                       + ["--output=/staging/" + device.UKI_ARTIFACT], timeout=1800)
        builder.logged(work, "ukify-rebuild", options + arguments
                       + ["--output=/staging/" + REBUILD_NAME], timeout=1800)
        built = regular_file(staging, device.UKI_ARTIFACT)
        if sha256(built) != sha256(staging / REBUILD_NAME):
            raise SafetyError("UKI rebuild differs: ukify output is not byte-stable")
        builder.logged(work, "ukify-inspect", options + ["ukify", "inspect",
                       "/staging/" + device.UKI_ARTIFACT], timeout=300)
        binary = built.read_bytes()
        sections, timestamp = pe_sections(binary)
        by_name = {section["name"]: section for section in sections}
        missing = [name for name in REQUIRED_SECTIONS if name not in by_name]
        if missing:
            raise SafetyError(f"UKI lacks required sections: {missing}")
        expected = {".linux": (staging / "kernel").read_bytes(),
                    ".initrd": (staging / "initrd.img").read_bytes(),
                    ".cmdline": device.KERNEL_CMDLINE.encode(),
                    ".osrel": osrel.read_bytes(),
                    ".uname": release.encode()}
        for name, content in expected.items():
            if not section_carries(binary, by_name[name], content):
                raise SafetyError(f"Embedded {name} section does not carry its input file")
        uki = output / device.UKI_ARTIFACT
        shutil.move(str(built), str(uki))
        # Publish the exact section inputs beside the UKI: the PCR-policy
        # stage rebuilds from precisely these receipt-covered bytes. The
        # disposable rebuild evidence stays in the staging area.
        published = {}
        for name in ("kernel", "initrd.img", "cmdline", "os-release",
                     "linuxx64.efi.stub"):
            shutil.move(str(staging / name), str(output / name))
            published[name] = sha256(output / name)
        write_json(work / "uki.json", {
            "schema": 1, "uki": device.UKI_ARTIFACT, "slot": "A",
            "development_shell": shell,
            "uname": release, "cmdline": device.KERNEL_CMDLINE,
            "pe_timestamp": f"{timestamp:#x}", "sections": sections,
            "ukify": version, "tools_image": image,
            "inputs": {"root_label": root_label, "rootfs_label": rootfs_label,
                       "root_tar_sha256": sha256(archive),
                       "kernel_sha256": sha256(kernel), "initrd_sha256": sha256(initrd),
                       "combined_initrd_sha256": published["initrd.img"],
                       "dev_cpio_sha256": sha256(work / "dev.cpio"),
                       "stub_sha256": published["linuxx64.efi.stub"],
                       "os_release_sha256": published["os-release"],
                       "authority_sha256": sha256(payload_output / "verity-authority.json")},
            "byte_identical_rebuild": True,
            "scope": "Unsigned development UKI; not signed, not Secure Boot, not a release artifact"})
        write_json(work / "result.json", {
            "passed": True,
            "artifacts": {device.UKI_ARTIFACT: sha256(uki), **published},
            "byte_identical_rebuild": True, "sections_verified": True,
            "uki_unsigned": True, "boot_chain_qualified": False,
            "scope": "UKI constructed from frozen payloads; unsigned and not yet booted"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Unsigned slot-A UKI built from verified stage outputs"}
