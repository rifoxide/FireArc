"""Audit the project root gate in a built initramfs without booting it."""

import re
import tarfile
from pathlib import Path

from . import builder
from .integrity import SafetyError, identifier, private_directory, read_json, regular_file, sha256, verify_file, write_json

REQUIRED = {"firearc-root", "systemd", "systemd-initrd", "dm", "tpm2-tss"}
FORBIDDEN = {"rootfs-block", "dracut-systemd", "rescue", "overlay-root", "overlayfs",
             "systemd-emergency", "debug", "crypt", "systemd-cryptsetup", "systemd-veritysetup"}


def check_modules(text):
    lines = set(text.splitlines())
    if not REQUIRED <= lines or FORBIDDEN & lines:
        raise SafetyError("Initrd is missing the root gate or includes an alternate root/emergency module")


def audit(root, tools_label, source_label, label):
    identifier(source_label)
    identifier(label)
    builder.verify_tools(root, tools_label)
    tools_work = builder.parent(root) / identifier(tools_label)
    source = private_directory(Path(root) / "build/images" / source_label)
    result = read_json(regular_file(source, "result.json"))
    inputs = read_json(regular_file(source, "inputs.json"))
    if (not result.get("passed") or result.get("profile") != "root"
            or inputs.get("tools_inventory_sha256") != sha256(tools_work / "tools-inventory.json")):
        raise SafetyError("Expected a passed root stage built with these tools")
    archive = regular_file(source / "output", "firearc-root.tar")
    verify_file(archive, result["artifacts"][archive.name])
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    public = work / "public"
    public.mkdir(mode=0o700)
    release = builder.root_lock(root)["kernel_release"]
    with tarfile.open(archive, "r:") as tar:
        member = tar.getmember("./boot/initrd.img-" + release)
        if not member.isreg() or not 0 < member.size < 256 * 1024 * 1024:
            raise SafetyError("Unexpected initramfs member")
        # Extract only this verified regular file; never tar.extract/all paths.
        with tar.extractfile(member) as stream, (public / "initrd.img").open("xb") as output:
            while chunk := stream.read(1024 * 1024):
                output.write(chunk)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid audit tools-image identity")
    options = builder.docker_args(image) + ["--mount", f"type=bind,src={public},dst=/audit,readonly", image, "lsinitrd"]
    write_json(work / "inputs.json", {"source_result_sha256": sha256(source / "result.json"),
                                      "initrd_sha256": sha256(public / "initrd.img"), "tools_image_id": image})
    try:
        modules = builder.logged(work, "modules", options + ["--mod", "/audit/initrd.img"])
        check_modules(modules)
        listing = builder.logged(work, "listing", options + ["/audit/initrd.img"])
        if not re.search(r"^-rwxr-xr-x\s+[^\n]+ usr/lib/firearc/verify-root$", listing, re.MULTILINE):
            raise SafetyError("Root-gate entry point is not executable with the expected mode")
        installed = {"authority.sh": "usr/lib/firearc/authority.sh", "firearc-verify-root": "usr/lib/firearc/verify-root",
                     "firearc-verify-root.service": "etc/systemd/system/firearc-verify-root.service",
                     "sysroot.mount": "etc/systemd/system/sysroot.mount",
                     "firearc-boot-failure.service": "etc/systemd/system/firearc-boot-failure.service",
                     "emergency.target": "etc/systemd/system/emergency.target"}
        hashes = {}
        for index, (name, path) in enumerate(installed.items()):
            builder.logged(work, f"file-{index}", options + ["--file", path, "/audit/initrd.img"])
            expected = regular_file(source / "config/skeleton/usr/lib/dracut/modules.d/99firearc-root", name)
            verify_file(work / f"file-{index}.stdout", sha256(expected))
            hashes[path] = sha256(expected)
        masks = ["etc/systemd/system/" + name for name in ["emergency.service", "rescue.service", "debug-shell.service"]]
        masks += ["etc/systemd/system-generators/" + name for name in [
            "systemd-gpt-auto-generator", "systemd-fstab-generator", "systemd-veritysetup-generator",
            "dracut-rootfs-generator", "systemd-debug-generator"]]
        for path in masks:
            if not re.search(r"\s" + re.escape(path) + r" -> /dev/null$", listing, re.MULTILINE):
                raise SafetyError("Missing initrd fallback mask: " + path)
        if not re.search(r"\setc/systemd/system/rescue.target -> emergency.target$", listing, re.MULTILINE):
            raise SafetyError("Rescue target does not use the no-shell failure target")
        if not re.search(r"\setc/systemd/system/initrd-root-fs.target.requires/sysroot.mount -> ../sysroot.mount$", listing, re.MULTILINE):
            raise SafetyError("Verified root mount is not a required initrd target dependency")
        if not re.search(r"\setc/systemd/system/default.target -> /usr/lib/systemd/system/initrd.target$", listing, re.MULTILINE):
            raise SafetyError("Generic initrd does not select the intended initrd target")
        if re.search(r"\setc/firearc/verity.authority(?: -> .*|)$", listing, re.MULTILINE):
            raise SafetyError("Generic initrd unexpectedly contains slot authority")
        # Unpack only inside a disposable, capability-free container tmpfs. The
        # pinned systemd verifies the actual embedded units, not host copies.
        # exec is needed for its X_OK checks; verify does not start these units.
        unit_options = builder.docker_args(image) + ["--mount",
            f"type=bind,src={public},dst=/audit,readonly", "--tmpfs", "/unpack:rw,exec,nosuid,nodev,mode=1777,size=512m",
            "--workdir", "/unpack", image, "/bin/sh", "-ec",
            "lsinitrd --unpack /audit/initrd.img\nsystemd-analyze --root=/unpack --man=no verify firearc-verify-root.service firearc-boot-failure.service sysroot.mount emergency.target"]
        builder.logged(work, "verify-embedded-units", unit_options)
        verify_file(archive, result["artifacts"][archive.name])
        builder.verify_tools(root, tools_label)
        write_json(work / "result.json", {"passed": True, "embedded_file_sha256": hashes,
                                          "required_modules": sorted(REQUIRED), "forbidden_modules": sorted(FORBIDDEN),
                                          "fallback_masks_checked": masks, "boot_chain_qualified": False,
                                          "embedded_systemd_units_verified": True,
                                          "scope": "Static initrd contents only; no boot or failure-path qualification"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error), "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work), "scope": "Static root-gate initrd audit"}
