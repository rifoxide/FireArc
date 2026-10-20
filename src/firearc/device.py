"""Development installed-device profile and QEMU Q35 boot verification.

Assembles an unsigned development disk (GPT ESP + FIREARC_ROOT_A/FIREARC_HASH_A)
from the frozen OS payloads, boots it under the pinned host QEMU/OVMF tools and
asserts the initrd integrity gate outcome on the serial console, including a
corrupted-root negative control. This is a development harness profile: it is
not Secure Boot, not the production provisioning layout and not a signing or
physical-device qualification.
"""

import os
from pathlib import Path
import re
import shutil
import stat

from . import builder, rootfs
from .inputs import load_lock
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, sha256,
    verify_file, write_json,
)

SECTOR = 512
MIB = 1024 * 1024
ESP_MIB = 512
DISK_MIB = 1 + ESP_MIB + rootfs.ROOT_BYTES // MIB + rootfs.HASH_BYTES // MIB + 1
ROOT_OFFSET = (1 + ESP_MIB) * MIB
HASH_OFFSET = ROOT_OFFSET + rootfs.ROOT_BYTES

# Fixed development partition identities keep the harness reproducible; real
# device provisioning assigns fresh random identities per installation.
DISK_GUID = "10000000-0000-4000-8000-0000000000f0"
PARTITIONS = (
    ("FIREARC_ESP", 2048, ESP_MIB * MIB // SECTOR, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
     "10000000-0000-4000-8000-0000000000f1"),
    ("FIREARC_ROOT_A", 2048 + ESP_MIB * MIB // SECTOR, rootfs.ROOT_BYTES // SECTOR,
     "0fc63daf-8483-4772-8e79-3d69d8477de4", "10000000-0000-4000-8000-0000000000f2"),
    ("FIREARC_HASH_A", 2048 + (ESP_MIB * MIB + rootfs.ROOT_BYTES) // SECTOR,
     rootfs.HASH_BYTES // SECTOR, "0fc63daf-8483-4772-8e79-3d69d8477de4",
     "10000000-0000-4000-8000-0000000000f3"),
)

KERNEL_CMDLINE = ("root=/dev/mapper/firearc-root rootfstype=ext4 rootflags=ro,noload ro "
                  "rauc.slot=A rd.shell=0 rd.emergency=poweroff console=ttyS0,115200")

DEV_UNIT = """[Unit]
Description=FireArc development boot smoke terminal
DefaultDependencies=no
Requires=sysroot.mount
After=sysroot.mount

[Service]
Type=oneshot
StandardInput=null
StandardOutput=journal+console
StandardError=journal+console
# The harness marker is written straight to the console device (initrd journald
# console forwarding nondeterministically drops bursty lines) and is printed
# only after independently confirming the verified read-only sysroot mount.
ExecStart=/bin/sh -c 'if grep -Eq " /sysroot ext4 ro(,| )" /proc/mounts; then echo FIREARC_DEV_BOOT_OK > /dev/console; echo FIREARC_DEV_BOOT_OK > /dev/console; else echo FIREARC_DEV_BOOT_MISSING > /dev/console; fi; /usr/bin/systemctl --no-block --force poweroff'
"""

LOADER_CONF = "timeout 0\ndefault firearc-a\neditor no\n"

BOOT_ENTRY = f"""title   FireArc development slot A
linux   /firearc/vmlinuz
initrd  /firearc/initrd.img
options {KERNEL_CMDLINE}
"""

POSITIVE_MARKERS = ("FIREARC_VERITY_PREVERIFY_OK", "FIREARC_VERITY_MAPPING_READY",
                    "Mounted sysroot.mount", "FIREARC_DEV_BOOT_OK")
# The dev terminal unit verifies the read-only sysroot mount itself and writes
# this marker directly to the console device, so it alone is authoritative;
# journald console forwarding can drop the other recorded lines.
REQUIRED_MARKER = "FIREARC_DEV_BOOT_OK"
DENIAL_MARKER = re.compile(r"Verification failed at position [0-9]+\.")


def cpio_archive(entries):
    """Deterministic newc archives the kernel accepts as appended segments."""
    payload = bytearray()
    inodes = 0
    for name, mode, data in sorted(entries, key=lambda item: item[0]):
        if not name or name.startswith("/") or ".." in Path("/", name).parts or "\0" in name:
            raise SafetyError(f"Unsafe cpio entry path: {name!r}")
        if mode not in (0o040755, 0o0100644, 0o0100755, 0o0120777):
            raise SafetyError(f"Unsupported cpio entry mode for {name}")
        encoded = name.encode()
        inodes += 1
        header = [inodes, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded) + 1, 0]
        payload += b"070701" + "".join(f"{field:08x}" for field in header).encode()
        payload += encoded + b"\0"
        payload += b"\0" * (-len(payload) % 4)
        payload += data + b"\0" * (-len(data) % 4)
    inodes += 1
    trailer = [inodes, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(b"TRAILER!!!") + 1, 0]
    payload += b"070701" + "".join(f"{field:08x}" for field in trailer).encode()
    payload += b"TRAILER!!!\0"
    payload += b"\0" * (-len(payload) % 4)
    return bytes(payload)


def dev_cpio(authority):
    """Authority plus an explicit development poweroff switch, never shipped."""
    text = rootfs.render_initrd_authority(authority, "A")
    if re.search(r"[^a-zA-Z0-9_=\n]", text):
        raise SafetyError("Rendered authority contains characters the gate parser rejects")
    return cpio_archive([
        ("etc", 0o040755, b""),
        ("etc/firearc", 0o040755, b""),
        ("etc/firearc/verity.authority", 0o0100644, text.encode()),
        ("etc/systemd", 0o040755, b""),
        ("etc/systemd/system", 0o040755, b""),
        ("etc/systemd/system/firearc-dev-done.service", 0o0100644, DEV_UNIT.encode()),
        ("etc/systemd/system/initrd.target.wants", 0o040755, b""),
        ("etc/systemd/system/initrd.target.wants/firearc-dev-done.service", 0o0120777,
         b"../firearc-dev-done.service"),
    ])


def sfdisk_script():
    lines = ["label: gpt", f"label-id: {DISK_GUID}", "unit: sectors"]
    for name, start, size, kind, unique in PARTITIONS:
        attrs = ", attrs=RequiredPartition" if name == "FIREARC_ESP" else ""
        lines.append(f"start={start}, size={size}, type={kind}, uuid={unique}, "
                     f"name=\"{name}\"{attrs}")
    return "\n".join(lines) + "\n"


def qemu_command(code, variables, disk, serial, *, kvm):
    return ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm" if kvm else "tcg",
            "-cpu", "max", "-m", "2048", "-nodefaults", "-display", "none", "-no-reboot",
            "-net", "none", "-serial", f"file:{serial}",
            "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,file={variables}",
            "-drive", f"file={disk},format=raw,if=virtio"]


def boot_verdict(serial_text):
    """Classify one serial log against the gate's console contract."""
    if not serial_text or len(serial_text) > 8 * 1024 * 1024:
        raise SafetyError("Serial console log is empty or oversized")
    return {marker: marker in serial_text for marker in POSITIVE_MARKERS}, {
        "denial": bool(DENIAL_MARKER.search(serial_text))}


def ovmf_pins(root):
    pins = load_lock(root, "host-tools").get("ovmf")
    if not isinstance(pins, dict) or set(pins) != {"code", "vars"}:
        raise SafetyError("Expected pinned host OVMF code/vars firmware files")
    files = {}
    for role in ("code", "vars"):
        item = pins[role]
        if not isinstance(item, dict) or not Path(item.get("path", "")).is_absolute() \
                or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")):
            raise SafetyError(f"Invalid OVMF {role} compatibility pin")
        path = Path(item["path"])
        if not stat.S_ISREG(path.stat().st_mode):
            raise SafetyError(f"OVMF {role} pin is not a regular host file")
        verify_file(path, item["sha256"])
        files[role] = path
    return files


def _stage_outputs(root, label, expected):
    source = private_directory(Path(root) / "build/images" / label)
    result = read_json(regular_file(source, "result.json"))
    if not result.get("passed") or not result.get("artifacts"):
        raise SafetyError(f"Expected a successful {expected} stage")
    output = private_directory(source / "output")
    for name, digest in result["artifacts"].items():
        verify_file(regular_file(output, name), digest)
    return source, output, result


def assemble(root, tools_label, root_label, rootfs_label, label):
    """Build the unsigned development disk from the frozen payloads."""
    builder.verify_tools(root, tools_label)
    root_source, root_output, root_result = _stage_outputs(root, root_label, "appliance-root")
    payload_source, payload_output, payload_result = _stage_outputs(root, rootfs_label, "rootfs")
    if not payload_result.get("full_verity_verified"):
        raise SafetyError("Expected verified verity payloads for device assembly")
    kernel = regular_file(root_output, "firearc-root.vmlinuz")
    initrd = regular_file(root_output, "firearc-initrd.img")
    archive = regular_file(root_output, "firearc-root.tar")
    data = regular_file(payload_output, payload_result["root_payload"])
    tree = regular_file(payload_output, "root.verity")
    authority = read_json(regular_file(payload_output, "verity-authority.json"))
    rootfs.verity_args(authority)
    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    staging = work / "esp"
    for name in ("EFI/BOOT", "EFI/systemd", "loader/entries", "firearc"):
        (staging / name).mkdir(parents=True, mode=0o700)
    (staging / "loader/loader.conf").write_text(LOADER_CONF)
    (staging / "loader/entries/firearc-a.conf").write_text(BOOT_ENTRY)
    (work / "dev.cpio").write_bytes(dev_cpio(authority))
    with (staging / "firearc/vmlinuz").open("wb") as target:
        shutil.copyfileobj(kernel.open("rb"), target)
    with initrd.open("rb") as source_stream, (staging / "firearc/initrd.img").open("wb") as target:
        shutil.copyfileobj(source_stream, target, 16 * MIB)
        # The kernel only recognizes a cpio segment at a 4-byte-aligned offset
        # of the whole concatenated initramfs; zero padding between segments is
        # skipped by the unpacker.
        target.write(b"\0" * (-initrd.stat().st_size % 4))
        target.write((work / "dev.cpio").read_bytes())
    (work / "gpt.sfdisk").write_text(sfdisk_script())
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
        "--mount", f"type=bind,src={work},dst=/work,readonly", image]
    try:
        # The loader binary is taken from the exact root archive this device uses.
        builder.logged(work, "extract-systemd-boot", options + [
            "tar", "--extract", "--wildcards", "--file", "/root-output/firearc-root.tar",
            "--directory", "/workspace", "*/boot/efi/systemd-bootx64.efi"], timeout=300)
        loader = regular_file(workspace / "usr/lib/systemd/boot/efi", "systemd-bootx64.efi")
        shutil.copyfile(loader, staging / "EFI/BOOT/BOOTX64.EFI")
        shutil.copyfile(loader, staging / "EFI/systemd/systemd-bootx64.efi")
        builder.logged(work, "format-esp", options + [
            "truncate", "--size", f"{ESP_MIB}M", "/workspace/esp.img"], timeout=120)
        builder.logged(work, "mkfs-esp", options + [
            "mkfs.vfat", "--invariant", "-F", "32", "-n", "FIREARC_ESP", "/workspace/esp.img"], timeout=300)
        builder.logged(work, "populate-esp", options + [
            "mcopy", "-i", "/workspace/esp.img", "-s",
            "/staging/EFI", "/staging/loader", "/staging/firearc", "::"], timeout=300)
        builder.logged(work, "create-disk", options + [
            "truncate", "--size", f"{DISK_MIB}M", "/workspace/device.raw"], timeout=300)
        builder.logged(work, "partition-disk", options + [
            "sh", "-c", "sfdisk --quiet --no-reread --no-tell-kernel /workspace/device.raw < /work/gpt.sfdisk"],
            timeout=300)
        builder.logged(work, "install-esp", options + [
            "dd", "if=/workspace/esp.img", "of=/workspace/device.raw", "bs=1M", "seek=1",
            "conv=notrunc", "status=none"], timeout=300)
        builder.logged(work, "install-root", options + [
            "dd", "if=/payload/" + data.name, "of=/workspace/device.raw", "bs=1M",
            f"seek={1 + ESP_MIB}", "conv=notrunc", "status=none"], timeout=900)
        builder.logged(work, "install-hash", options + [
            "dd", "if=/payload/root.verity", "of=/workspace/device.raw", "bs=1M",
            f"seek={(1 + ESP_MIB + rootfs.ROOT_BYTES // MIB)}", "conv=notrunc", "status=none"], timeout=300)
        disk = output / "device.raw"
        shutil.move(str(workspace / "device.raw"), str(disk))
        if disk.stat().st_size != DISK_MIB * MIB:
            raise SafetyError("Assembled development disk has unexpected geometry")
        manifest = {
            "schema": 1, "disk_bytes": DISK_MIB * MIB, "sector_bytes": SECTOR,
            "disk_guid": DISK_GUID, "deterministic_development_ids": True,
            "partitions": [{"name": name, "start_sector": start, "sectors": size,
                            "type": kind, "uuid": unique} for name, start, size, kind, unique in PARTITIONS],
            "kernel_cmdline": KERNEL_CMDLINE,
            "inputs": {"root_label": root_label, "rootfs_label": rootfs_label,
                       "root_tar_sha256": sha256(archive), "kernel_sha256": sha256(kernel),
                       "initrd_sha256": sha256(initrd), "dev_cpio_sha256": sha256(work / "dev.cpio"),
                       "root_payload_sha256": sha256(data), "verity_sha256": sha256(tree),
                       "authority_sha256": sha256(payload_output / "verity-authority.json")},
            "esp": {"loader": "systemd-boot from the root archive", "size_mib": ESP_MIB,
                    "files": sorted(str(item.relative_to(staging)) for item in staging.rglob("*")
                                    if item.is_file())},
            "scope": "Unsigned development installed-device profile for the QEMU harness; "
                     "not a release artifact and not production provisioning",
        }
        write_json(work / "device.json", manifest)
        write_json(work / "result.json", {"passed": True, "artifacts": {"device.raw": sha256(disk)},
                                          "device_bytes": DISK_MIB * MIB,
                                          "boot_chain_qualified": False,
                                          "scope": "Offline development disk assembly; no boot executed"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Development disk assembled; unsigned and not yet booted"}


def check_boot(root, tools_label, device_label, label):
    """Boot the development disk in QEMU Q35 and assert the gate outcome."""
    builder.verify_tools(root, tools_label)
    device_source, device_output, device_result = _stage_outputs(root, device_label, "device")
    disk = regular_file(device_output, "device.raw")
    manifest = read_json(regular_file(device_source, "device.json"))
    if manifest.get("kernel_cmdline") != KERNEL_CMDLINE or not manifest.get("deterministic_development_ids"):
        raise SafetyError("Device manifest does not match the development harness contract")
    firmware = ovmf_pins(root)
    qemu = shutil.which("qemu-system-x86_64")
    pins = load_lock(root, "host-tools")["tools"]["qemu-system-x86_64"]
    if not qemu or sha256(Path(qemu)) != pins["sha256"]:
        raise SafetyError("Host QEMU is absent or does not match the pinned regression tool")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    try:
        runs = {}
        for name, corrupt in (("good", False), ("corrupt", True)):
            target = work / ("device-" + name + ".raw")
            # Private copies: QEMU opens the disk read-write, so the stage
            # artifact must never be the file the guest can touch.
            shutil.copyfile(disk, target)
            if corrupt:
                rootfs.flip_byte(target, ROOT_OFFSET + rootfs.ROOT_BYTES // 2)
            variables = work / ("vars-" + name + ".fd")
            shutil.copyfile(firmware["vars"], variables)
            serial = work / ("serial-" + name + ".log")
            builder.logged(work, "qemu-boot-" + name, qemu_command(
                firmware["code"], variables, target, serial, kvm=kvm), timeout=1800)
            markers, denial = boot_verdict(serial.read_text(errors="replace"))
            runs[name] = {"markers": markers, "denial": denial, "exited": True}
            if corrupt:
                if any(markers.values()) or not denial["denial"]:
                    raise SafetyError("Corrupted root was accepted or produced no verity denial")
            elif not markers[REQUIRED_MARKER] or denial["denial"]:
                raise SafetyError("Uncorrupted development boot did not reach the verified "
                                  "read-only sysroot terminal marker")
        for name, digest in device_result["artifacts"].items():
            verify_file(regular_file(device_output, name), digest)
        builder.verify_tools(root, tools_label)
        write_json(work / "result.json", {
            "passed": True, "kvm": kvm,
            "positive_boot": runs["good"], "corruption_control": runs["corrupt"],
            "ovmf": {role: sha256(path) for role, path in firmware.items()},
            "qemu_sha256": pins["sha256"],
            "qemu_boot_verified": True, "boot_chain_qualified": False,
            "scope": "QEMU Q35 development harness; unsigned dev profile with OVMF, "
                     "not Secure Boot, physical-device or production qualification"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "QEMU boot gate verification (development trust domain)"}
