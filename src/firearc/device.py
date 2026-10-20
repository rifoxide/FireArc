"""Development installed-device profile and QEMU Q35 boot verification.

Assembles an unsigned development disk (GPT ESP + FIREARC_ROOT_A/FIREARC_HASH_A)
from the frozen OS payloads, boots it under the pinned host QEMU with the
self-built coreboot/EDK II firmware and asserts the initrd integrity gate
outcome on the serial console, including a corrupted-root negative control.
Each booted flash copy must also differ from the pristine ROM only inside the
SMMSTORE variable region: guest firmware writes may never touch code,
flash-map, preserved or unmapped bytes. The firmware image is the monolithic 8 MiB ROM from the firmware-build stage;
its SMMSTORE region carries the writable UEFI variable store, so each run
boots a private writable copy of the ROM. This is a development harness
profile: it is not Secure Boot, not the production provisioning layout and
not a signing or physical-device qualification.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from . import builder, firmware_layout, qmp, rootfs
from .inputs import load_lock
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, sha256,
    verify_file, write_json,
)

SECTOR = 512
MIB = 1024 * 1024
ESP_MIB = 512
FIRMWARE_BYTES = 8 * MIB
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

# The dev unit waits out this many seconds after its markers before powering
# off. This fallback is best-effort only: the unit runs in the initrd, and
# switch_root's cleanup stops it first, so in practice every session is ended
# by the harness over QMP (orderly quit, powerdown request or hard kill).
GRACE_SECONDS = 25

# Sustained serial silence for this long suggests the payload is parked at
# its interactive boot menu; send a recorded ENTER nudge, at most this many
# times per session, before the hard timeout fails the boot closed.
MENU_UNSTICK_AFTER = 45
MENU_UNSTICK_MAX = 3


def die_with_parent():
    """preexec_fn: orphaned machines must not outlive the harness process."""
    import ctypes
    import signal
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0)

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
# The TPM marker reports whether the kernel's built-in tpm_tis driver bound a
# TPM 2.0 device through ACPI (QEMU's tpm-tis presents the MSFT0101 device; the
# chip lands at /sys/class/tpm/tpm0 with tpm_version_major=2 and /dev/tpm0);
# without a TPM attached the profile boot gate expects the explicit miss line. The debug lines are dev-harness
# diagnostics only. After the markers the unit stays up in a bounded grace
# window (GRACE_SECONDS) so harness operations — QMP reset/powerdown or a
# power cut — act on a running machine; only then does it fall back to the
# immediate poweroff syscall (a systemd shutdown job once raced switch_root
# to the real root in observed runs).
ExecStart=/bin/sh -c 'echo FIREARC_TPM_DEBUG_CLASS=$(ls /sys/class 2>/dev/null | grep -i tpm); echo FIREARC_TPM_DEBUG_TPM0=$(ls /sys/class/tpm/tpm0 2>&1); echo FIREARC_TPM_DEBUG_VERSION=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>&1); echo FIREARC_TPM_DEBUG_DEV=$(ls /dev/tpm0 /dev/tpmrm0 2>&1); if [ -c /dev/tpm0 ] && [ -d /sys/class/tpm/tpm0 ] && [ "$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null)" = "2" ]; then echo FIREARC_TPM_TIS_OK > /dev/console; else echo FIREARC_TPM_TIS_MISSING > /dev/console; fi; if grep -Eq " /sysroot ext4 ro(,| )" /proc/mounts; then echo FIREARC_DEV_BOOT_OK > /dev/console; echo FIREARC_DEV_BOOT_OK > /dev/console; else echo FIREARC_DEV_BOOT_MISSING > /dev/console; fi; sleep 25; /usr/bin/poweroff -f || /usr/bin/systemctl --no-block --force poweroff'
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
# Console contract for TPM qualification in the persistent device profile:
# the kernel has CONFIG_TCG_TIS=y/CONFIG_TCG_CRB=y built in, so an attached
# swtpm tpm-tis device must bind through ACPI without any initrd support.
TPM_TIS_MARKER = "FIREARC_TPM_TIS_OK"
TPM_TIS_MISSING_MARKER = "FIREARC_TPM_TIS_MISSING"


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


def qemu_command(firmware, disk, serial, *, kvm, tpm=None, qmp_socket=None, rebootable=False):
    # The payload has no virtio drivers: the development disk is presented
    # over the emulated ICH9 AHCI controller the payload does support.
    command = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm" if kvm else "tcg",
               "-cpu", "max", "-m", "2048", "-nodefaults", "-display", "none",
               "-net", "none", "-serial", f"file:{serial}"]
    # Reset loops must exit instead of spinning forever — unless the operator
    # explicitly runs a reboot operation, which needs in-process resets.
    if not rebootable:
        command += ["-no-reboot"]
    if qmp_socket:
        # Local-only control socket (unix, inside the 0700 evidence/run
        # directory) for automated reset/powerdown/stop of the machine.
        command += ["-qmp", f"unix:{qmp_socket},server,nowait"]
    command += [
        # Monolithic firmware: the writable pflash copy carries both code
        # and the SMMSTORE variable region (no OVMF-style CODE/VARS split).
        "-drive", f"if=pflash,format=raw,file={firmware}",
        "-device", "ahci,id=ahci0",
        "-drive", f"if=none,id=disk0,file={disk},format=raw",
        "-device", "ide-hd,drive=disk0,bus=ahci0.0"]
    if tpm:
        # Exactly one emulated TPM per machine, over the ISA TIS interface,
        # backed by the device profile's isolated swtpm control socket.
        command += ["-chardev", f"socket,id=chrtpm,path={tpm}",
                    "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                    "-device", "tpm-tis,tpmdev=tpm0"]
    return command


class VmSession:
    """One QEMU process under local QMP control.

    The machine's lifecycle is explicit at every exit path: orderly QMP quit,
    operator-requested powerdown, hard kill for power-cut tests, or the
    machine leaving by itself. Serial evidence is watched live; evidence
    files mirror builder.logged's shape (command/stdout/stderr/exit).
    """

    def __init__(self, work, name, command, socket_path, *, timeout=1800):
        self.work = work
        self.name = name
        self.command = command
        self.socket_path = socket_path
        self.timeout = timeout
        self.process = None
        self.control = None
        self.serial_path = None
        self.keypresses = 0
        self._out = None
        self._err = None
        self.deadline = 0.0

    def start(self, serial_path):
        write_json(self.work / (self.name + ".command.json"), self.command)
        self.serial_path = serial_path
        self._out = (self.work / (self.name + ".stdout")).open("xb")
        self._err = (self.work / (self.name + ".stderr")).open("xb")
        self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL,
                                        stdout=self._out, stderr=self._err,
                                        preexec_fn=die_with_parent)
        self.deadline = time.monotonic() + self.timeout
        ready = time.monotonic() + 30
        while not self.socket_path.exists():
            if self.process.poll() is not None:
                raise SafetyError(f"QEMU exited before opening the control socket "
                                  f"(rc={self.process.returncode})")
            if time.monotonic() > ready:
                raise SafetyError("QEMU did not open its QMP control socket")
            time.sleep(0.05)
        self.control = qmp.QmpControl(self.socket_path).connect()
        return self

    def serial_text(self):
        if self.serial_path is None:
            return ""
        return self.serial_path.read_text(errors="replace")

    def press_enter(self):
        """One ENTER keypress over QMP input-send-event (emulated keyboard).

        The payload's interactive boot menu ("ENTER to boot directly") can
        fail to auto-continue from a pristine variable store (observed
        2026-10-20 on fresh profiles). This bounded, recorded nudge lets the
        machine boot while keeping the payload defect visible in evidence;
        it is never sent while serial output is still flowing.
        """
        if not self.alive():
            return False
        self.control.command("input-send-event", events=[
            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "ret"}}},
            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "ret"}}},
        ])
        self.keypresses += 1
        return True

    def wait_until(self, predicate):
        """Poll the serial log until predicate(text) holds or QEMU leaves.

        Sustained serial silence suggests the payload is waiting at its
        interactive boot menu; a bounded number of ENTER keypresses is sent
        and recorded before the hard timeout fails the session closed.
        """
        last_size = -1
        last_growth = time.monotonic()
        while True:
            text = self.serial_text()
            if predicate(text):
                return text
            if self.process.poll() is not None:
                # The machine is gone; the caller judges the final log.
                return self.serial_text()
            try:
                size = self.serial_path.stat().st_size
            except OSError:
                size = 0
            if size != last_size:
                last_size = size
                last_growth = time.monotonic()
            elif self.keypresses < MENU_UNSTICK_MAX \
                    and time.monotonic() - last_growth >= MENU_UNSTICK_AFTER:
                self.press_enter()
                last_growth = time.monotonic()
            if time.monotonic() > self.deadline:
                self.process.kill()
                raise SafetyError(f"QEMU session {self.name} timed out after "
                                  f"{self.timeout}s without the expected serial output")
            time.sleep(0.1)

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def reset(self):
        """In-process machine reset; firmware and devices stay powered."""
        if not self.alive():
            raise SafetyError("Cannot reset a machine that already left")
        self.control.command("system_reset")

    def powerdown(self):
        """Operator power-down request (ACPI power button)."""
        if not self.alive():
            raise SafetyError("Cannot power down a machine that already left")
        self.control.command("system_powerdown")

    def quit(self):
        """Orderly stop of the machine by the harness."""
        if self.alive():
            self.control.command("quit")
        return self.wait_exit(120)

    def kill(self):
        """Hard kill: the emulated board loses power without cleanup."""
        if self.alive():
            self.process.kill()
        return self.wait_exit(30)

    def wait_exit(self, timeout):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.process.kill()
            self.process.wait(timeout=30)
            raise SafetyError(f"QEMU session {self.name} did not exit within "
                              f"{timeout}s") from error
        return self.process.returncode

    def close(self):
        """Finalize evidence; safe once the process has left."""
        if self.process is None:
            return
        if self.control is not None:
            self.control.close()
        for stream in (self._out, self._err):
            if stream is not None and not stream.closed:
                stream.close()
        write_json(self.work / (self.name + ".exit.json"),
                   {"returncode": self.process.returncode,
                    "qmp_controlled": self.control is not None,
                    "menu_unstick_keypresses": self.keypresses,
                    "timeout": self.timeout})


def start_vm(work, name, *, flash, disk, serial, kvm, tpm=None, rebootable=False,
             timeout=1800):
    """Start one QEMU machine under QMP control inside an evidence directory."""
    socket_path = work / (name + ".qmp.sock")
    return VmSession(work, name,
                     qemu_command(flash, disk, serial, kvm=kvm, tpm=tpm,
                                  qmp_socket=socket_path, rebootable=rebootable),
                     socket_path, timeout=timeout).start(serial)


def boot_verdict(serial_text):
    """Classify one serial log against the gate's console contract."""
    if not serial_text or len(serial_text) > 8 * 1024 * 1024:
        raise SafetyError("Serial console log is empty or oversized")
    return {marker: marker in serial_text for marker in POSITIVE_MARKERS}, {
        "denial": bool(DENIAL_MARKER.search(serial_text))}


def firmware_rom(root, label):
    """The verified self-built firmware ROM from a firmware-build stage."""
    source, output, result = _stage_outputs(
        root, label, "firmware-build", Path(root) / "build/firmware-build")
    rom = regular_file(output, "coreboot.rom")
    if result.get("artifacts", {}).get("coreboot.rom") != sha256(rom):
        raise SafetyError("Firmware stage does not vouch for the ROM artifact")
    manifest = read_json(regular_file(output, "manifest.json"))
    if manifest.get("coreboot.rom", {}).get("sha256") != sha256(rom) \
            or manifest.get("coreboot.rom", {}).get("bytes") != FIRMWARE_BYTES:
        raise SafetyError("Firmware manifest does not match the ROM artifact")
    return source, rom, manifest


def _stage_outputs(root, label, expected, parent=None):
    source = private_directory((parent or Path(root) / "build/images") / label)
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


def check_boot(root, tools_label, device_label, firmware_label, label):
    """Boot the development disk in QEMU Q35 and assert the gate outcome."""
    builder.verify_tools(root, tools_label)
    device_source, device_output, device_result = _stage_outputs(root, device_label, "device")
    disk = regular_file(device_output, "device.raw")
    manifest = read_json(regular_file(device_source, "device.json"))
    if manifest.get("kernel_cmdline") != KERNEL_CMDLINE or not manifest.get("deterministic_development_ids"):
        raise SafetyError("Device manifest does not match the development harness contract")
    firmware_source, rom, firmware_manifest = firmware_rom(root, firmware_label)
    pristine = rom.read_bytes()
    layout = firmware_layout.classify(pristine, firmware_layout.parse_fmap(pristine))
    qemu = shutil.which("qemu-system-x86_64")
    pins = load_lock(root, "host-tools")["tools"]["qemu-system-x86_64"]
    if not qemu or sha256(Path(qemu)) != pins["sha256"]:
        raise SafetyError("Host QEMU is absent or does not match the pinned regression tool")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    try:
        runs = {}
        flash_runs = {}
        for name, corrupt in (("good", False), ("corrupt", True)):
            target = work / ("device-" + name + ".raw")
            # Private copies: QEMU opens the disk and the firmware flash
            # read-write, so stage artifacts must never be guest-writable.
            shutil.copyfile(disk, target)
            if corrupt:
                rootfs.flip_byte(target, ROOT_OFFSET + rootfs.ROOT_BYTES // 2)
            flash = work / ("flash-" + name + ".rom")
            shutil.copyfile(rom, flash)
            serial = work / ("serial-" + name + ".log")
            # QMP-controlled machine: the harness stops QEMU itself as soon as
            # the serial verdict is in; no reliance on the guest powering off.
            session = start_vm(work, "qemu-boot-" + name, flash=flash, disk=target,
                               serial=serial, kvm=kvm, timeout=1800)
            try:
                session.wait_until(lambda text: REQUIRED_MARKER in text
                                   or DENIAL_MARKER.search(text))
                session.quit()  # no-op if the machine already left on its own
            finally:
                session.close()
            markers, denial = boot_verdict(serial.read_text(errors="replace"))
            # Guest firmware writes must land only in the declared variable
            # store; every code, flash-map, preserved and unmapped byte of the
            # booted flash copy must match the pristine image.
            flash_runs[name] = firmware_layout.write_confinement(
                pristine, flash.read_bytes(), layout)
            runs[name] = {"markers": markers, "denial": denial, "exited": True,
                          "menu_unstick_keypresses": session.keypresses}
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
            "firmware": {"rom_sha256": sha256(rom),
                         "sdk_image": firmware_manifest.get("sdk_image"),
                         "sources": len(firmware_manifest.get("sources", {})),
                         "evidence": firmware_source.name},
            "qemu_sha256": pins["sha256"],
            "flash_write_confinement": {
                "permitted_region": firmware_layout.VARIABLE_STORE_AREA,
                "runs": flash_runs,
                "scope": "Observed write destinations only; QEMU pflash has no "
                         "hardware write protection"},
            "qemu_boot_verified": True, "boot_chain_qualified": False,
            "scope": "QEMU Q35 development harness; unsigned dev profile on the self-built "
                     "coreboot/EDK II firmware, not Secure Boot, physical-device or "
                     "production qualification"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "QEMU boot gate verification (development trust domain)"}
