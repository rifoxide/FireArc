"""Development installed-device profile and QEMU Q35 boot verification.

Assembles a development disk (GPT ESP + FIREARC_ROOT_A/FIREARC_HASH_A) from
the frozen OS payloads and the development-signed boot artifacts, boots it
under the pinned host QEMU with the self-built coreboot/EDK II firmware and
asserts the initrd integrity gate outcome on the serial console, including
a corrupted-root negative control. The ESP carries the sb-signed
systemd-boot loader plus one signed Unified Kernel Image as a type-2 loader
entry; the kernel, command line, verity authority and development unit all
ride inside the UKI, so the ESP holds no unsigned kernel or initramfs.
Secure Boot is not yet enforced: the device variable store still has to be
enrolled with the development PK/KEK/db. Each booted flash copy must also
differ from the pristine ROM only inside the SMMSTORE variable region:
guest firmware writes may never touch code, flash-map, preserved or
unmapped bytes. The firmware image is the monolithic 8 MiB ROM from the
firmware-build stage; its SMMSTORE region carries the writable UEFI
variable store, so each run boots a private writable copy of the ROM.
This is a development harness profile: it is not production provisioning,
not a production-custody claim and not a physical-device qualification.
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

# The unsigned slot-A Unified Kernel Image (built by the uki stage) and its
# systemd-boot type-2 auto-entry location on the ESP. The kernel, command
# line, verity authority and development unit live inside the UKI, not as
# separate ESP files.
UKI_ARTIFACT = "firearc-uki-a.efi"
ESP_UKI_PATH = "EFI/Linux/firearc-a.efi"

# After its markers the unit waits this many seconds — the harness's window
# to corrupt the disk mid-session for the runtime verity test — then drops
# caches and re-reads the whole verity device, printing whether dm-verity
# returned an I/O error. Afterwards it idles bounded: every session is ended
# by the harness over QMP (PDEATHSIG covers orphans), so the unit carries no
# poweroff of its own.
RUNTIME_READ_SETTLE_SECONDS = 6
UNIT_TAIL_IDLE_SECONDS = 600

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
Before=initrd.target

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
# without a TPM attached the profile boot gate expects the explicit miss line.
# The debug lines are dev-harness diagnostics only. Blocking initrd.target
# (Before= plus the requires symlink) keeps the machine in the initrd for the
# runtime verity read: after a bounded settle window the unit drops caches and
# re-reads the whole verity-mapped root, reporting an I/O error (corruption
# caught after mapping) or a clean read. It then idles; the harness, not the
# guest, ends every session. The read uses cat (coreutils): dd is not part
# of the minimal dracut initramfs, and the shell captures cat's stderr only.
ExecStart=/bin/sh -c 'echo FIREARC_TPM_DEBUG_CLASS=$(ls /sys/class 2>/dev/null | grep -i tpm); echo FIREARC_TPM_DEBUG_TPM0=$(ls /sys/class/tpm/tpm0 2>&1); echo FIREARC_TPM_DEBUG_VERSION=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>&1); echo FIREARC_TPM_DEBUG_DEV=$(ls /dev/tpm0 /dev/tpmrm0 2>&1); if [ -c /dev/tpm0 ] && [ -d /sys/class/tpm/tpm0 ] && [ "$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null)" = "2" ]; then echo FIREARC_TPM_TIS_OK > /dev/console; else echo FIREARC_TPM_TIS_MISSING > /dev/console; fi; if grep -Eq " /sysroot ext4 ro(,| )" /proc/mounts; then echo FIREARC_DEV_BOOT_OK > /dev/console; echo FIREARC_DEV_BOOT_OK > /dev/console; else echo FIREARC_DEV_BOOT_MISSING > /dev/console; fi; sleep 6; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; rterr=$(cat /dev/mapper/firearc-root 2>&1 > /dev/null); case "$rterr" in *"Input/output error"*) echo FIREARC_RUNTIME_CORRUPT_EIO > /dev/console;; *) echo FIREARC_RUNTIME_READ_CLEAN > /dev/console;; esac; sleep 600'
"""

LOADER_CONF = "timeout 0\ndefault firearc-a\neditor no\n"

# With one UKI under EFI/Linux and timeout 0, systemd-boot boots the single
# type-2 entry automatically; the entry's kernel command line comes from the
# UKI's embedded .cmdline section, not from a loader entry file.

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
# Runtime verity gate: after full preverification and mapping, the dev unit
# drops caches and re-reads the whole verity device. A mid-session disk
# corruption must surface as a dm-verity I/O error, never as read-through.
RUNTIME_EIO_MARKER = "FIREARC_RUNTIME_CORRUPT_EIO"
RUNTIME_CLEAN_MARKER = "FIREARC_RUNTIME_READ_CLEAN"


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
        # requires (not wants): initrd.target — and therefore switch_root —
        # waits for the dev unit, keeping the machine in the initrd for the
        # runtime verity read.
        ("etc/systemd/system/initrd.target.requires", 0o040755, b""),
        ("etc/systemd/system/initrd.target.requires/firearc-dev-done.service",
         0o0120777, b"../firearc-dev-done.service"),
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
    if len(str(socket_path).encode()) >= 108:
        # Kernel limit for UNIX socket paths; fail closed with a clear cause
        # instead of QEMU's cryptic rc=1. Keep session labels short.
        raise SafetyError(f"QMP socket path too long for a UNIX socket "
                          f"(>=108 bytes): {socket_path}")
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


def assemble(root, tools_label, rootfs_label, sign_label, label):
    """Build the development disk from the frozen payloads and signed boot artifacts."""
    builder.verify_tools(root, tools_label)
    payload_source, payload_output, payload_result = _stage_outputs(root, rootfs_label, "rootfs")
    if not payload_result.get("full_verity_verified"):
        raise SafetyError("Expected verified verity payloads for device assembly")
    sign_source, sign_output, sign_result = _stage_outputs(root, sign_label, "sign")
    uki = regular_file(sign_output, UKI_ARTIFACT)
    loader = regular_file(sign_output, "systemd-bootx64.efi")
    for name, digest in ((UKI_ARTIFACT, uki), ("systemd-bootx64.efi", loader)):
        if sign_result.get("artifacts", {}).get(name) != sha256(digest):
            raise SafetyError(f"Signing stage does not vouch for {name}")
    if not sign_result.get("signed") or not sign_result.get("signatures_verified") \
            or not sign_result.get("covers_exact_unsigned_content"):
        raise SafetyError("Expected verified, content-checked signatures for the ESP")
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
    for name in ("EFI/BOOT", "EFI/systemd", "EFI/Linux", "loader"):
        (staging / name).mkdir(parents=True, mode=0o700)
    (staging / "loader/loader.conf").write_text(LOADER_CONF)
    # The whole boot payload — loader, kernel, command line, verity authority
    # and development unit — is signed development content (ADR 0006 keys);
    # the ESP carries no unsigned kernel or initramfs. Secure Boot is still
    # unenforced until the variable store is enrolled.
    shutil.copyfile(loader, staging / "EFI/BOOT/BOOTX64.EFI")
    shutil.copyfile(loader, staging / "EFI/systemd/systemd-bootx64.efi")
    shutil.copyfile(uki, staging / ESP_UKI_PATH)
    (work / "gpt.sfdisk").write_text(sfdisk_script())
    workspace = work / "workspace"
    workspace.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={payload_output},dst=/payload,readonly",
        "--mount", f"type=bind,src={staging},dst=/staging",
        "--mount", f"type=bind,src={workspace},dst=/workspace",
        "--mount", f"type=bind,src={work},dst=/work,readonly", image]
    try:
        builder.logged(work, "format-esp", options + [
            "truncate", "--size", f"{ESP_MIB}M", "/workspace/esp.img"], timeout=120)
        builder.logged(work, "mkfs-esp", options + [
            "mkfs.vfat", "--invariant", "-F", "32", "-n", "FIREARC_ESP", "/workspace/esp.img"], timeout=300)
        builder.logged(work, "populate-esp", options + [
            "mcopy", "-i", "/workspace/esp.img", "-s",
            "/staging/EFI", "/staging/loader", "::"], timeout=300)
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
            "inputs": {"rootfs_label": rootfs_label, "sign_label": sign_label,
                       "uki_sha256": sha256(uki), "loader_sha256": sha256(loader),
                       "signer_fingerprint": sign_result.get("signer_fingerprint"),
                       "root_payload_sha256": sha256(data), "verity_sha256": sha256(tree),
                       "authority_sha256": sha256(payload_output / "verity-authority.json")},
            "esp": {"loader": "systemd-boot, development-signed (ADR 0006 sb key)",
                    "size_mib": ESP_MIB,
                    "uki": {"path": ESP_UKI_PATH, "sha256": sha256(uki),
                            "entry": "systemd-boot type-2 auto-entry (signed dev UKI)",
                            "signatures_verified": True},
                    "files": sorted(str(item.relative_to(staging)) for item in staging.rglob("*")
                                    if item.is_file())},
            "scope": "Development installed-device profile (signed boot artifacts, "
                     "Secure Boot not yet enrolled); not a release artifact and "
                     "not production provisioning",
        }
        write_json(work / "device.json", manifest)
        write_json(work / "result.json", {"passed": True, "artifacts": {"device.raw": sha256(disk)},
                                          "device_bytes": DISK_MIB * MIB,
                                          "boot_chain_qualified": False,
                                          "scope": "Offline development disk assembly with signed "
                                                   "boot artifacts; no boot executed"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Development disk assembled with signed boot artifacts; not yet booted"}


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
        # Three corruption disciplines on the same disk and firmware:
        #   good            — clean boot to the verified read-only sysroot,
        #                     plus a clean full runtime re-read of the mapping
        #   corrupt         — root byte flipped before boot: full preverification
        #                     must deny at exactly that offset
        #   runtime-corrupt — root byte flipped mid-session AFTER preverification
        #                     and mapping: the dev unit's cached-dropped re-read
        #                     must hit dm-verity's I/O error, never read through
        for name in ("good", "corrupt", "runtime-corrupt"):
            target = work / ("device-" + name + ".raw")
            # Private copies: QEMU opens the disk and the firmware flash
            # read-write, so stage artifacts must never be guest-writable.
            shutil.copyfile(disk, target)
            if name == "corrupt":
                rootfs.flip_byte(target, ROOT_OFFSET + rootfs.ROOT_BYTES // 2)
            flash = work / ("flash-" + name + ".rom")
            shutil.copyfile(rom, flash)
            serial = work / ("serial-" + name + ".log")
            # QMP-controlled machine: the harness stops QEMU itself as soon as
            # the serial verdict is in; no reliance on the guest powering off.
            session = start_vm(work, "qemu-boot-" + name, flash=flash, disk=target,
                               serial=serial, kvm=kvm, timeout=1800)
            try:
                if name == "runtime-corrupt":
                    session.wait_until(lambda text: REQUIRED_MARKER in text)
                    # The mapping is up and preverification passed; corrupt the
                    # underlying disk under the running machine.
                    rootfs.flip_byte(target, ROOT_OFFSET + rootfs.ROOT_BYTES // 2)
                    session.wait_until(lambda text: RUNTIME_EIO_MARKER in text
                                       or RUNTIME_CLEAN_MARKER in text)
                elif name == "good":
                    session.wait_until(
                        lambda text: (REQUIRED_MARKER in text
                                      and (RUNTIME_CLEAN_MARKER in text
                                           or RUNTIME_EIO_MARKER in text))
                        or bool(DENIAL_MARKER.search(text)))
                else:
                    session.wait_until(lambda text: REQUIRED_MARKER in text
                                       or bool(DENIAL_MARKER.search(text)))
                session.quit()  # no-op if the machine already left on its own
            finally:
                session.close()
            text = serial.read_text(errors="replace")
            markers, denial = boot_verdict(text)
            runtime = {"io_error": RUNTIME_EIO_MARKER in text,
                       "read_clean": RUNTIME_CLEAN_MARKER in text}
            # Guest firmware writes must land only in the declared variable
            # store; every code, flash-map, preserved and unmapped byte of the
            # booted flash copy must match the pristine image.
            flash_runs[name] = firmware_layout.write_confinement(
                pristine, flash.read_bytes(), layout)
            runs[name] = {"markers": markers, "denial": denial, "exited": True,
                          "runtime_verdict": runtime,
                          "menu_unstick_keypresses": session.keypresses}
            if name == "corrupt":
                if any(markers.values()) or not denial["denial"]:
                    raise SafetyError("Corrupted root was accepted or produced no verity denial")
            elif name == "runtime-corrupt":
                if not markers[REQUIRED_MARKER] or denial["denial"] \
                        or runtime["read_clean"] or not runtime["io_error"]:
                    raise SafetyError("Post-mapping corruption was not denied at "
                                      "runtime: dm-verity read through or returned "
                                      "no I/O error")
            elif not markers[REQUIRED_MARKER] or denial["denial"] \
                    or not runtime["read_clean"]:
                raise SafetyError("Uncorrupted development boot did not reach the "
                                  "verified read-only sysroot terminal marker with "
                                  "a clean runtime read")
        for name, digest in device_result["artifacts"].items():
            verify_file(regular_file(device_output, name), digest)
        builder.verify_tools(root, tools_label)
        write_json(work / "result.json", {
            "passed": True, "kvm": kvm,
            "positive_boot": runs["good"], "corruption_control": runs["corrupt"],
            "runtime_corruption_control": runs["runtime-corrupt"],
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
