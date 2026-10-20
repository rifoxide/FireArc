"""Persistent installed-device profile: OS disk, firmware flash and swtpm state.

A device profile is mutable machine state, deliberately outside the stage
graph: `provision` explicitly creates (or, with confirmation, replaces) a
per-device directory holding the persistent OS disk, the writable firmware
copy whose SMMSTORE region carries UEFI variables, and one isolated swtpm
TPM 2.0 state directory. `boot` then cold-starts the machine: every boot is
a fresh QEMU process plus a fresh swtpm process reusing the same state files,
so flash/TPM identity continuity across cold starts is asserted rather than
assumed, and nothing is ever silently reset — state changes only inside guest
execution, and re-provisioning is an explicit operation.

This is the development harness only: unsigned profile, host-trusted swtpm
custody, no PCR measurements (the pinned payload carries no TPM stack), no
warm-reboot loops and no power-cut/snapshot operations yet.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from . import builder, device, firmware_layout, pipeline
from .inputs import load_lock
from .integrity import SafetyError, private_directory, read_json, regular_file, sha256, write_json

PROFILE_SCHEMA = 1
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
MAX_BOOT_RUNS = 16
SWTPM_TIMEOUT = 120

# TPM console lines worth archiving per boot (kernel tpm_tis/ACPI messages).
TPM_CONSOLE_PATTERN = re.compile(r"(?i)\b(tpm|tcg2?)\b")


def validate_name(name):
    if not NAME_PATTERN.fullmatch(name or ""):
        raise SafetyError("Device name must match [a-z0-9][a-z0-9-]{0,31}")
    return name


def save_json(path, value):
    """Atomically replace mutable device-state JSON (not stage evidence)."""
    temporary = Path(path).parent / (Path(path).name + "." + uuid.uuid4().hex)
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def tpm_digests(directory):
    """Deterministic {file: sha256} inventory of one TPM state directory."""
    digests = {}
    for item in sorted(regular_path(directory).iterdir()):
        if item.is_file():
            digests[item.name] = sha256(item)
    return digests


def regular_path(directory):
    if not directory.is_dir():
        raise SafetyError(f"Expected directory: {directory}")
    return directory


def area_digest(image, layout, area_name):
    """sha256 of one flash area inside an image, by FMAP area name."""
    for area in layout["areas"]:
        if area["name"] == area_name:
            return hashlib.sha256(image[area["offset"]:area["offset"] + area["size"]]).hexdigest()
    raise SafetyError(f"Flash map has no {area_name!r} area")


def assert_identity_unchanged(expected, current, what):
    """Fail closed when persistent identity moved outside guest execution."""
    if expected != current:
        raise SafetyError(f"{what} changed outside guest execution; the profile state "
                          "was reset or tampered with. Re-provision explicitly if a "
                          "fresh device identity is intended")


def provision(root, name, *, replace=False):
    """Explicitly create (or replace) a persistent device profile."""
    validate_name(name)
    pipe = pipeline.Pipeline(root, online=False)
    device_label = pipe.ensure("device")["id"]
    firmware_label = pipe.ensure("firmware-build")["id"]
    return _provision(root, name, device_label, firmware_label, replace=replace)


def _provision(root, name, device_label, firmware_label, *, replace=False):
    device_source, device_output, device_result = device._stage_outputs(root, device_label, "device")
    disk = regular_file(device_output, "device.raw")
    if device_result.get("artifacts", {}).get("device.raw") != sha256(disk):
        raise SafetyError("Device stage does not vouch for the disk artifact")
    manifest = read_json(regular_file(device_source, "device.json"))
    firmware_source, rom, _ = device.firmware_rom(root, firmware_label)
    parent = private_directory(Path(root) / "build/devices", create=True)
    target = parent / name
    if target.exists():
        if not replace:
            raise SafetyError(f"Device profile {name!r} already exists; provisioning would "
                              "silently discard its flash/TPM identity. Use --replace "
                              "to explicitly create a fresh device")
        shutil.rmtree(target)
    target.mkdir(mode=0o700)
    shutil.copyfile(disk, target / "disk.raw")
    shutil.copyfile(rom, target / "flash.rom")
    (target / "tpm").mkdir(mode=0o700)
    (target / "runs").mkdir(mode=0o700)
    profile = {
        "schema": PROFILE_SCHEMA, "name": name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provenance": {
            "device_label": device_source.name, "device_raw_sha256": sha256(disk),
            "disk_bytes": disk.stat().st_size,
            "firmware_label": firmware_source.name, "rom_sha256": sha256(rom),
            "rom_bytes": rom.stat().st_size, "kernel_cmdline": manifest.get("kernel_cmdline"),
        },
        "boots": 0,
        "tpm": {"interface": "tpm-tis", "state_dir": "tpm", "backend": "swtpm --tpm2"},
        "scope": "Development persistent device state (disk, firmware variables, TPM); "
                 "not a reproducible payload and not production provisioning",
    }
    write_json(target / "profile.json", profile)
    return {"passed": True, "name": name, "evidence": str(target),
            "provenance": profile["provenance"],
            "scope": "New persistent device profile created; no boot executed"}


def load(root, name):
    """Load and structurally validate one persistent device profile."""
    validate_name(name)
    devices = Path(root) / "build/devices"
    if not devices.is_dir():
        raise SafetyError("No device profiles exist yet; run just device-provision first")
    target = private_directory(devices) / name
    profile = read_json(regular_file(target, "profile.json"))
    if profile.get("schema") != PROFILE_SCHEMA or profile.get("name") != name:
        raise SafetyError("Device profile schema or name mismatch")
    provenance = profile.get("provenance", {})
    if provenance.get("kernel_cmdline") != device.KERNEL_CMDLINE:
        raise SafetyError("Device profile was built against a different harness "
                          "kernel cmdline; re-provision explicitly")
    disk = regular_file(target, "disk.raw")
    flash = regular_file(target, "flash.rom")
    if disk.stat().st_size != provenance.get("disk_bytes") \
            or flash.stat().st_size != provenance.get("rom_bytes") \
            or provenance.get("rom_bytes") != device.FIRMWARE_BYTES:
        raise SafetyError("Device profile storage has unexpected geometry")
    return target, profile


def boot(root, name, *, count=2):
    """Cold-start the persistent profile; verify boot, writes and identity."""
    if not 1 <= count <= MAX_BOOT_RUNS:
        raise SafetyError(f"Boot count must be within 1..{MAX_BOOT_RUNS}")
    target, profile = load(root, name)
    provenance = profile["provenance"]
    qemu = shutil.which("qemu-system-x86_64")
    swtpm = shutil.which("swtpm")
    pins = load_lock(root, "host-tools")["tools"]
    for tool, path in (("qemu-system-x86_64", qemu), ("swtpm", swtpm)):
        if not path or sha256(Path(path)) != pins[tool]["sha256"]:
            raise SafetyError(f"Host {tool} is absent or does not match the pinned tool")
    _, rom, _ = device.firmware_rom(root, provenance["firmware_label"])
    pristine = rom.read_bytes()
    layout = firmware_layout.classify(pristine, firmware_layout.parse_fmap(pristine))
    disk = target / "disk.raw"
    flash = target / "flash.rom"
    tpm_dir = regular_path(target / "tpm")
    runs_dir = regular_path(target / "runs")
    # Identity continuity across invocations: whatever the last boot left
    # behind must still be there, untouched, when the next cold start begins.
    expected_state = profile.get("state_after_last_boot")
    if expected_state:
        assert_identity_unchanged(
            expected_state.get("smmstore_sha256"),
            area_digest(flash.read_bytes(), layout, firmware_layout.VARIABLE_STORE_AREA),
            "Firmware variable-store region")
        assert_identity_unchanged(expected_state.get("tpm_sha256"), tpm_digests(tpm_dir),
                                  "TPM state")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    first_ever_boot = profile.get("boots", 0) == 0
    records = []
    try:
        for offset in range(count):
            number = profile["boots"] + 1
            run_dir = runs_dir / f"{number:04d}"
            run_dir.mkdir(mode=0o700)
            smm_before = area_digest(flash.read_bytes(), layout, firmware_layout.VARIABLE_STORE_AREA)
            tpm_before = tpm_digests(tpm_dir)
            if records:
                assert_identity_unchanged(records[-1]["smmstore_sha256_after"], smm_before,
                                          "Firmware variable-store region")
                assert_identity_unchanged(records[-1]["tpm_sha256_after"], tpm_before,
                                          "TPM state")
            serial = run_dir / "serial.log"
            record = _cold_start(run_dir, qemu, swtpm, flash, disk, tpm_dir, serial, kvm)
            text = serial.read_text(errors="replace")
            markers, denial = device.boot_verdict(text)
            tpm_ok = device.TPM_TIS_MARKER in text and device.TPM_TIS_MISSING_MARKER not in text
            if not markers[device.REQUIRED_MARKER] or denial["denial"]:
                raise SafetyError(f"Cold start {number} did not reach the verified "
                                  "read-only sysroot terminal marker")
            if not tpm_ok:
                raise SafetyError(f"Cold start {number} did not bind a TPM 2.0 device "
                                  f"through ACPI/TIS (no {device.TPM_TIS_MARKER!r} marker)")
            confinement = firmware_layout.write_confinement(
                pristine, flash.read_bytes(), layout)
            smm_after = area_digest(flash.read_bytes(), layout, firmware_layout.VARIABLE_STORE_AREA)
            tpm_after = tpm_digests(tpm_dir)
            if not tpm_after:
                raise SafetyError(f"Cold start {number} persisted no swtpm state")
            if first_ever_boot and offset == 0 and smm_after == area_digest(
                    pristine, layout, firmware_layout.VARIABLE_STORE_AREA):
                raise SafetyError("First boot of the profile left the variable store "
                                  "identical to the erased pristine image")
            record.update({
                "run": number, "cold_start": True, "kvm": kvm, "markers": markers,
                "denial": denial, "tpm_tis_acpi_bound": True,
                "tpm_console_lines": [line.strip()[:200] for line in text.splitlines()
                                      if TPM_CONSOLE_PATTERN.search(line)][:40],
                "smmstore_sha256_before": smm_before, "smmstore_sha256_after": smm_after,
                "tpm_sha256_before": tpm_before, "tpm_sha256_after": tpm_after,
                "tpm_state_changed_in_boot": tpm_before != tpm_after,
                "disk_sha256": sha256(disk),
                "flash_write_confinement": confinement,
                "qemu_sha256": pins["qemu-system-x86_64"]["sha256"],
                "swtpm_sha256": pins["swtpm"]["sha256"],
                "scope": "One cold start of the persistent profile; fresh QEMU and "
                         "swtpm processes over the same disk/flash/TPM state",
            })
            records.append(record)
            profile["boots"] = number
            profile["state_after_last_boot"] = {
                "smmstore_sha256": smm_after, "tpm_sha256": tpm_after}
            save_json(target / "profile.json", profile)
            write_json(run_dir / "run.json", record)
    except Exception as error:
        profile["last_error"] = str(error)
        save_json(target / "profile.json", profile)
        raise
    return {"passed": True, "name": name, "boots": [record["run"] for record in records],
            "identity": profile["state_after_last_boot"], "evidence": str(target),
            "scope": "Persistent cold-start boots with flash/TPM identity continuity "
                     "(development trust domain)"}


def _cold_start(run_dir, qemu, swtpm, flash, disk, tpm_dir, serial, kvm):
    """Boot once: fresh QEMU plus one swtpm instance over persistent state."""
    control = run_dir / "swtpm.sock"
    log = run_dir / "swtpm.log"
    command = [swtpm, "socket", "--tpm2", "--tpmstate", f"dir={tpm_dir}",
               "--ctrl", f"type=unixio,path={control}",
               "--log", f"file={log}", "--terminate"]
    with (run_dir / "swtpm-stderr.log").open("wb") as error_stream:
        process = subprocess.Popen(command, stdout=error_stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while not control.exists():
                if process.poll() is not None:
                    raise SafetyError(f"swtpm exited before accepting control "
                                      f"(rc={process.returncode}); see {log.name}")
                if time.monotonic() > deadline:
                    raise SafetyError("swtpm did not open its control socket")
                time.sleep(0.1)
            time.sleep(0.2)  # settle listen() before QEMU connects
            builder.logged(run_dir, "qemu-boot", device.qemu_command(
                flash, disk, serial, kvm=kvm, tpm=control), timeout=1800)
        finally:
            try:
                process.wait(timeout=SWTPM_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=10)
                raise SafetyError("swtpm did not exit after QEMU disconnected")
            if process.returncode not in (0, None):
                raise SafetyError(f"swtpm exited with rc={process.returncode}; "
                                  f"see {log.name}")
    return {"swtpm_state_dir": tpm_dir.name, "swtpm_control": "unixio"}
