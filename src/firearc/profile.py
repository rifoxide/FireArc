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

Beyond plain power-ons, the operator drives the machine explicitly:
`reboot` warm-resets a running machine in place (same QEMU/swtpm processes:
flash and TPM stay powered through the reset), `stop` requests an orderly
power-down over the local QMP socket, `powercut` kills both processes hard
without cleanup, and `snapshot`/`restore` copy and — only on explicit
command — restore the whole persistent state. Ordinary boot never silently
resets TPM/NVRAM or other identity after any failure: every operation starts
and ends with digest assertions and fails closed.

This is the development harness only: unsigned profile, host-trusted swtpm
custody, no PCR measurements (the pinned payload carries no TPM stack).
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import time
import uuid

from . import builder, device, firmware_layout, luks, pipeline
from .inputs import load_lock
from .integrity import (
    SafetyError, ok_line, private_directory, read_json, regular_file, sha256, verify_file,
    write_json,
)

PROFILE_SCHEMA = 1
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
MAX_BOOT_RUNS = 16
MAX_RESETS = 8
SWTPM_TIMEOUT = 120
VM_TIMEOUT = 1800
# stop(): how long the machine may take to honor the QMP powerdown request
# (ACPI power button) before the harness stops it itself.
STOP_POWERDOWN_WAIT = 30
# powercut(): let the machine settle into the fully booted OS before cutting.
POWERCUT_SETTLE_SECONDS = 20

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
    print(f"\u25b8 provisioning device '{name}'"
          + (" (replacing existing state)" if replace else ""), file=sys.stderr, flush=True)
    """Explicitly create (or replace) a persistent device profile."""
    validate_name(name)
    pipe = pipeline.Pipeline(root, online=False)
    device_label = pipe.ensure("device")["id"]
    # The profile's firmware is the vboot-signed image (our GBB root): the
    # machine's flash carries verified RW sections from cold start.
    firmware_label = pipe.ensure("firmware-sign")["id"]
    tools_label = pipe.ensure("tools")["id"]
    return _provision(root, name, device_label, firmware_label, tools_label,
                      replace=replace)


def _provision(root, name, device_label, firmware_label, tools_label, *, replace=False):
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
    # Per-device LUKS2 data volume: created exactly here, from the blank
    # factory region, with unique volume material and a separate recovery
    # credential (Phase 5 item 6). Escrow of the credential is item 7.
    data = luks.provision_data(root, target, tools_label)
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
        "data": {"volume": "luks2", "uuid": data["uuid"],
                 "region_sha256": data["data_region_sha256"],
                 "keyslots": data["keyslots"],
                 "recovery_credential": {**data["recovery_credential"]},
                 "evidence": "provision/data.json"},
        "operations": [{"op": "provision", "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "data_volume_uuid": data["uuid"]}],
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
    data = profile.get("data")
    if data:
        # Provisioned data volume: the sealed region is device identity. It
        # must still match the provisioning evidence, and the recovery
        # credential must remain where the profile recorded it.
        if data.get("volume") != "luks2" or not data.get("uuid") \
                or data.get("keyslots") not in (["0"], ["0", "1"]):
            raise SafetyError("Provisioned data volume does not match the "
                              "per-device LUKS2 provisioning contract")
        if data.get("keyslots") == ["0", "1"] and not data.get("token"):
            raise SafetyError("Enrolled data volume lacks its token record")
        if not data.get("enroll_pending") and luks.region_digest(disk, luks.DATA_OFFSET) != data.get("region_sha256"):
            raise SafetyError("LUKS2 data volume region diverged from the "
                              "provisioning evidence; re-provision explicitly")
        credential = regular_file(target, data.get("recovery_credential", {}).get("path", ""))
        import stat as stat_module
        if stat_module.S_IMODE(credential.lstat().st_mode) != 0o600:
            raise SafetyError("Recovery credential must be a 0600 file")
        if hashlib.sha256(credential.read_bytes()).hexdigest() \
                != data["recovery_credential"].get("sha256"):
            raise SafetyError("Recovery credential does not match its recorded digest")
    return target, profile


def next_run(runs_dir):
    """Monotonic per-profile run directory: runs/0001, runs/0002, ..."""
    numbers = [int(entry.name) for entry in runs_dir.iterdir()
               if entry.is_dir() and re.fullmatch(r"[0-9]{4}", entry.name)]
    return runs_dir / f"{max(numbers, default=0) + 1:04d}"


def record_operation(profile, op, **fields):
    entry = {"op": op, "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    entry.update(fields)
    operations = profile.get("operations", [])[-63:] + [entry]
    profile["operations"] = operations


def _prepare(root, name):
    """Resolve and verify everything one powered-on session needs."""
    target, profile = load(root, name)
    qemu = shutil.which("qemu-system-x86_64")
    swtpm = shutil.which("swtpm")
    pins = load_lock(root, "host-tools")["tools"]
    for tool, path in (("qemu-system-x86_64", qemu), ("swtpm", swtpm)):
        if not path or sha256(Path(path)) != pins[tool]["sha256"]:
            raise SafetyError(f"Host {tool} is absent or does not match the pinned tool")
    _, rom, _ = device.firmware_rom(root, profile["provenance"]["firmware_label"])
    pristine = rom.read_bytes()
    layout = firmware_layout.classify(pristine, firmware_layout.parse_fmap(pristine))
    return {
        "target": target, "profile": profile, "pins": pins, "qemu": qemu, "swtpm": swtpm,
        "pristine": pristine, "layout": layout,
        "disk": regular_file(target, "disk.raw"), "flash": regular_file(target, "flash.rom"),
        "tpm_dir": regular_path(target / "tpm"), "runs_dir": regular_path(target / "runs"),
        "pristine_store_sha256": area_digest(pristine, layout, firmware_layout.VARIABLE_STORE_AREA),
    }


def _assert_session_started_from_expected_state(prepared):
    """Identity continuity across invocations: the last session's end state
    must still be there, untouched, when the machine powers on again."""
    expected = prepared["profile"].get("state_after_last_boot")
    if not expected:
        return
    assert_identity_unchanged(
        expected.get("smmstore_sha256"),
        area_digest(prepared["flash"].read_bytes(), prepared["layout"],
                    firmware_layout.VARIABLE_STORE_AREA),
        "Firmware variable-store region")
    assert_identity_unchanged(expected.get("tpm_sha256"), tpm_digests(prepared["tpm_dir"]),
                              "TPM state")
    if expected.get("data_sha256"):
        # Nothing in the boot path may touch the sealed data volume; the
        # per-device LUKS2 region is identity, not scratch space.
        assert_identity_unchanged(
            expected["data_sha256"],
            luks.region_digest(prepared["disk"], luks.DATA_OFFSET),
            "LUKS2 data volume region")


def _assert_boot_markers(text, what):
    """A powered-on session must reach the verified sysroot and bind the TPM."""
    markers, denial = device.boot_verdict(text)
    if not markers[device.REQUIRED_MARKER] or denial["denial"]:
        raise SafetyError(f"{what} did not reach the verified read-only sysroot "
                          f"terminal marker")
    tpm_ok = (device.TPM_TIS_MARKER in text
              and device.TPM_TIS_MISSING_MARKER not in text)
    if not tpm_ok:
        raise SafetyError(f"{what} did not bind a TPM 2.0 device through ACPI/TIS "
                          f"(no {device.TPM_TIS_MARKER!r} marker)")
    # The data-unlock probe must report a healthy outcome: an unattended
    # TPM2 unlock, an as-yet-unenrolled volume, or a pre-data disk. Refusal
    # or missing TPM/signature files is a failed session, never a pass.
    healthy = (device.DATA_UNLOCK_OK_MARKER in text
               or device.DATA_TOKEN_ABSENT_MARKER in text
               or device.DATA_PROBE_NO_DISK_MARKER in text)
    refused = (device.DATA_UNLOCK_REFUSED_MARKER in text
               or device.DATA_PROBE_NO_TPM_MARKER in text
               or device.DATA_PCRSIG_MISSING_MARKER in text)
    if refused or not healthy:
        raise SafetyError(f"{what} did not report a healthy data-unlock probe "
                          f"outcome (refused={refused})")
    return markers, denial


class Machine:
    """One power-on of the persistent device: isolated swtpm plus QEMU/QMP.

    Entering starts swtpm over the persistent state directory and boots the
    machine from the profile's disk/flash; every session reads and writes the
    same files, so identity continuity across power-ons is asserted by the
    caller. Leaving waits for swtpm to exit (it terminates with QEMU); after
    a power cut both processes die hard and carry the kill status.
    """

    def __init__(self, run_dir, qemu, swtpm, flash, disk, tpm_dir, serial, *,
                 kvm, rebootable=False, timeout=VM_TIMEOUT, enroll_disk=None):
        self.run_dir = run_dir
        self.qemu = qemu
        self.swtpm = swtpm
        self.flash = flash
        self.disk = disk
        self.tpm_dir = tpm_dir
        self.serial = serial
        self.kvm = kvm
        self.rebootable = rebootable
        self.timeout = timeout
        self.enroll_disk = enroll_disk
        self.process = None
        self.session = None
        self.cut = False
        self._stderr = None

    def __enter__(self):
        control = self.run_dir / "swtpm.sock"
        log = self.run_dir / "swtpm.log"
        self._stderr = (self.run_dir / "swtpm-stderr.log").open("xb")
        command = [self.swtpm, "socket", "--tpm2", "--tpmstate", f"dir={self.tpm_dir}",
                   "--ctrl", f"type=unixio,path={control}",
                   "--log", f"file={log}", "--terminate"]
        print(f"  \u25b8 swtpm: starting (state: {self.tpm_dir.parent.name}/{self.tpm_dir.name})\n"
              f"    $ {shlex.join(command)}", file=sys.stderr, flush=True)
        self.process = subprocess.Popen(command, stdout=self._stderr,
                                        stderr=subprocess.STDOUT,
                                        preexec_fn=device.die_with_parent)
        try:
            deadline = time.monotonic() + 20
            while not control.exists():
                if self.process.poll() is not None:
                    raise SafetyError(f"swtpm exited before accepting control "
                                      f"(rc={self.process.returncode}); see {log.name}")
                if time.monotonic() > deadline:
                    raise SafetyError("swtpm did not open its control socket")
                time.sleep(0.1)
            time.sleep(0.2)  # settle listen() before QEMU connects
            self.session = device.start_vm(
                self.run_dir, "qemu-boot", flash=self.flash, disk=self.disk,
                serial=self.serial, kvm=self.kvm, tpm=control,
                rebootable=self.rebootable, timeout=self.timeout,
                enroll_disk=self.enroll_disk)
        except BaseException:
            self._stop_swtpm()
            raise
        return self

    def power_cut(self):
        """Emulated board power loss: both processes die without cleanup."""
        self.cut = True
        self.session.kill()
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=30)

    def _stop_swtpm(self):
        if self.process is None:
            return
        try:
            self.process.wait(timeout=SWTPM_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
            raise SafetyError("swtpm did not exit after QEMU disconnected")
        allowed = (0, -9) if self.cut else (0, None)
        if self.process.returncode not in allowed:
            raise SafetyError(f"swtpm exited with rc={self.process.returncode}; "
                              f"see swtpm.log")
        if self._stderr is not None and not self._stderr.closed:
            self._stderr.close()

    def __exit__(self, *exception):
        if self.session is not None:
            self.session.close()
        self._stop_swtpm()
        return False


def _finish_session(prepared, run_dir, serial_text, record, session):
    """Shared post-session evidence: flash confinement and identity update."""
    layout = prepared["layout"]
    flash = prepared["flash"]
    confinement = firmware_layout.write_confinement(
        prepared["pristine"], flash.read_bytes(), layout)
    record.update({
        "smmstore_sha256_after": area_digest(flash.read_bytes(), layout,
                                             firmware_layout.VARIABLE_STORE_AREA),
        "tpm_sha256_after": tpm_digests(prepared["tpm_dir"]),
        "data_sha256_after": (luks.region_digest(prepared["disk"], luks.DATA_OFFSET)
                              if prepared["profile"].get("data") else None),
        "disk_sha256": sha256(prepared["disk"]),
        "flash_write_confinement": confinement,
        "qemu_sha256": prepared["pins"]["qemu-system-x86_64"]["sha256"],
        "swtpm_sha256": prepared["pins"]["swtpm"]["sha256"],
        "menu_unstick_keypresses": session.keypresses,
        "tpm_console_lines": [line.strip()[:200] for line in serial_text.splitlines()
                              if TPM_CONSOLE_PATTERN.search(line)][:40],
        "qmp_control": "unix:" + (run_dir / "qemu-boot.qmp.sock").name,
    })
    if not record["tpm_sha256_after"]:
        raise SafetyError("The session persisted no swtpm state")
    return record


def _session_scope(extra):
    return extra + " (development trust domain; fresh QEMU and swtpm processes " \
                   "over the same disk/flash/TPM state)"


def _record_failure(prepared, run_dir, op, error, session, session_ran):
    """Fail honestly: record what a failed session did to persistent state.

    A session that actually ran the machine may have legitimately written
    flash/TPM state (guest execution) before the harness failed. The observed
    identity is adopted as the new baseline with an explicit failed-operation
    record, so later sessions assert continuity from what actually happened
    instead of blocking forever on a stale baseline. Failures before the
    machine powered on record only the error.
    """
    profile = prepared["profile"]
    if session_ran:
        record = {
            "op": op, "run": int(run_dir.name), "passed": False,
            "error": str(error)[:500],
            "smmstore_sha256_after": area_digest(
                prepared["flash"].read_bytes(), prepared["layout"],
                firmware_layout.VARIABLE_STORE_AREA),
            "tpm_sha256_after": tpm_digests(prepared["tpm_dir"]),
            "data_sha256_after": (luks.region_digest(prepared["disk"], luks.DATA_OFFSET)
                                  if prepared["profile"].get("data") else None),
            "menu_unstick_keypresses": getattr(session, "keypresses", None),
            "scope": "Failed session; observed state adopted as the new baseline",
        }
        save_json(run_dir / "run.json", record)
        profile["boots"] = profile.get("boots", 0) + 1
        profile["state_after_last_boot"] = {
            "smmstore_sha256": record["smmstore_sha256_after"],
            "tpm_sha256": record["tpm_sha256_after"],
            "data_sha256": record.get("data_sha256_after")}
        record_operation(profile, op, run=int(run_dir.name), failed=True,
                         error=str(error)[:200])
    profile["last_error"] = str(error)
    save_json(prepared["target"] / "profile.json", profile)


def data_enroll(root, name):
    print(f"\u25b8 data-enroll '{name}': one TPM2 enrollment boot (PCR 7 + signed PCR 11)",
          file=sys.stderr, flush=True)
    """One enrollment session: boot with the one-shot credential transport
    attached, let the guest enroll the TPM2 token against the live PCR
    state (PCR 7 + the signed PCR 11 policy), validate the in-boot unlock,
    then verify the on-disk token against our PCR-policy key host-side.

    The session is a real powered-on boot (flash/TPM identity advance), and
    the LUKS2 header legitimately changes: keyslot 1 + the systemd-tpm2
    token. Both are recorded, so later boots assert continuity from the
    post-enrollment state.
    """
    prepared = _prepare(root, name)
    profile = prepared["profile"]
    data = profile.get("data")
    if not data:
        raise SafetyError("Profile has no provisioned data volume; run "
                          "device-provision first")
    if data.get("keyslots") != ["0"]:
        raise SafetyError("Data volume is already TPM-enrolled; re-enrollment "
                          "is an explicit re-provision")
    _assert_session_started_from_expected_state(prepared)
    credential = regular_file(prepared["target"], "secrets/recovery.key")
    if hashlib.sha256(credential.read_bytes()).hexdigest() \
            != data["recovery_credential"]["sha256"]:
        raise SafetyError("Recovery credential does not match its recorded digest")
    policy_pem, policy_pkfp = luks.expected_pcr_policy(root)
    # An interrupted enrollment session may have written the token to the
    # volume without the profile being updated. Fail closed — but with a
    # validated adoption, so the operator can recover without destroying
    # the device: the token must satisfy the full host-side contract.
    with open(prepared["disk"], "rb") as handle:
        handle.seek(luks.DATA_OFFSET)
        current_header = luks.parse_header_json(handle.read(luks.HEADER_READ_BYTES))
    if data.get("keyslots") == ["0"] and current_header.get("tokens"):
        token = luks.validate_enrolled(current_header, expected_pem=policy_pem)
        data["keyslots"] = ["0", "1"]
        data["region_sha256"] = luks.region_digest(prepared["disk"], luks.DATA_OFFSET)
        data["token"] = {"type": luks.TOKEN_TYPE, "pcrs_plain": ["7"],
                         "pcrs_signed": ["11"], "policy_pkfp": policy_pkfp,
                         "adopted_after_interrupt": True}
        data.pop("enroll_pending", None)
        record_operation(profile, "data-enroll-adopt", interrupted=True)
        save_json(prepared["target"] / "profile.json", profile)
        raise SafetyError("Found an enrolled volume from an interrupted session; "
                          "the profile has adopted the validated token — re-run "
                          "data-enroll or boot to validate the unlock")
    # Transaction marker: an interrupted session may leave the volume
    # enrolled while the profile still records the pre-enrollment state;
    # with this flag set, load() tolerates the divergence and the adoption
    # path above is the only way to clear it.
    data["enroll_pending"] = True
    save_json(prepared["target"] / "profile.json", profile)
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    run_dir = next_run(prepared["runs_dir"])
    run_dir.mkdir(mode=0o700)
    enroll_disk = run_dir / "enroll-key.img"
    luks.build_enroll_disk(enroll_disk, credential.read_bytes())
    serial = run_dir / "serial.log"
    machine = Machine(run_dir, prepared["qemu"], prepared["swtpm"], prepared["flash"],
                      prepared["disk"], prepared["tpm_dir"], serial, kvm=kvm,
                      timeout=VM_TIMEOUT, enroll_disk=enroll_disk)
    session_ran = False
    try:
        with machine:
            session_ran = True
            machine.session.wait_until(
                lambda text: device.DATA_ENROLL_OK_MARKER in text
                or device.DATA_ENROLL_FAIL_MARKER in text
                or device.DATA_ENROLL_ALREADY_MARKER in text
                or device.DATA_ENROLL_NO_PCRSIG_MARKER in text
                or device.DATA_ENROLL_DISK_ABSENT_MARKER in text)
            # Give the probe unit (ordered after enrollment) its turn to
            # validate the fresh token with a real unattended unlock.
            machine.session.wait_until(
                lambda text: device.DATA_UNLOCK_OK_MARKER in text
                or device.DATA_UNLOCK_REFUSED_MARKER in text
                or device.DATA_TOKEN_ABSENT_MARKER in text)
            try:
                machine.session.wait_until(
                    lambda text: "FIREARC_PCR_DUMP_END" in text)
            except SafetyError:
                pass
            machine.session.quit()
            text = serial.read_text(errors="replace")
    except Exception as error:
        _record_failure(prepared, run_dir, "data-enroll", error,
                        machine.session, session_ran)
        raise
    finally:
        # The one-shot transport never outlives its session.
        luks.scrub(enroll_disk)
    try:
        for refused in (device.DATA_ENROLL_FAIL_MARKER, device.DATA_ENROLL_ALREADY_MARKER,
                        device.DATA_ENROLL_NO_PCRSIG_MARKER,
                        device.DATA_ENROLL_DISK_ABSENT_MARKER,
                        device.DATA_UNLOCK_REFUSED_MARKER,
                        device.DATA_TOKEN_ABSENT_MARKER,
                        device.DATA_PROBE_NO_TPM_MARKER, device.DATA_PCRSIG_MISSING_MARKER):
            if refused in text:
                raise SafetyError(f"Enrollment session reported {refused!r}; "
                                  f"inspect {run_dir}")
        if device.DATA_ENROLL_OK_MARKER not in text or device.DATA_UNLOCK_OK_MARKER not in text:
            raise SafetyError(f"Enrollment session lacked its OK markers; inspect {run_dir}")
        _assert_boot_markers(text, "Enrollment boot")
        # Host-side verification of the mutated header: keyslot 1 + exactly one
        # systemd-tpm2 token covering PCR 7 and the signed PCR 11 policy, under
        # our PCR-policy public key, spliced exactly once into the data region.
        with open(prepared["disk"], "rb") as handle:
            handle.seek(luks.DATA_OFFSET)
            on_disk = handle.read(luks.HEADER_READ_BYTES)
        header = luks.parse_header_json(on_disk)
        luks.assert_binary_identity(on_disk, uuid=data["uuid"])
        token = luks.validate_enrolled(header, expected_pem=policy_pem)
        new_region = luks.region_digest(prepared["disk"], luks.DATA_OFFSET)
        if new_region == data["region_sha256"]:
            raise SafetyError("Enrollment boot did not change the data region")
        record = {
            "op": "data-enroll", "run": int(run_dir.name), "passed": True,
            "kvm": kvm, "policy_pkfp": policy_pkfp,
            "token": {"type": token["type"],
                      "pcrs_plain": sorted(str(v) for v in token.get("tpm2-pcrs", [])),
                      "pcrs_signed": sorted(str(v) for v in token.get("tpm2_pubkey_pcrs", [])),
                      "keyslot": token.get("keyslots")},
            "region_sha256_before": data["region_sha256"],
            "scope": _session_scope("TPM2 enrollment of the data volume "
                                    "(PCR 7 + signed PCR 11 policy)"),
        }
        _finish_session(prepared, run_dir, text, record, machine.session)
    except Exception as error:
        # The machine already ran and advanced identity (flash/TPM, and
        # possibly the volume); a failed post-session validation must still
        # record that observed state honestly, never leave the profile
        # asserting a pre-session baseline that no longer exists.
        record = {"op": "data-enroll", "run": int(run_dir.name), "passed": False,
                  "error": str(error)[:500],
                  "smmstore_sha256_after": area_digest(
                      prepared["flash"].read_bytes(), prepared["layout"],
                      firmware_layout.VARIABLE_STORE_AREA),
                  "tpm_sha256_after": tpm_digests(prepared["tpm_dir"]),
                  "data_sha256_after": luks.region_digest(prepared["disk"], luks.DATA_OFFSET),
                  "scope": "Failed enrollment session; observed state adopted as "
                           "the new baseline (enroll_pending remains set)"}
        save_json(run_dir / "run.json", record)
        profile["boots"] = profile.get("boots", 0) + 1
        profile["state_after_last_boot"] = {
            "smmstore_sha256": record["smmstore_sha256_after"],
            "tpm_sha256": record["tpm_sha256_after"],
            "data_sha256": record["data_sha256_after"]}
        record_operation(profile, "data-enroll", run=int(run_dir.name), failed=True,
                         error=str(error)[:200])
        profile["last_error"] = str(error)
        save_json(prepared["target"] / "profile.json", profile)
        raise
    data["keyslots"] = ["0", "1"]
    data["region_sha256"] = new_region
    data["token"] = {"type": luks.TOKEN_TYPE, "pcrs_plain": ["7"],
                     "pcrs_signed": ["11"], "policy_pkfp": policy_pkfp,
                     "enrolled_run": int(run_dir.name)}
    data.pop("enroll_pending", None)
    data["recovery_credential"]["transport"] = ("one-shot enroll disk (item 8); "
                                                 "file only; never in argv, serial or logs")
    profile["boots"] = profile.get("boots", 0) + 1
    profile["state_after_last_boot"] = {
        "smmstore_sha256": record["smmstore_sha256_after"],
        "tpm_sha256": record["tpm_sha256_after"],
        "data_sha256": record["data_sha256_after"]}
    record_operation(profile, "data-enroll", run=int(run_dir.name), passed=True)
    save_json(prepared["target"] / "profile.json", profile)
    write_json(run_dir / "run.json", record)
    return {"passed": True, "name": name, "run": int(run_dir.name),
            "token": data["token"], "policy_pkfp": policy_pkfp,
            "region_sha256": new_region, "evidence": str(run_dir),
            "scope": "TPM2 token enrolled against the live boot state and "
                     "validated by an unattended in-boot unlock"}


def boot(root, name, *, count=2, tcg=False):
    """Cold-start the persistent profile; verify boot, writes and identity.

    `tcg=True` forces the TCG software-accelerated machine (initial-correctness
    profile); KVM is the default distinct profile whenever available. Every
    run records which accelerator served it.
    """
    if not 1 <= count <= MAX_BOOT_RUNS:
        raise SafetyError(f"Boot count must be within 1..{MAX_BOOT_RUNS}")
    prepared = _prepare(root, name)
    profile = prepared["profile"]
    layout = prepared["layout"]
    flash, tpm_dir, runs_dir = prepared["flash"], prepared["tpm_dir"], prepared["runs_dir"]
    _assert_session_started_from_expected_state(prepared)
    kvm = not tcg and os.access("/dev/kvm", os.R_OK | os.W_OK)
    timeout = VM_TIMEOUT if kvm else 2 * VM_TIMEOUT  # TCG boots are far slower
    first_ever_boot = profile.get("boots", 0) == 0
    records = []
    try:
        for offset in range(count):
            run_dir = next_run(runs_dir)
            run_dir.mkdir(mode=0o700)
            number = int(run_dir.name)
            smm_before = area_digest(flash.read_bytes(), layout,
                                     firmware_layout.VARIABLE_STORE_AREA)
            tpm_before = tpm_digests(tpm_dir)
            if records:
                assert_identity_unchanged(records[-1]["smmstore_sha256_after"], smm_before,
                                          "Firmware variable-store region")
                assert_identity_unchanged(records[-1]["tpm_sha256_after"], tpm_before,
                                          "TPM state")
            serial = run_dir / "serial.log"
            print(f"  \u25b8 cold boot {offset + 1}/{count} (run {number}, "
                  f"{run_dir.parent.parent.name}/{run_dir.name})", file=sys.stderr, flush=True)
            boot_started = time.monotonic()
            machine = Machine(run_dir, prepared["qemu"], prepared["swtpm"], flash,
                              prepared["disk"], tpm_dir, serial, kvm=kvm,
                              timeout=timeout)
            session_ran = False
            try:
                with machine:
                    session_ran = True
                    machine.session.wait_until(lambda text: device.REQUIRED_MARKER in text
                                               or device.DENIAL_MARKER.search(text))
                    if prepared.get("tpm_dir") is not None:
                        # The Phase 5 investigation dump (securityfs event log
                        # via od) trails the boot marker; let it finish before
                        # quitting. Diagnostic only — an incomplete dump is
                        # recorded by the missing end marker, never fatal.
                        try:
                            machine.session.wait_until(
                                lambda text: "FIREARC_PCR_DUMP_END" in text)
                        except SafetyError:
                            pass
                    # The data-unlock probe's verdict is part of every boot's
                    # contract (a bounded TPM2 attach may legitimately take
                    # longer than the boot markers); wait for it before
                    # quitting so refusal is always captured, never missed
                    # by quitting too early.
                    machine.session.wait_until(
                        lambda text: (device.DATA_UNLOCK_OK_MARKER in text
                                      or device.DATA_UNLOCK_REFUSED_MARKER in text
                                      or device.DATA_TOKEN_ABSENT_MARKER in text
                                      or device.DATA_PROBE_NO_DISK_MARKER in text
                                      or device.DATA_PROBE_NO_TPM_MARKER in text
                                      or device.DATA_PCRSIG_MISSING_MARKER in text))
                    machine.session.quit()
                    text = serial.read_text(errors="replace")
            except Exception as error:
                _record_failure(prepared, run_dir, "boot", error,
                                machine.session, session_ran)
                raise
            markers, denial = _assert_boot_markers(text, f"Cold start {number}")
            smm_after = area_digest(flash.read_bytes(), layout,
                                    firmware_layout.VARIABLE_STORE_AREA)
            if first_ever_boot and offset == 0 and smm_after == prepared["pristine_store_sha256"]:
                raise SafetyError("First boot of the profile left the variable store "
                                  "identical to the erased pristine image")
            record = {
                "op": "boot", "run": number, "cold_start": True, "kvm": kvm,
                "accel": "kvm" if kvm else "tcg",
                "markers": markers, "denial": denial, "tpm_tis_acpi_bound": True,
                "smmstore_sha256_before": smm_before,
                "tpm_sha256_before": tpm_before,
                "scope": _session_scope("Cold start of the persistent profile"),
            }
            _finish_session(prepared, run_dir, text, record, machine.session)
            record["tpm_state_changed_in_boot"] = tpm_before != record["tpm_sha256_after"]
            records.append(record)
            profile["boots"] = number
            profile["state_after_last_boot"] = {
                "smmstore_sha256": record["smmstore_sha256_after"],
                "tpm_sha256": record["tpm_sha256_after"],
                "data_sha256": record.get("data_sha256_after")}
            record_operation(profile, "boot", run=number)
            save_json(prepared["target"] / "profile.json", profile)
            write_json(run_dir / "run.json", record)
            print(ok_line(f"  \u2713 cold boot {number} passed ({time.monotonic() - boot_started:.0f}s)"),
                  file=sys.stderr, flush=True)
    except Exception as error:
        profile["last_error"] = str(error)
        save_json(prepared["target"] / "profile.json", profile)
        raise
    return {"passed": True, "name": name, "boots": [record["run"] for record in records],
            "identity": profile["state_after_last_boot"], "evidence": str(prepared["target"]),
            "scope": "Persistent cold-start boots with flash/TPM identity continuity "
                     "(development trust domain)"}


def reboot(root, name, *, resets=2):
    """Warm-reset the running machine in place; flash and TPM stay powered.

    One QEMU process and one swtpm process serve the whole session: every
    QMP system_reset re-enters the firmware with the variable store and TPM
    state carried over, exactly like a warm reset of real hardware. The
    session ends with a full verified boot; a reset that silently restored
    pristine NVRAM or wiped TPM state fails closed.
    """
    if not 1 <= resets <= MAX_RESETS:
        raise SafetyError(f"Reset count must be within 1..{MAX_RESETS}")
    prepared = _prepare(root, name)
    profile = prepared["profile"]
    layout = prepared["layout"]
    flash, tpm_dir, runs_dir = prepared["flash"], prepared["tpm_dir"], prepared["runs_dir"]
    _assert_session_started_from_expected_state(prepared)
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    run_dir = next_run(runs_dir)
    run_dir.mkdir(mode=0o700)
    smm_before = area_digest(flash.read_bytes(), layout, firmware_layout.VARIABLE_STORE_AREA)
    tpm_before = tpm_digests(tpm_dir)
    serial = run_dir / "serial.log"
    machine = Machine(run_dir, prepared["qemu"], prepared["swtpm"], flash,
                      prepared["disk"], tpm_dir, serial, kvm=kvm,
                      rebootable=True)
    session_ran = False
    try:
        with machine:
            session_ran = True
            session = machine.session
            text = ""
            for cycle in range(resets + 1):
                print(f"  \u25b8 warm reset cycle {cycle}/{resets}", file=sys.stderr, flush=True)
                # The dev unit prints the terminal marker twice per boot.
                needed = 2 * (cycle + 1)
                text = session.wait_until(
                    lambda seen, needed=needed: seen.count(device.REQUIRED_MARKER) >= needed
                    or bool(device.DENIAL_MARKER.search(seen)))
                if device.DENIAL_MARKER.search(text):
                    raise SafetyError(f"Reboot cycle {cycle + 1} hit a verity denial")
                if text.count(device.REQUIRED_MARKER) < needed:
                    raise SafetyError(f"Reboot cycle {cycle + 1} did not reach the "
                                      f"verified sysroot marker (machine left early)")
                if cycle < resets:
                    session.reset()
            session.quit()
            text = serial.read_text(errors="replace")
        markers, denial = _assert_boot_markers(text, "Reboot session")
        boots_in_session = resets + 1
        if text.count(device.REQUIRED_MARKER) < 2 * boots_in_session \
                or text.count(device.TPM_TIS_MARKER) < boots_in_session:
            raise SafetyError("Reboot session lost full boot evidence across resets")
        record = {
            "op": "reboot", "run": int(run_dir.name), "kvm": kvm, "resets": resets,
            "boots_in_session": boots_in_session,
            "marker_prints": text.count(device.REQUIRED_MARKER),
            "tpm_tis_marker_prints": text.count(device.TPM_TIS_MARKER),
            "markers": markers, "denial": denial,
            "smmstore_sha256_before": smm_before,
            "tpm_sha256_before": tpm_before,
            "scope": _session_scope("Warm-reset loop in one powered session"),
        }
        _finish_session(prepared, run_dir, text, record, machine.session)
        if record["smmstore_sha256_after"] == prepared["pristine_store_sha256"]:
            raise SafetyError("Warm resets restored the variable store to the erased "
                              "pristine image (silent NVRAM reset)")
        if not record["tpm_sha256_after"]:
            raise SafetyError("Warm resets left no TPM state")
        write_json(run_dir / "run.json", record)
        profile["boots"] = profile.get("boots", 0) + 1
        profile["state_after_last_boot"] = {
            "smmstore_sha256": record["smmstore_sha256_after"],
            "tpm_sha256": record["tpm_sha256_after"],
            "data_sha256": record.get("data_sha256_after")}
        record_operation(profile, "reboot", run=int(run_dir.name), resets=resets)
        save_json(prepared["target"] / "profile.json", profile)
    except Exception as error:
        _record_failure(prepared, run_dir, "reboot", error, machine.session, session_ran)
        raise
    return {"passed": True, "name": name, "resets": resets,
            "boots_in_session": resets + 1, "identity": profile["state_after_last_boot"],
            "evidence": str(run_dir), "scope": record["scope"]}


def stop(root, name):
    print(f"\u25b8 device-stop '{name}': boot to marker, then QMP powerdown", file=sys.stderr, flush=True)
    """Boot to the verified marker, then stop the machine via QMP powerdown.

    The power-down request is the ACPI power button; whether the appliance
    honors it (exit well before the dev unit's own fallback poweroff) is
    recorded as evidence, not assumed.
    """
    prepared = _prepare(root, name)
    profile = prepared["profile"]
    runs_dir = prepared["runs_dir"]
    _assert_session_started_from_expected_state(prepared)
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    run_dir = next_run(runs_dir)
    run_dir.mkdir(mode=0o700)
    serial = run_dir / "serial.log"
    machine = Machine(run_dir, prepared["qemu"], prepared["swtpm"], prepared["flash"],
                      prepared["disk"], prepared["tpm_dir"], serial, kvm=kvm)
    session_ran = False
    try:
        with machine:
            session_ran = True
            machine.session.wait_until(lambda text: device.REQUIRED_MARKER in text
                                       or bool(device.DENIAL_MARKER.search(text)))
            requested = machine.session.alive()
            exit_seconds = None
            honored = None
            if requested:
                # Operator power-down request (ACPI power button). Whether the
                # appliance honors it is evidence, not an assumption: if the
                # machine ignores the button, the harness stops it itself.
                machine.session.powerdown()
                started = time.monotonic()
                deadline = started + STOP_POWERDOWN_WAIT
                while machine.session.alive() and time.monotonic() < deadline:
                    time.sleep(0.2)
                exit_seconds = round(time.monotonic() - started, 1)
                honored = not machine.session.alive()
            returncode = machine.session.quit()
            text = serial.read_text(errors="replace")
        if returncode != 0:
            raise SafetyError(f"Stopped machine left QEMU with rc={returncode}")
        markers, denial = _assert_boot_markers(text, "Stop session")
        record = {
            "op": "stop", "run": int(run_dir.name), "kvm": kvm,
            "powerdown_requested": requested, "exit_after_powerdown_seconds": exit_seconds,
            "acpi_powerdown_honored": honored,
            "markers": markers, "denial": denial,
            "smmstore_sha256_before": area_digest(
                prepared["flash"].read_bytes(), prepared["layout"],
                firmware_layout.VARIABLE_STORE_AREA),
            "tpm_sha256_before": tpm_digests(prepared["tpm_dir"]),
            "scope": _session_scope("Orderly power-down over the local QMP socket"),
        }
        _finish_session(prepared, run_dir, text, record, machine.session)
        write_json(run_dir / "run.json", record)
        profile["boots"] = profile.get("boots", 0) + 1
        profile["state_after_last_boot"] = {
            "smmstore_sha256": record["smmstore_sha256_after"],
            "tpm_sha256": record["tpm_sha256_after"],
            "data_sha256": record.get("data_sha256_after")}
        record_operation(profile, "stop", run=int(run_dir.name))
        save_json(prepared["target"] / "profile.json", profile)
    except Exception as error:
        _record_failure(prepared, run_dir, "stop", error, machine.session, session_ran)
        raise
    return {"passed": True, "name": name, "run": int(run_dir.name),
            "exit_after_powerdown_seconds": record["exit_after_powerdown_seconds"],
            "acpi_powerdown_honored": record["acpi_powerdown_honored"],
            "identity": profile["state_after_last_boot"], "evidence": str(run_dir),
            "scope": record["scope"]}


def powercut(root, name):
    print(f"\u25b8 device-powercut '{name}': verified boot, then hard kill", file=sys.stderr, flush=True)
    """Cut power mid-session: SIGKILL QEMU and swtpm after a verified boot.

    The cut is abrupt by design (no TPM2_Shutdown, no variable-store flush);
    the assertions afterwards are that nothing silently reset — the variable
    store must not have reverted to the pristine image and TPM state must
    still exist — and the next cold start must recover from whatever the cut
    left behind.
    """
    prepared = _prepare(root, name)
    profile = prepared["profile"]
    runs_dir = prepared["runs_dir"]
    _assert_session_started_from_expected_state(prepared)
    if not tpm_digests(prepared["tpm_dir"]):
        raise SafetyError("Power-cut needs a profile whose TPM state already exists")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    run_dir = next_run(runs_dir)
    run_dir.mkdir(mode=0o700)
    serial = run_dir / "serial.log"
    smm_before = area_digest(prepared["flash"].read_bytes(), prepared["layout"],
                             firmware_layout.VARIABLE_STORE_AREA)
    tpm_before = tpm_digests(prepared["tpm_dir"])
    try:
        machine = Machine(run_dir, prepared["qemu"], prepared["swtpm"], prepared["flash"],
                          prepared["disk"], prepared["tpm_dir"], serial, kvm=kvm)
        session_ran = False
        with machine:
            session_ran = True
            text = machine.session.wait_until(
                lambda seen: device.REQUIRED_MARKER in seen
                or bool(device.DENIAL_MARKER.search(seen)))
            if device.DENIAL_MARKER.search(text) or device.REQUIRED_MARKER not in text:
                raise SafetyError("Power cut requires a machine that booted to the "
                                  "verified marker first")
            # Let the machine settle into the fully booted OS, then cut power
            # from a running system (no TPM2_Shutdown, no variable flush).
            deadline = time.monotonic() + POWERCUT_SETTLE_SECONDS
            while machine.session.alive() and time.monotonic() < deadline:
                time.sleep(0.5)
            if not machine.session.alive():
                raise SafetyError("Machine left on its own before the power cut")
            machine.power_cut()
            returncode = machine.session.wait_exit(30)
            text = serial.read_text(errors="replace")
        if returncode != -9:
            raise SafetyError(f"Power cut did not kill QEMU abruptly (rc={returncode})")
        markers, denial = _assert_boot_markers(text, "Power-cut session")
        record = {
            "op": "powercut", "run": int(run_dir.name), "kvm": kvm,
            "qemu_killed": True, "swtpm_killed": True,
            "markers": markers, "denial": denial,
            "smmstore_sha256_before": smm_before, "tpm_sha256_before": tpm_before,
            "scope": _session_scope("Abrupt power loss after a verified boot"),
        }
        _finish_session(prepared, run_dir, text, record, machine.session)
        if record["smmstore_sha256_after"] == prepared["pristine_store_sha256"]:
            raise SafetyError("Power cut restored the variable store to the erased "
                              "pristine image (silent NVRAM reset)")
        if not record["tpm_sha256_after"]:
            raise SafetyError("Power cut wiped the TPM state directory")
        write_json(run_dir / "run.json", record)
        # The guest legitimately ran before the cut: whatever it flushed is the
        # new identity baseline; nothing here was reset by the harness.
        profile["boots"] = profile.get("boots", 0) + 1
        profile["state_after_last_boot"] = {
            "smmstore_sha256": record["smmstore_sha256_after"],
            "tpm_sha256": record["tpm_sha256_after"],
            "data_sha256": record.get("data_sha256_after")}
        record_operation(profile, "powercut", run=int(run_dir.name))
        save_json(prepared["target"] / "profile.json", profile)
    except Exception as error:
        _record_failure(prepared, run_dir, "powercut", error, machine.session, session_ran)
        raise
    return {"passed": True, "name": name, "run": int(run_dir.name),
            "identity": profile["state_after_last_boot"], "evidence": str(run_dir),
            "scope": record["scope"]}


def snapshot(root, name, label):
    print(f"\u25b8 device-snapshot '{name}' -> '{label}'", file=sys.stderr, flush=True)
    """Explicitly copy the whole persistent device state into a named snapshot."""
    validate_name(label)
    target, profile = load(root, name)
    snapshots = target / "snapshots"
    snap = snapshots / label
    if snap.exists():
        raise SafetyError(f"Snapshot {label!r} already exists for device {name!r}; "
                          "snapshots are immutable once written")
    snapshots.mkdir(mode=0o700)
    snap.mkdir(mode=0o700)
    (snap / "tpm").mkdir(mode=0o700)
    files = {"disk.raw": sha256(regular_file(target, "disk.raw")),
             "flash.rom": sha256(regular_file(target, "flash.rom"))}
    shutil.copyfile(target / "disk.raw", snap / "disk.raw")
    shutil.copyfile(target / "flash.rom", snap / "flash.rom")
    for item in sorted((target / "tpm").iterdir()):
        if item.is_file():
            shutil.copyfile(item, snap / "tpm" / item.name)
            files["tpm/" + item.name] = sha256(item)
    manifest = {
        "schema": 1, "label": label, "name": name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "boots": profile.get("boots", 0),
        "state_after_last_boot": profile.get("state_after_last_boot", {}),
        "files": files,
        "scope": "Isolated snapshot of persistent device state; restore is a "
                 "separate explicit operation and never happens implicitly",
    }
    write_json(snap / "manifest.json", manifest)
    profile.setdefault("snapshots", {})[label] = {
        "created_utc": manifest["created_utc"], "files": files}
    record_operation(profile, "snapshot", label=label)
    save_json(target / "profile.json", profile)
    return {"passed": True, "name": name, "label": label, "files": files,
            "evidence": str(snap), "scope": manifest["scope"]}


def restore(root, name, label):
    print(f"\u25b8 device-restore '{name}' <- '{label}'", file=sys.stderr, flush=True)
    """Explicitly restore persistent device state from a named snapshot.

    This is the only state-restoration path, and it is always operator
    command: ordinary boots and failed sessions never roll a device back.
    """
    validate_name(label)
    target, profile = load(root, name)
    snap = target / "snapshots" / label
    if not snap.is_dir():
        raise SafetyError(f"No snapshot {label!r} for device {name!r}")
    manifest = read_json(regular_file(snap, "manifest.json"))
    if manifest.get("schema") != 1 or manifest.get("label") != label \
            or manifest.get("name") != name:
        raise SafetyError("Snapshot manifest does not match this device and label")
    for relative, digest in sorted(manifest.get("files", {}).items()):
        if sha256(regular_file(snap, relative)) != digest:
            raise SafetyError(f"Snapshot file {relative!r} no longer matches its "
                              "manifest; refusing to restore corrupted state")
    shutil.copyfile(snap / "disk.raw", target / "disk.raw")
    shutil.copyfile(snap / "flash.rom", target / "flash.rom")
    for item in list((target / "tpm").iterdir()):
        if item.is_file():
            item.unlink()
    for relative in sorted(manifest.get("files", {})):
        if relative.startswith("tpm/"):
            shutil.copyfile(snap / relative, target / "tpm" / relative.split("/", 1)[1])
    profile["boots"] = manifest.get("boots", 0)
    profile["state_after_last_boot"] = manifest.get("state_after_last_boot", {})
    record_operation(profile, "restore", label=label)
    save_json(target / "profile.json", profile)
    return {"passed": True, "name": name, "label": label,
            "restored_boots": profile["boots"],
            "identity": profile["state_after_last_boot"],
            "evidence": str(snap),
            "scope": "Persistent device state restored by explicit operator command"}
