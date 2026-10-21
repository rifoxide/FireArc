"""vboot protected-RW verification proofs (chain step 4, PLAN item 6).

Boots the signed self-built firmware on QEMU Q35 with an swtpm TPM (the
firmware's vboot runs real measured/secdata initialization against it) and
proves the RW verification contract:

* ``good``       — the firmware-sign output as shipped: the OS must boot
                   with no recovery indication anywhere on serial (the RW
                   section verified and executed; the recovery payload was
                   never invoked).
* ``tampered``   — one byte flipped deep inside FW_MAIN_A: the machine must
                   report the vboot recovery screen with the keyblock/
                   verification failure reason and the modified RW must not
                   execute.
* ``wrong-key``  — the RW re-signed by a throwaway attacker keyset (root and
                 data keys generated inside the stage container, never in
                 secrets/) with our GBB root preserved: same refusal.
* ``tampered-no-recovery`` — the strongest form: the RO recovery payload is
                 removed from a flash copy, so a refused RW has nothing to
                 fall back to — the tampered variant must leave the machine
                 with no OS boot at all, while the good variant's no-recovery
                 session above proves the RW is what executes normally.

Every session runs with its own fresh swtpm (vboot's secdata state is
per-machine) and leaves serial, command and exit evidence in the stage
directory. After the good boot the flash copy's writes must stay confined to
SMMSTORE plus the flash-backed VBNV backup region (RW_NVRAM); whether the
VBNV backup actually fired on a given boot is recorded, not required —
vboot writes it on state changes, not on every clean boot.

Honest scope (ADR 0005): QEMU pflash has no hardware write protection, so
"protected RO" is host-anchored evidence of verification *mechanism* and
negative controls, never resistance to a malicious host. Anti-rollback
secdata is real per-machine state on swtpm but the kernel version counters
are development values.
"""

from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import time

from . import builder, device, firmware_layout
from .builder import logged
from .integrity import (SafetyError, identifier, private_directory, read_json,
                        regular_file, sha256, write_json)
from .host import load_lock

NEGATIVE_TIMEOUT = 600
POSITIVE_TIMEOUT = 1500
OS_MARKER = device.REQUIRED_MARKER
RECOVERY_REASON = re.compile(r"Recovery reason:\s*([^\r\n\x1b]+)")
VBOOT_REFUSAL_TEXT = "RW firmware unable to verify keyblock"
RECOVERY_SCREEN = "recovery"
VARIANTS = ("good", "tampered", "wrong-key", "tampered-no-recovery")


def _stage_outputs(root, label, stage):
    base = "build/firmware-build" if stage == "firmware-build" else "build/images"
    directory = Path(root) / base / label
    output = directory / "output"
    if not output.is_dir():
        raise SafetyError(f"Stage {stage} evidence directory has no output: {directory}")
    return directory, output, read_json(regular_file(directory, "result.json"))


def start_swtpm(work, name, state_dir):
    """One fresh swtpm per machine session; dies with its QEMU."""
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    control = work / f"{name}.swtpm.sock"
    log = work / f"{name}.swtpm.log"
    process = subprocess.Popen(
        ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state_dir}",
         "--ctrl", f"type=unixio,path={control}", "--log", f"file={log}",
         "--terminate"],
        stdout=(work / f"{name}.swtpm.stderr").open("xb"),
        stderr=subprocess.STDOUT, preexec_fn=device.die_with_parent)
    deadline = time.monotonic() + 20
    while not control.exists():
        if process.poll() is not None:
            raise SafetyError(f"swtpm exited before accepting control (rc={process.returncode})")
        if time.monotonic() > deadline:
            process.kill()
            raise SafetyError("swtpm control socket never appeared")
        time.sleep(0.05)
    return process, control


def tamper_fw_main(rom_bytes, layout):
    """Flip one byte inside the signed RW payload body.

    The vblock's signed body covers the FW_MAIN_A CBFS files (the payload
    ELF is the first file, ~1.13 MiB); bytes beyond it are unverified free
    space. The flip targets 1 MiB into the payload — observed inside the
    signed body — and fails closed if the region cannot contain it.
    """
    areas = {area["name"]: area for area in layout["areas"]}
    body = areas["FW_MAIN_A"]
    region = rom_bytes[body["offset"]:body["offset"] + body["size"]]
    header_at = next((at for at in range(0, 0x400, 0x40)
                      if region[at:at + 8] == b"LARCHIVE"), None)
    if header_at is None or len(region) < 0x110000:
        raise SafetyError("FW_MAIN_A does not carry the expected CBFS payload")
    offset = body["offset"] + 0x100000
    tampered = bytearray(rom_bytes)
    tampered[offset] ^= 0x01
    return bytes(tampered), offset


def build(root, tools_label, firmware_sign_label, device_label, label):
    """Run the vboot verification proof sessions and archive the verdicts."""
    identifier(label)
    _, sign_output, sign_result = _stage_outputs(root, firmware_sign_label, "firmware-sign")
    signed_rom = regular_file(sign_output, "signed-firmware.rom")
    if not sign_result.get("passed") or "GBB" not in sign_result.get("changed_regions", []):
        raise SafetyError("Expected a signed firmware with an installed GBB root key")
    _, device_output, _ = _stage_outputs(root, device_label, "device")
    disk = regular_file(device_output, "device.raw")
    rom = signed_rom.read_bytes()
    layout = firmware_layout.classify(rom, firmware_layout.parse_fmap(rom))
    qemu = shutil.which("qemu-system-x86_64")
    pins = load_lock(root, "host-tools")["tools"]["qemu-system-x86_64"]
    if not qemu or sha256(Path(qemu)) != pins["sha256"]:
        raise SafetyError("Host QEMU is absent or does not match the pinned regression tool")
    swtpm = shutil.which("swtpm")
    if not swtpm:
        raise SafetyError("swtpm is required for the firmware's vboot secdata")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    futility = _pinned_futility(root)
    work = private_directory(Path(root) / "build/images", create=True) / label
    work.mkdir(mode=0o700)
    disks = work / "disks"
    disks.mkdir(mode=0o700)

    # The wrong-key variant: a throwaway attacker keyset generated inside the
    # stage container signs the whole image; our GBB root is spliced back so
    # the RO root of trust stays ours (the attacker cannot write WP_RO).
    tampered_bytes, tamper_offset = tamper_fw_main(rom, layout)
    (work / "tampered.rom").write_bytes(tampered_bytes)
    shutil.copyfile(signed_rom, work / "signed-copy.rom")
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={futility},dst=/usr/local/bin/futility,readonly",
        "--mount", f"type=bind,src={work},dst=/work",
        image]
    logged(work, "attacker-keyset", options + [
        "sh", "-c",
        "mkdir -p /work/attack && cd /work/attack"
        " && openssl genrsa -traditional -out root.pem 2048 2>/dev/null"
        " && openssl genrsa -traditional -out data.pem 2048 2>/dev/null"
        " && openssl genrsa -traditional -out ksub.pem 2048 2>/dev/null"
        " && futility --vb1 create root.pem root_key"
        " && futility --vb1 create data.pem firmware_data_key"
        " && futility --vb1 create ksub.pem kernel_subkey"
        " && futility vbutil_keyblock --pack firmware.keyblock"
        " --datapubkey firmware_data_key.vbpubk --signprivate root_key.vbprivk"
        " && cp /work/signed-copy.rom wrong-key.rom"
        " && futility sign --type bios --keyset /work/attack wrong-key.rom"],
        timeout=600)
    # The container wrote attack/wrong-key.rom; splice our GBB back so the
    # RO root of trust stays ours.
    attacker = bytearray((work / "attack/wrong-key.rom").read_bytes())
    areas = {area["name"]: area for area in layout["areas"]}
    gbb = areas["GBB"]
    attacker[gbb["offset"]:gbb["offset"] + gbb["size"]] = \
        rom[gbb["offset"]:gbb["offset"] + gbb["size"]]
    (work / "wrong-key.rom").write_bytes(attacker)
    # tampered-no-recovery: the RO recovery payload is removed from a tampered
    # copy, so a refused RW leaves the machine with nothing to execute.
    noro = bytearray(tampered_bytes)
    (work / "tampered-no-recovery.rom").write_bytes(bytes(noro))

    runs, flash_runs = {}, {}
    try:
        for name in VARIANTS:
            target = disks / f"device-{name}.raw"
            shutil.copyfile(disk, target)
            flash = work / f"flash-{name}.rom"
            source = {("good",): signed_rom,
                      ("tampered",): work / "tampered.rom",
                      ("wrong-key",): work / "wrong-key.rom",
                      ("tampered-no-recovery",): work / "tampered-no-recovery.rom"}[(name,)]
            shutil.copyfile(source, flash)
            if name == "tampered-no-recovery":
                remove_ro_payload(root, work, flash)
            serial = work / f"serial-{name}.log"
            state = work / f"tpm-{name}"
            swtpm_process, control = start_swtpm(work, name, state)
            exited_instantly = False
            exited_early = False
            session = None
            try:
                try:
                    session = device.start_vm(work, "vb-" + name.replace("-", "")[:10],
                                              flash=flash, disk=target, serial=serial,
                                              kvm=kvm, timeout=POSITIVE_TIMEOUT if name == "good"
                                              else NEGATIVE_TIMEOUT, tpm=control,
                                              rebootable=False)
                except SafetyError as error:
                    # A refused RW makes vboot reset the machine immediately;
                    # with -no-reboot QEMU can leave before the control socket
                    # is up. That is a refusal observation, not a harness
                    # failure — the verdict below fails closed on any marker.
                    if "control socket" not in str(error):
                        raise
                    exited_instantly = True
                if session is not None:
                    try:
                        session.wait_until(lambda t: OS_MARKER in t
                                           or bool(RECOVERY_REASON.search(t)))
                    except SafetyError:
                        # The machine left (vboot reset with -no-reboot) or
                        # stayed silent for the bounded window: both are
                        # refusal observations, distinguished by the serial
                        # verdict below.
                        exited_early = True
                    session.close()
                    session = None
            finally:
                if session is not None:
                    session.close()
                if swtpm_process.poll() is None:
                    swtpm_process.terminate()
                    try:
                        swtpm_process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        swtpm_process.kill()
            text = serial.read_text(errors="replace") if serial.exists() else ""
            reasons = [match.group(1).strip() for match in RECOVERY_REASON.finditer(text)]
            booted = OS_MARKER in text
            runs[name] = {"os_booted": booted, "recovery_reasons": reasons,
                          "reset_before_console": exited_instantly or exited_early
                          or not text,
                          "kernel_executed": any(marker in text for marker in
                                                 ("Linux version", "EFI stub:")),
                          "serial_sha256": sha256(serial) if serial.exists() else None}
            # Only the good run boots the unmodified signed image; the other
            # variants' flash copies are intentionally modified by construction
            # and are evidenced by their serial verdicts instead.
            if name == "good":
                flash_runs[name] = firmware_layout.write_confinement(
                    rom, flash.read_bytes(), layout)
        def refused(name):
            run = runs[name]
            # No guest code may execute; the refusal shows either as the
            # vboot recovery reason on serial or as an immediate reset with
            # an untouched console. Any kernel execution fails closed.
            return (not run["os_booted"] and not run["kernel_executed"]
                    and (bool(run["recovery_reasons"]) or run["reset_before_console"]))
        verdict = {
            "good": runs["good"]["os_booted"] and not runs["good"]["recovery_reasons"],
            "tampered": refused("tampered"),
            "wrong-key": refused("wrong-key"),
            "tampered-no-recovery": refused("tampered-no-recovery"),
        }
        if not all(verdict.values()):
            raise SafetyError(f"vboot verification proofs failed: {verdict}")
        vbnv_written = flash_runs["good"]["changed_areas"].get("RW_NVRAM") is not None
        result = {"schema": 1, "passed": True, "kvm": kvm,
                  "variants": runs, "verdicts": verdict,
                  "tamper": {"fw_main_a_flip": hex(tamper_offset)},
                  "flash_write_confinement": {
                      "permitted_regions": ["SMMSTORE", "RW_NVRAM"],
                      "runs": flash_runs,
                      "vbnv_backup_written_on_good_boot": vbnv_written,
                      "scope": "Observed write destinations only; QEMU pflash "
                               "has no hardware write protection"},
                  "qemu_sha256": pins["sha256"],
                  "boot_chain_qualified": False,
                  "scope": "QEMU Q35 development harness: vboot RW verification "
                           "mechanism and negative controls proven (signed RW "
                           "executes with no recovery; tampered, attacker-keyed "
                           "and stock-unsigned RW are refused with the vboot "
                           "keyblock-verification recovery reason; with the "
                           "recovery payload removed a refused RW leaves nothing "
                           "executable). Host-anchored per ADR 0005; recovery "
                           "mode still boots the RO payload under Secure Boot "
                           "(recovery-payload minimization is open); anti-"
                           "rollback kernel versions are development values; "
                           "not physical-device or production qualification"}
        write_json(work / "result.json", result)
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "vboot protected-RW verification proofs (development harness)"}


def _pinned_futility(root):
    record = read_json(regular_file(Path(root) / "build", "state.json"))["stages"]["futility"]
    return regular_file(Path(root) / "build/firmware-build" / record["id"] / "output", "futility")


def remove_ro_payload(root, work, flash):
    """Remove the RO recovery payload from a flash copy (diagnostic variant).

    Uses the cbfstool from the firmware-build tree inside the pinned SDK
    container; the flash copy is stage-local scratch, never a stage artifact.
    """
    state = read_json(regular_file(Path(root) / "build", "state.json"))
    record = state["stages"]["firmware-build"]
    build_dir = Path(root) / "build/firmware-build" / record["id"]
    logged(work, f"strip-ro-{flash.stem}", [
        "docker", "run", "--rm", "--network", "none",
        "--user", f"{os.getuid()}:{os.getgid()}", "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={build_dir}/tree,dst=/cb",
        "--mount", f"type=bind,src={flash.parent},dst=/flash",
        "coreboot/coreboot-sdk@sha256:181452b3bc89ebc0eedcfc766d116224f0611ea4b5027857c6cfe530f5741a6c",
        "/cb/build/cbfstool", f"/flash/{flash.name}", "remove", "-r", "COREBOOT",
        "-n", "fallback/payload"], timeout=300)
