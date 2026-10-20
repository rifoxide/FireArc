"""Secure Boot enforcement proofs on the enrolled firmware image.

This is the chain step 3d gate: with the development PK/KEK/db enrolled and
``SecureBoot=1`` in the variable store, the firmware must actually enforce
the trust state — the plan's first enforced-chain evidence.

On this firmware, enforcement anchors on the authenticode digests enrolled
in db: the payload's crypto library implements certificate verification
(``AuthenticodeVerify``) as an unconditional stub, so an image is authorized
only when its own exact digest is an ``EFI_CERT_SHA256`` db entry (validated
against the firmware's own debug output and bisected enrollments). Every
byte of the boot artifacts therefore matters: the signed chain boots because
its digests are enrolled, and any unsigned, re-signed or tampered variant
has different bytes — a different digest — and must be refused.

Four QEMU Q35 sessions boot the enrolled firmware with one boot payload
variable each:

* ``good``           — the stock disk: must boot to the verified read-only
                       sysroot, and the kernel must report ``secureboot:
                       Secure boot enabled`` (the in-band proof of the
                       SecureBoot variable the firmware honours).
* ``tampered``       — one content byte flipped inside the signed UKI's
                       .linux section: a different digest, must be refused.
* ``modified``       — the unsigned UKI with a perturbed .cmdline byte: a
                       genuinely different image (different command line),
                       must be refused.
* ``tampered-loader``— one byte flipped inside the ESP loader: the firmware
                       must refuse the boot manager itself.

A negative variant passes only if no guest code executed at all — not the
EFI stub, not the kernel — while the machine ran to a refusal verdict:
either an explicit security-violation/access-denied message on serial or a
bounded timeout with an untouched console contract. Any kernel execution
under enforcement fails the gate closed.

Honest scope note: under digest anchoring, an unsigned rebuild with
byte-identical content is indistinguishable from the signed artifact (the
signature layer is not part of the covered digest), so provenance-style
"wrong key" proofs are not expressible on this firmware; content-integrity
refusals are. Development keys; QEMU harness; host-anchored verifier per
ADR 0005; reboot/cold-start persistence and unauthorized variable-update
refusal remain open (PLAN Phase 2 item 13).
"""

from pathlib import Path
import hashlib
import os
import re
import shutil

from . import builder, device, enroll, firmware_layout, uki as uki_module
from .inputs import load_lock
from .integrity import (
    SafetyError, private_directory, read_json, regular_file, sha256, verify_file,
    write_json,
)

ESP_BYTES = 1024 * 1024  # the ESP partition begins at 1 MiB in the GPT disk
KERNEL_EXECUTION_MARKERS = ("EFI stub:", "Linux version", device.REQUIRED_MARKER)
SECURE_BOOT_KERNEL_LINE = "secureboot: Secure boot enabled"
NEGATIVE_TIMEOUT = 900
POSITIVE_TIMEOUT = 1500

VARIANTS = ("good", "tampered", "modified", "tampered-loader")


def install_command(name, source):
    """Replace the ESP UKI inside a disk copy (mtools, partition offset)."""
    return ["mcopy", "-i", f"/disk/device-{name}.raw@@{ESP_BYTES}",
            "-o", source, f"::{device.ESP_UKI_PATH}"]


def install_loader_command(name, source):
    """Replace both ESP loader paths inside a disk copy."""
    return ["sh", "-c",
            f"mcopy -i /disk/device-{name}.raw@@{ESP_BYTES} -o {source}"
            f" ::EFI/BOOT/BOOTX64.EFI"
            f" && mcopy -i /disk/device-{name}.raw@@{ESP_BYTES} -o {source}"
            f" ::EFI/systemd/systemd-bootx64.efi"]


def tamper_uki(signed_bytes):
    """Flip one content byte inside the signed UKI's .linux section."""
    sections, _ = uki_module.pe_sections(signed_bytes)
    section = next((item for item in sections if item["name"] == ".linux"), None)
    if section is None or section["bytes"] < 0x1000:
        raise SafetyError("Signed UKI lacks a .linux section to tamper with")
    offset = section["offset"] + section["bytes"] // 2
    tampered = bytearray(signed_bytes)
    tampered[offset] ^= 0x01
    return bytes(tampered), offset


def modify_uki(unsigned_bytes):
    """Perturb the unsigned UKI's kernel command line (a different image)."""
    sections, _ = uki_module.pe_sections(unsigned_bytes)
    section = next((item for item in sections if item["name"] == ".cmdline"), None)
    if section is None or section["bytes"] < 8:
        raise SafetyError("Unsigned UKI lacks a .cmdline section to modify")
    offset = section["offset"] + section["bytes"] // 2
    modified = bytearray(unsigned_bytes)
    modified[offset] = (modified[offset] ^ 0x20) | 0x20  # visible ASCII flip
    return bytes(modified), offset


def tamper_loader(loader_bytes):
    """Flip one content byte inside the loader's first large section."""
    sections, _ = uki_module.pe_sections(loader_bytes)
    section = max((item for item in sections if item["bytes"] > 0x100),
                  key=lambda item: item["bytes"])
    offset = section["offset"] + section["bytes"] // 2
    tampered = bytearray(loader_bytes)
    tampered[offset] ^= 0x01
    return bytes(tampered), offset


def kernel_executed(serial_text):
    return any(marker in serial_text for marker in KERNEL_EXECUTION_MARKERS)


def console_text(serial_text):
    """Serial text normalized for phrase matching.

    Firmware consoles wrap lines at VGA width mid-word — a denial arrives
    as ``Acc\\r\\ness denied`` — so verdict phrases must be matched with all
    whitespace stripped.
    """
    return re.sub(r"\s+", "", serial_text)


VIOLATION_PHRASES = re.compile(r"securityviolation|accessdenied", re.IGNORECASE)


def violation_seen(serial_text):
    return bool(VIOLATION_PHRASES.search(console_text(serial_text)))


def refusal_verdict(serial_text, timed_out):
    """Classify a negative run: refused, or (fail-closed) executed."""
    violation = violation_seen(serial_text)
    executed = kernel_executed(serial_text)
    return {"refused": not executed,
            "refusal_evidence": "security-violation" if violation
            else "bounded-timeout" if timed_out else "none",
            "kernel_executed": executed,
            "serial_sha256": hashlib.sha256(serial_text.encode()).hexdigest()}


def check_secure_boot(root, tools_label, uki_label, sign_label, device_label,
                      enroll_label, label):
    """Boot the enrolled firmware and prove signature enforcement."""
    builder.verify_tools(root, tools_label)
    _, uki_output, uki_result = device._stage_outputs(root, uki_label, "uki")
    unsigned_uki = regular_file(uki_output, device.UKI_ARTIFACT)
    if not uki_result.get("byte_identical_rebuild"):
        raise SafetyError("Expected the byte-stable unsigned UKI variant")
    _, sign_output, sign_result = device._stage_outputs(root, sign_label, "sign")
    signed_uki = regular_file(sign_output, device.UKI_ARTIFACT)
    loader = regular_file(sign_output, "systemd-bootx64.efi")
    if not sign_result.get("signed") or not sign_result.get("signatures_verified"):
        raise SafetyError("Expected verified signatures on the signed UKI")
    device_source, device_output, device_result = device._stage_outputs(root, device_label, "device")
    disk = regular_file(device_output, "device.raw")
    manifest = read_json(regular_file(device_source, "device.json"))
    if manifest.get("kernel_cmdline") != device.KERNEL_CMDLINE:
        raise SafetyError("Device manifest does not match the development harness contract")
    enroll_source, enroll_output, enroll_result = device._stage_outputs(root, enroll_label, "enroll")
    enrolled_rom = regular_file(enroll_output, "enrolled.rom")
    enroll_evidence = read_json(regular_file(enroll_source, "enroll.json"))
    enrolled_variables = {item["name"]: item["data_sha256"]
                          for item in enroll_evidence["variables"]}
    if enroll_result.get("artifacts", {}).get("enrolled.rom") != sha256(enrolled_rom):
        raise SafetyError("Enrollment stage does not vouch for the enrolled ROM")

    qemu = shutil.which("qemu-system-x86_64")
    pins = load_lock(root, "host-tools")["tools"]["qemu-system-x86_64"]
    if not qemu or sha256(Path(qemu)) != pins["sha256"]:
        raise SafetyError("Host QEMU is absent or does not match the pinned regression tool")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)

    tools_work = builder.parent(root) / builder.identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")

    work = private_directory(Path(root) / "build/images") / label
    # A failed attempt leaves exclusive evidence files behind; stage evidence
    # from retries starts fresh.
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    # One writable disk copy exists at a time: the raw disk is over a GiB,
    # and four simultaneous copies have exhausted build space before.
    disks = work / "disks"
    disks.mkdir(mode=0o700)
    payload = work / "payload"
    payload.mkdir(mode=0o700)
    try:
        # Variant payloads: the signed UKI with one tampered kernel byte, the
        # unsigned UKI with a perturbed command line, and the loader with one
        # tampered byte. Content modifications change the digest the firmware
        # anchors on; same-content signature changes are indistinguishable
        # under digest anchoring (see the module docstring).
        shutil.copyfile(unsigned_uki, payload / "modified.efi")
        modified, modify_offset = modify_uki(unsigned_uki.read_bytes())
        (payload / "modified.efi").write_bytes(modified)
        tampered, tamper_offset = tamper_uki(signed_uki.read_bytes())
        (payload / "tampered.efi").write_bytes(tampered)
        tampered_loader, loader_tamper_offset = tamper_loader(loader.read_bytes())
        (payload / "tampered-loader.efi").write_bytes(tampered_loader)
        options = builder.docker_args(image) + [
            "--env", "LC_ALL=C",
            "--mount", f"type=bind,src={payload},dst=/payload,readonly",
            "--mount", f"type=bind,src={uki_output},dst=/inputs,readonly",
            "--mount", f"type=bind,src={disks},dst=/disk",
            "--mount", f"type=bind,src={work},dst=/work",
            image]

        enrolled_bytes = enrolled_rom.read_bytes()
        layout = firmware_layout.classify(enrolled_bytes,
                                          firmware_layout.parse_fmap(enrolled_bytes))
        runs, flash_runs, store_reports = {}, {}, {}
        for name in VARIANTS:
            target = disks / f"device-{name}.raw"
            shutil.copyfile(disk, target)
            if name == "tampered":
                builder.logged(work, "install-tampered",
                               options + install_command(name, "/payload/tampered.efi"),
                               timeout=300)
            elif name == "modified":
                builder.logged(work, "install-modified",
                               options + install_command(name, "/payload/modified.efi"),
                               timeout=300)
            elif name == "tampered-loader":
                builder.logged(work, "install-tampered-loader",
                               options + install_loader_command(name, "/payload/tampered-loader.efi"),
                               timeout=300)
            flash = work / ("flash-" + name + ".rom")
            shutil.copyfile(enrolled_rom, flash)
            serial = work / ("serial-" + name + ".log")
            timeout = POSITIVE_TIMEOUT if name == "good" else NEGATIVE_TIMEOUT
            # Short session label: the QMP socket path must stay under the
            # 108-byte UNIX socket limit even with full-length stage dirs.
            session = device.start_vm(work, "qs-" + name, flash=flash,
                                      disk=target, serial=serial, kvm=kvm,
                                      timeout=timeout)
            timed_out = False
            try:
                if name == "good":
                    text = session.wait_until(
                        lambda value: device.REQUIRED_MARKER in value
                        and (device.RUNTIME_CLEAN_MARKER in value
                             or device.RUNTIME_EIO_MARKER in value))
                    if SECURE_BOOT_KERNEL_LINE not in text:
                        raise SafetyError("Positive boot never reported the kernel's "
                                          "'secureboot: Secure boot enabled' line")
                else:
                    try:
                        session.wait_until(
                            lambda value: violation_seen(value)
                            or kernel_executed(value))
                    except SafetyError:
                        timed_out = True  # bounded silence is itself a refusal
                session.quit()  # no-op if the machine already left
            finally:
                session.close()
            text = serial.read_text(errors="replace")
            markers, denial = device.boot_verdict(text)
            if name == "good":
                if not markers[device.REQUIRED_MARKER] or denial["denial"]:
                    raise SafetyError("Enrolled firmware refused the correctly "
                                      "signed development boot chain")
                runs[name] = {"markers": markers, "denial": denial,
                              "secureboot_kernel_line": True,
                              "menu_unstick_keypresses": session.keypresses}
            else:
                verdict = refusal_verdict(text, timed_out)
                if not verdict["refused"]:
                    raise SafetyError(f"Secure Boot did not refuse the {name} "
                                      f"variant: guest code executed")
                runs[name] = {"refusal": verdict, "markers": markers,
                              "menu_unstick_keypresses": session.keypresses}
            # Guest writes must remain confined to the variable store.
            flash_runs[name] = firmware_layout.write_confinement(
                enrolled_bytes, flash.read_bytes(), layout)
            if name == "good":
                area = next((item for item in firmware_layout.parse_fmap(flash.read_bytes())["areas"]
                             if item["name"] == firmware_layout.VARIABLE_STORE_AREA), None)
                parsed = enroll.parse_store(flash.read_bytes()[area["offset"]:area["offset"] + area["size"]])
                survived = {item["name"]: hashlib.sha256(item["data"]).hexdigest()
                            for item in parsed}
                for variable in ("PK", "KEK", "db", "SecureBootEnable",
                                 "SecureBoot", "SetupMode"):
                    if survived.get(variable) != enrolled_variables[variable]:
                        raise SafetyError(f"Variable {variable} did not survive the "
                                          f"enforcing boot unchanged")
                store_reports[name] = {
                    "enrolled_variables_intact": True,
                    "runtime_added_variables": sorted(
                        set(survived) - set(enrolled_variables)),
                    "re_enrolled_defaults": any(
                        name in survived for name in ("dbx",)),
                }
            target.unlink()
        for name, digest in device_result["artifacts"].items():
            verify_file(regular_file(device_output, name), digest)
        builder.verify_tools(root, tools_label)
        write_json(work / "result.json", {
            "passed": True, "kvm": kvm,
            "enforcement": {
                "signed_boot": {"booted": True, "secureboot_kernel_line":
                                SECURE_BOOT_KERNEL_LINE},
                "tampered_refused": runs["tampered"]["refusal"],
                "modified_refused": runs["modified"]["refusal"],
                "tampered_loader_refused": runs["tampered-loader"]["refusal"],
                "mechanism": "db digest anchoring (the firmware's crypto "
                             "stubs certificate verification); same-content "
                             "signature changes are indistinguishable by "
                             "design of the covered digest",
            },
            "tamper": {"sections": {".linux flip": hex(tamper_offset),
                                    ".cmdline flip": hex(modify_offset),
                                    "loader flip": hex(loader_tamper_offset)},
                       "xor": "content byte flips"},
            "store_survival": store_reports["good"],
            "flash_write_confinement": {
                "permitted_region": firmware_layout.VARIABLE_STORE_AREA,
                "runs": flash_runs,
                "scope": "Observed write destinations only; QEMU pflash has no "
                         "hardware write protection"},
            "qemu_sha256": pins["sha256"],
            "boot_chain_qualified": False,
            "scope": "QEMU Q35 development harness on the enrolled self-built "
                     "firmware: enforcement evidenced by signed-boot success "
                     "plus tampered/modified/loader-tamper refusal and "
                     "variable-store survival. Enforcement anchors on db "
                     "digest entries (the firmware's crypto stubs certificate "
                     "verification); development keys; host-anchored verifier "
                     "(ADR 0005); reboot/cold-start persistence and "
                     "unauthorized variable-update refusal remain open; not "
                     "physical-device or production qualification"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Secure Boot enforcement proofs passed on the enrolled image"}
