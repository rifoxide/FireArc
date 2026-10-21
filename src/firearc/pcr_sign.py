"""PCR 11 policy signing for the slot-A UKI (PLAN Phase 5 item 5).

Constructs the PCR-carrying Unified Kernel Image: the same byte-stable UKI
the ``uki`` stage produces, rebuilt by the pinned ukify with two additional
sections — ``.pcrsig`` (signed TPM PCR policy authorizations) and
``.pcrpkey`` (the PCR-policy public key) — signed by the dedicated
PCR-policy key under ``secrets/pcr/`` (a distinct role from the db/sb
signer, per the plan). The signing container sees exactly that keypair,
read-only; no other secret ever enters it.

Why this binds the right thing (all verified against this platform's real
measurement behavior, not documentation):

* systemd-stub measures every UKI section into PCR 11 as two events — the
  section name including its NUL byte, then the section content at the PE
  VirtualSize — in its fixed section-table order; only ``.pcrsig`` is
  exempt (it signs the state it would perturb). ``.pcrpkey`` IS measured.
  The model in :func:`expected_pcr11` reproduces the platform's replayed
  event log byte-for-byte (validated against dev5 boot evidence, including
  the initrd's four legitimate trailing zero bytes and .sbat's NUL).
* The pinned systemd-measure 257.13 predicts the identical value from the
  same section files; the stage requires both computations to agree.
* ``pol`` in each .pcrsig entry is the TPM2 PolicyPCR digest over the
  expected PCR value — SHA-256 of (zero digest ‖ TPM2_CC_PolicyPCR ‖
  TPML_PCR_SELECTION ‖ SHA-256(expected value)) — recomputed here from the
  TPM2 specification serialization, independently of systemd.
* ``sig`` is an RSASSA-PKCS1-v1_5 SHA-256 signature over ``pol``,
  verified in-stage with the pinned openssl against the public key, and
  ``pkfp`` must equal the manifest's fingerprint of that key.

Phase policy: the authorization is for ``enter-initrd`` — the barrier
systemd-pcrphase-initrd.service measures early in the (systemd-based)
initrd through /dev/tpmrm0, before the verity gate runs and before any
future data unlock (items 8–10). That extend is invisible in the firmware
event log (it bypasses the TCG2 log), but it is in the TPM; the model
accounts for it, and the boot-time validation compares replay + phase
against the signed value. Later phases are deliberately NOT signed:
unlock must happen in the initrd, and authorizing later states would
weaken the policy.

Determinism: unlike the sbsign layer (which embeds a signing time), the
PKCS#1 v1.5 signature is deterministic, so the PCR-carrying UKI is
byte-reproducible and the stage enforces a byte-identical double build.

Honest scope: only the slot-A UKI exists (slot B arrives with the update
phase); the signatures are development credentials; the log-derived
validation is not a TPM quote (Phase 8); PCR 7 binding happens at
enrollment time (item 8), not here.
"""

from pathlib import Path
import base64
import hashlib
import json
import re
import shutil

from . import builder, device, pcr_keys
from . import uki as uki_module
from .integrity import (
    SafetyError, private_directory, read_json, regular_file, sha256, write_json,
)

# The unlock authorization phase (see module docstring). "enter-initrd" is
# measured by systemd-pcrphase-initrd.service before the verity gate.
PHASES = ("enter-initrd",)

# systemd's unified-section table order (src/fundamental/uki.h); the stub
# measures present sections in this order. .pcrsig is exempt from
# measurement; .pcrpkey is measured like any other section.
SECTION_ORDER = (".linux", ".osrel", ".cmdline", ".initrd", ".ucode",
                 ".splash", ".dtb", ".uname", ".sbat", ".pcrpkey",
                 ".profile", ".dtbauto", ".hwids")

# TPM2 constants for the PolicyPCR digest (TPM2 Part 1/2).
TPM2_CC_POLICY_PCR = 0x0000017F
TPM2_ALG_SHA256 = 0x000B
PCR_INDEX = 11
PCR_BANK = "sha256"

REBUILD_NAME = "rebuild.efi"


def extend(state, digest):
    """TPM PCR extend semantics for a SHA-256 bank."""
    return hashlib.sha256(state + digest).digest()


def phase_extends(pcr, phases):
    """Extend PCR state with each phase word (colon-splitting, no NUL)."""
    for phase in phases:
        for word in phase.split(":"):
            if word:
                pcr = extend(pcr, hashlib.sha256(word.encode()).digest())
    return pcr


def expected_pcr11(section_contents, phases=PHASES):
    """The PCR 11 value the platform will hold, from first principles.

    ``section_contents`` maps section name to the exact VirtualSize bytes.
    Per section: extend with SHA-256(name + NUL), then SHA-256(content);
    empty sections are skipped (the stub skips zero-size sections, and so
    does systemd-measure for empty files). Then the phase words extend.
    """
    unknown = set(section_contents) - set(SECTION_ORDER)
    if unknown:
        raise SafetyError(f"Sections outside the measurement model: {sorted(unknown)}")
    pcr = bytes(32)
    for name in SECTION_ORDER:
        content = section_contents.get(name)
        if not content:
            continue
        pcr = extend(pcr, hashlib.sha256(name.encode() + b"\0").digest())
        pcr = extend(pcr, hashlib.sha256(content).digest())
    return phase_extends(pcr, phases)


def policy_pcr_digest(pcr_value, pcr_index=PCR_INDEX):
    """TPM2 PolicyPCR policy digest over one expected SHA-256 PCR value.

    Per TPM2 Part 1 (policy sequencing) and the marshalled forms of
    TPM2_CC_PolicyPCR and TPML_PCR_SELECTION: start from the zero digest
    and extend with SHA-256(digest ‖ CC ‖ TPML_PCR_SELECTION ‖
    SHA-256(value)). Matches systemd's tpm2_calculate_policy_pcr and was
    validated against the pinned systemd-measure output.
    """
    if len(pcr_value) != 32:
        raise SafetyError("Expected a SHA-256-sized PCR value")
    pcr_hash = hashlib.sha256(pcr_value).digest()
    select = bytearray(3)
    select[pcr_index // 8] |= 1 << (pcr_index % 8)
    tpml = (1).to_bytes(4, "big") + TPM2_ALG_SHA256.to_bytes(2, "big") \
        + bytes([len(select)]) + bytes(select)
    cc = TPM2_CC_POLICY_PCR.to_bytes(4, "big")
    return hashlib.sha256(bytes(32) + cc + tpml + pcr_hash).digest()


def section_content(binary, sections, name):
    """The exact VirtualSize bytes of one section (what the stub measures)."""
    section = next((item for item in sections if item["name"] == name), None)
    if section is None:
        raise SafetyError(f"UKI lacks the {name} section")
    if section["virtual_size"] > section["bytes"]:
        raise SafetyError(f"Section {name} has VirtualSize beyond its raw data")
    return binary[section["offset"]:section["offset"] + section["virtual_size"]]


def verify_pcrsig(pcrsig_bytes, *, expected_value, pkfp, phases=PHASES):
    """Structurally and semantically validate the .pcrsig JSON.

    Fails closed unless the file is exactly one sha256-bank entry for
    PCR 11 whose policy digest covers ``expected_value`` and whose public
    key is the one the manifest fingerprint describes. The cryptographic
    signature check runs in-stage against the pinned openssl (see build).
    """
    try:
        document = json.loads(pcrsig_bytes.rstrip(b"\0"))
    except (ValueError, UnicodeDecodeError) as error:
        raise SafetyError(f".pcrsig is not JSON: {error}")
    if not isinstance(document, dict) or set(document) != {PCR_BANK}:
        raise SafetyError(".pcrsig must carry exactly the sha256 bank")
    entries = document[PCR_BANK]
    if not isinstance(entries, list) or len(entries) != 1:
        raise SafetyError(".pcrsig must carry exactly one policy entry "
                          "(one key, one phase set)")
    entry = entries[0]
    if not isinstance(entry, dict):
        raise SafetyError(".pcrsig entry is not an object")
    if entry.get("pcrs") != [PCR_INDEX]:
        raise SafetyError(f".pcrsig entry does not authorize PCR {PCR_INDEX}")
    if not re.fullmatch(r"[0-9a-f]{64}", entry.get("pkfp", "")):
        raise SafetyError(".pcrsig entry lacks a valid public-key fingerprint")
    if entry["pkfp"] != pkfp:
        raise SafetyError(".pcrsig is signed by a different key than the "
                          "PCR-policy manifest describes")
    try:
        pol = bytes.fromhex(entry.get("pol", ""))
    except ValueError as error:
        raise SafetyError(f".pcrsig policy digest is not hex: {error}")
    if len(pol) != 32:
        raise SafetyError(".pcrsig policy digest is not SHA-256-sized")
    if pol != policy_pcr_digest(bytes.fromhex(expected_value)):
        raise SafetyError(".pcrsig policy digest does not cover the "
                          "expected PCR 11 value for the signed phases")
    try:
        signature = base64.b64decode(entry.get("sig", ""), validate=True)
    except (ValueError, TypeError) as error:
        raise SafetyError(f".pcrsig signature is not valid base64: {error}")
    if not signature:
        raise SafetyError(".pcrsig signature is empty")
    return {"pkfp": entry["pkfp"], "pol": entry["pol"], "signature": signature}


def build(root, tools_label, uki_label, label):
    """Rebuild the UKI with signed PCR 11 policy sections; verify in-stage."""
    status, _ = pcr_keys.state(root)
    if status != "complete":
        raise SafetyError("Development PCR-policy key absent; run just pcr-keys first")
    manifest = read_json(regular_file(Path(root) / "secrets/pcr", "manifest.json"))
    pkfp = manifest.get("pkfp", "")
    if not re.fullmatch(r"[0-9a-f]{64}", pkfp):
        raise SafetyError("secrets/pcr/manifest.json lacks the public-key fingerprint")

    builder.verify_tools(root, tools_label)
    _, uki_output, uki_result = device._stage_outputs(root, uki_label, "uki")
    unsigned_uki = regular_file(uki_output, device.UKI_ARTIFACT)
    if not uki_result.get("byte_identical_rebuild") or not uki_result.get("sections_verified"):
        raise SafetyError("Expected a byte-stable, section-verified UKI as input")
    # The exact section inputs the uki stage receipt covers; the PCR rebuild
    # must consume precisely those bytes.
    inputs = {}
    for name in ("kernel", "initrd.img", "cmdline", "os-release", "linuxx64.efi.stub"):
        inputs[name] = regular_file(uki_output, name)
        if uki_result.get("artifacts", {}).get(name) != sha256(inputs[name]):
            raise SafetyError(f"The uki stage does not vouch for the {name} section input")
    release = builder.root_lock(root)["kernel_release"]

    tools_work = builder.parent(root) / builder.identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")

    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    staging = work / "payload"
    staging.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)

    # The isolated PCR-policy signing step: only pcr.key/pcr.pub enter the
    # container, read-only; nothing else under secrets/ is reachable.
    secrets = Path(root) / "secrets/pcr"
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={secrets / 'pcr.key'},dst=/keys/pcr.key,readonly",
        "--mount", f"type=bind,src={secrets / 'pcr.pub'},dst=/keys/pcr.pub,readonly",
        "--mount", f"type=bind,src={uki_output},dst=/inputs,readonly",
        "--mount", f"type=bind,src={staging},dst=/staging",
        image]
    try:
        arguments = ["ukify", "build", "--linux=/inputs/kernel",
                     "--initrd=/inputs/initrd.img", "--cmdline=@/inputs/cmdline",
                     "--os-release=@/inputs/os-release", "--uname=" + release,
                     "--stub=/inputs/linuxx64.efi.stub", "--efi-arch=x64",
                     "--pcr-banks=" + PCR_BANK,
                     "--pcr-private-key=/keys/pcr.key",
                     "--pcr-public-key=/keys/pcr.pub",
                     *(["--phases=" + ",".join(PHASES)] if PHASES else [])]
        version = builder.logged(work, "ukify-version", options + ["ukify", "--version"],
                                 timeout=120).strip().splitlines()[-1]
        builder.logged(work, "ukify-pcr-build", options + arguments
                       + ["--output=/staging/" + device.UKI_ARTIFACT], timeout=1800)
        builder.logged(work, "ukify-pcr-rebuild", options + arguments
                       + ["--output=/staging/" + REBUILD_NAME], timeout=1800)
        built = regular_file(staging, device.UKI_ARTIFACT)
        if sha256(built) != sha256(staging / REBUILD_NAME):
            raise SafetyError("PCR rebuild differs: the .pcrsig layer is not "
                              "byte-stable (deterministic signing expected)")
        builder.logged(work, "ukify-inspect", options + ["ukify", "inspect",
                       "/staging/" + device.UKI_ARTIFACT], timeout=300)
        (staging / REBUILD_NAME).unlink()

        binary = built.read_bytes()
        sections, timestamp = uki_module.pe_sections(binary)
        by_name = {section["name"]: section for section in sections}
        missing = [name for name in (*uki_module.REQUIRED_SECTIONS, ".pcrsig", ".pcrpkey")
                   if name not in by_name]
        if missing:
            raise SafetyError(f"PCR UKI lacks required sections: {missing}")

        # Content sections must equal the unsigned UKI's byte for byte: the
        # authorization must not drift from the artifact the uki stage froze.
        unsigned_binary = unsigned_uki.read_bytes()
        unsigned_sections, _ = uki_module.pe_sections(unsigned_binary)
        unsigned_by_name = {section["name"]: section for section in unsigned_sections}
        for name, section in by_name.items():
            if name in (".pcrsig", ".pcrpkey"):
                continue
            other = unsigned_by_name.get(name)
            if other is None or other["sha256"] != section["sha256"]:
                raise SafetyError(f"Section {name} differs from the unsigned UKI")

        public_key = (secrets / "pcr.pub").read_bytes()
        if section_content(binary, sections, ".pcrpkey") != public_key:
            raise SafetyError(".pcrpkey does not carry the PCR-policy public key")

        # Independent expected-value computation from first principles, over
        # the exact measured bytes (VirtualSize-exact, .pcrpkey included).
        # Only unified sections are measured; stub sections (.text/.data/…)
        # never enter PCR 11.
        contents = {name: section_content(binary, sections, name)
                    for name in by_name if name in SECTION_ORDER}
        expected = expected_pcr11(contents, PHASES).hex()
        authorization = verify_pcrsig(section_content(binary, sections, ".pcrsig"),
                                      expected_value=expected, pkfp=pkfp)

        # The pinned authoritative tool must independently agree on the
        # expected value (same inputs, its own model). .sbat and .pcrpkey
        # are the section-exact bytes, as ukify passed them.
        (staging / "uname.txt").write_text(release)
        shutil.copyfile(secrets / "pcr.pub", staging / "pcr.pub")
        (staging / "sbat.txt").write_bytes(section_content(binary, sections, ".sbat"))
        report = builder.logged(work, "systemd-measure-calculate", options + [
            "/usr/lib/systemd/systemd-measure", "--bank=" + PCR_BANK,
            "--linux=/inputs/kernel", "--initrd=/inputs/initrd.img",
            "--cmdline=/inputs/cmdline", "--osrel=/inputs/os-release",
            "--uname=/staging/uname.txt", "--sbat=/staging/sbat.txt",
            "--pcrpkey=/staging/pcr.pub",
            *[f"--phase={phase}" for phase in PHASES],
            "--json=short", "calculate"], timeout=300)
        tool_value = ""
        for entry in json.loads(report).get(PCR_BANK, []):
            if entry.get("phase") in PHASES or entry.get("phase") == ":".join(PHASES):
                tool_value = entry.get("hash", "")
        if not re.fullmatch(r"[0-9a-f]{64}", tool_value) or tool_value != expected:
            raise SafetyError("systemd-measure prediction disagrees with the "
                              "platform-derived expected PCR 11 value")

        # Cryptographic verification of the policy signature with the pinned
        # openssl, inside the same container image the signing ran in.
        (staging / "pol.bin").write_bytes(bytes.fromhex(authorization["pol"]))
        (staging / "sig.bin").write_bytes(authorization["signature"])
        builder.logged(work, "openssl-verify-pcrsig", options + [
            "openssl", "dgst", "-" + PCR_BANK, "-verify", "/keys/pcr.pub",
            "-signature", "/staging/sig.bin", "/staging/pol.bin"], timeout=120)
        for name in ("pol.bin", "sig.bin", "uname.txt", "sbat.txt", "pcr.pub"):
            (staging / name).unlink()

        uki = output / device.UKI_ARTIFACT
        shutil.move(str(built), str(uki))
        write_json(work / "pcr.json", {
            "schema": 1, "uki": device.UKI_ARTIFACT, "slot": "A",
            "phases": list(PHASES), "pcr": PCR_INDEX, "bank": PCR_BANK,
            "expected_pcr11": expected,
            "policy_digest": authorization["pol"],
            "public_key_fingerprint": pkfp,
            "measurement_model": "per section: SHA-256(name+NUL) then "
                                 "SHA-256(VirtualSize content), systemd "
                                 "section-table order, .pcrsig exempt, "
                                 ".pcrpkey measured; then phase word extends",
            "sections": sections, "pe_timestamp": f"{timestamp:#x}",
            "ukify": version, "tools_image": image,
            "inputs": {"uki_label": uki_label,
                       "unsigned_sha256": sha256(unsigned_uki),
                       **{name: sha256(path) for name, path in inputs.items()}},
            "byte_identical_rebuild": True,
            "custody": "Development PCR-policy key (secrets/pcr); only "
                       "pcr.key/pcr.pub entered the signing container, "
                       "read-only; distinct role from the db/sb signer",
            "scope": "Development PCR policy; unlock enrollment (item 8) and "
                     "TPM attestation (Phase 8) are not claimed here"})
        write_json(work / "result.json", {
            "passed": True,
            "artifacts": {device.UKI_ARTIFACT: sha256(uki)},
            "byte_identical_rebuild": True, "sections_verified": True,
            "pcr_signed": True, "pcrsig_verified": True,
            "phases": list(PHASES), "expected_pcr11": expected,
            "public_key_fingerprint": pkfp,
            "boot_chain_qualified": False,
            "scope": "PCR-policy-carrying UKI; Secure Boot signature and "
                     "enforcement come from the sign/enroll stages"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Signed PCR 11 authorizations embedded in the slot-A UKI"}
