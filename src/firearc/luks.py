"""Per-device LUKS2 data volumes created only during explicit provisioning.

PLAN Phase 5 item 6: the factory image (the `device` stage disk) carries a
FIREARC_DATA partition that is deliberately **blank** — no populated LUKS
header, no shared header template, nothing to copy between devices. The
volume comes into existence exactly once, when `device-provision` creates a
persistent device profile: the pinned cryptsetup (2.7.5 from the locked
tools closure) formats the partition region with fresh random volume
material, and one separate high-entropy recovery credential (256 bits from
the host kernel CSPRNG) is enrolled as the sole keyslot. The credential
never appears in command lines, serial capture or stage logs — it travels
by file handle only (`--key-file`), lands under the profile's 0700
`secrets/` directory (0600) and is marked escrow-pending until Phase 5
item 7 moves it onto an approved custody path.

The inner ext4 filesystem is intentionally NOT created here: nothing in
the boot path unlocks the volume yet (that is items 8–10), so first-mount
formatting belongs to the unlock work. This keeps item 6 exactly scoped:
unique per-device volume material, a recovery credential, and the
factory-image blank rule enforced both in the `device` stage (assert on
the assembled disk) and here (assert on the profile copy before format).

Not production provisioning: dev-harness entropy (host kernel CSPRNG),
dev-harness sizing (256 MiB provisional, an H interface per PLAN §4.3)
and dev-harness custody (escrow pending).
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets as pysecrets

from . import builder, device
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file,
    write_json,
)

MIB = 1024 * 1024

# The data-partition geometry lives with the GPT table it belongs to
# (device.py owns the partition layout; this module consumes it).
DATA_MIB = device.DATA_MIB
DATA_BYTES = device.DATA_BYTES
DATA_OFFSET = device.DATA_OFFSET
# LUKS2 on-disk identity: magic "LUKS\xba\xbe" then u16 BE version 2.
LUKS2_MAGIC = b"LUKS\xba\xbe"
LUKS2_VERSION = 2
# The recovery credential: 256 bits from the host kernel CSPRNG, held as
# raw bytes (cryptsetup --key-file consumes the file verbatim).
RECOVERY_BYTES = 32
LUKS_LABEL = "FIREARC_DATA"
# One-shot enrollment transport (Phase 5 item 8): 32-byte magic block
# followed by the 32-byte recovery credential, padded to one sector.
ENROLL_MAGIC = b"FIREARC-ENROLL-KEY-V1\n"
ENROLL_DISK_BYTES = 512
# The systemd-tpm2 LUKS2 token fields the enrollment contract pins.
TOKEN_TYPE = "systemd-tpm2"
# cryptsetup 2.7.5 defaults kept deliberately: argon2id KDF, aes-xts-plain64,
# 16 MiB metadata area, 512-byte sectors. Evidence records the effective
# parameters from luksDump rather than pinning them in code.


def _zeros_digest(size):
    hasher = hashlib.sha256()
    block = b"\0" * MIB
    remaining = size
    while remaining:
        hasher.update(block[:min(remaining, len(block))])
        remaining -= MIB
    return hasher.hexdigest()


BLANK_SHA256 = _zeros_digest(DATA_BYTES)


def region_digest(path, offset=0, size=None):
    """sha256 over one byte region of a file (default: the data partition)."""
    if size is None:
        size = DATA_BYTES
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        handle.seek(offset)
        remaining = size
        while remaining:
            block = handle.read(min(remaining, MIB))
            if not block:
                raise SafetyError(f"Unexpected end of file reading region: {path}")
            hasher.update(block)
            remaining -= len(block)
    return hasher.hexdigest()


def assert_region_blank(path, what):
    """The factory-image rule: the data region must contain no LUKS header.

    Digests the whole region, not just the magic bytes: a stale or partial
    header template anywhere in the partition is a violation.
    """
    digest = region_digest(path, DATA_OFFSET)
    if digest != BLANK_SHA256:
        raise SafetyError(f"{what} carries non-blank FIREARC_DATA bytes "
                          f"(region digest {digest}); a populated shared "
                          f"LUKS header must never enter the factory image")
    return digest


# LUKS2 on-disk header layout (validated against real cryptsetup 2.7.5
# output): magic[6], u16 version, u64 hdr_size, then binary fields (crc,
# salt/label/uuid strings, KDF hashes) through 0xFFF; the JSON text area
# starts at 0x1000 and runs to hdr_size (16 KiB by default, covering the
# primary and secondary header copies; keyslots follow at 32 KiB).
HEADER_JSON_OFFSET = 0x1000
HEADER_READ_BYTES = MIB


def parse_header_json(blob):
    """Extract the primary header JSON per the LUKS2 on-disk layout."""
    if len(blob) < HEADER_JSON_OFFSET + 512:
        raise SafetyError("Formatted region too small for a LUKS2 header")
    if blob[:6] != LUKS2_MAGIC or int.from_bytes(blob[6:8], "big") != LUKS2_VERSION:
        raise SafetyError("Formatted region is not a LUKS2 volume")
    hdr_size = int.from_bytes(blob[8:16], "big")
    if not HEADER_JSON_OFFSET < hdr_size <= HEADER_READ_BYTES or hdr_size % 512:
        raise SafetyError(f"Implausible LUKS2 binary header size {hdr_size}")
    if len(blob) < hdr_size:
        raise SafetyError("Truncated LUKS2 header JSON area")
    try:
        header = json.loads(blob[HEADER_JSON_OFFSET:hdr_size].rstrip(b"\x00"))
    except ValueError as error:
        raise SafetyError(f"LUKS2 header JSON is not parseable: {error}")
    if not isinstance(header, dict):
        raise SafetyError("LUKS2 header JSON is not an object")
    return header


def assert_binary_identity(blob, *, uuid, label=LUKS_LABEL):
    """The binary header (everything before the JSON area) must carry the
    volume's uuid and label as ASCII strings. cryptsetup 2.7 keeps them in
    fixed struct fields; scanning keeps us robust to field placement while
    still requiring an exact match."""
    region = blob[:HEADER_JSON_OFFSET].decode("ascii", errors="ignore")
    if uuid.lower() not in region.lower():
        raise SafetyError("LUKS2 binary header does not carry the dumped uuid")
    if label not in region:
        raise SafetyError("LUKS2 binary header does not carry the volume label")


def validate_header(header, *, keyslots):
    """Fail-closed checks on the luksDump/header inventory we record."""
    segments = header.get("segments", {})
    if set(segments) != {"0"} or segments.get("0", {}).get("type") != "crypt":
        raise SafetyError("Expected exactly one crypt data segment")
    if set(header.get("keyslots", {})) != set(keyslots):
        raise SafetyError(f"LUKS2 keyslot inventory {sorted(header['keyslots'])} "
                          f"does not match the provisioning contract {sorted(keyslots)}")
    for slot, kdf in header.get("keyslots", {}).items():
        if kdf.get("type") != "luks2":
            raise SafetyError(f"Keyslot {slot} is not a LUKS2 keyslot")
    if header.get("tokens"):
        raise SafetyError(f"Unexpected tokens already enrolled: {sorted(header['tokens'])}")


def generate_recovery_credential():
    """256 bits from the host kernel CSPRNG (os.urandom)."""
    return pysecrets.token_bytes(RECOVERY_BYTES)


def write_secret(path, blob):
    """Create one 0600 file with an explicit mode (no umask games)."""
    if path.exists():
        raise SafetyError(f"Refusing to overwrite an existing secret: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, blob)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def build_enroll_disk(path, credential):
    """Write the one-shot enrollment transport: magic block + credential."""
    if len(credential) != RECOVERY_BYTES:
        raise SafetyError("Enrollment transport requires the exact credential size")
    blob = ENROLL_MAGIC + b"\0" * (32 - len(ENROLL_MAGIC)) + credential
    blob += b"\0" * (ENROLL_DISK_BYTES - len(blob))
    if len(blob) != ENROLL_DISK_BYTES:
        raise SafetyError("Enrollment transport has unexpected size")
    write_secret(path, blob)
    return blob


def validate_enrolled(header, *, expected_pem=None):
    """Fail-closed checks on an enrolled header (real systemd 257.13 token
    structure, pinned from the first live enrollment): keyslot 1 bound to
    exactly one systemd-tpm2 token, plain PolicyPCR on 7 (SHA-256 bank),
    signed policy on PCR 11 under the PCR-policy public key, whose base64
    PEM body must equal the UKI's .pcrpkey bytes."""
    import base64
    if set(header.get("keyslots", {})) != {"0", "1"}:
        raise SafetyError(f"Enrolled keyslot inventory {sorted(header.get('keyslots', {}))} "
                          "does not match the enrollment contract")
    tokens = header.get("tokens", {})
    if set(tokens) != {"0"} or tokens["0"].get("type") != TOKEN_TYPE:
        raise SafetyError("Expected exactly one systemd-tpm2 token")
    token = tokens["0"]
    if token.get("keyslots") != ["1"]:
        raise SafetyError("The TPM2 token does not bind keyslot 1")
    plain_pcrs = {str(value) for value in token.get("tpm2-pcrs", [])}
    if plain_pcrs != {"7"}:
        raise SafetyError(f"The token's plain PCR binding {sorted(plain_pcrs)} is not "
                          "the explicit PCR 7 binding")
    signed_pcrs = {str(value) for value in
                   (token.get("tpm2_pubkey_pcrs") or token.get("tpm2-public-key-pcrs") or [])}
    if signed_pcrs != {"11"}:
        raise SafetyError(f"The token's signed PCR set {sorted(signed_pcrs)} is not "
                          "the signed PCR 11 policy")
    if token.get("tpm2-pcr-bank") not in (None, "sha256"):
        raise SafetyError("The TPM2 token does not use the SHA-256 bank")
    pubkey = token.get("tpm2_pubkey") or ""
    if not pubkey:
        raise SafetyError("The TPM2 token lacks the signed-policy public key")
    try:
        decoded = base64.b64decode(pubkey, validate=True).decode()
    except (ValueError, TypeError) as error:
        raise SafetyError(f"The token's public key is not base64 PEM: {error}")
    if "BEGIN PUBLIC KEY" not in decoded:
        raise SafetyError("The token's public key is not a PEM public key")
    if expected_pem is not None and decoded.strip() != expected_pem.strip():
        raise SafetyError("The TPM2 token was enrolled under a different "
                          "PCR-policy public key than the UKI carries")
    return token


def expected_pcr_policy(root):
    """The PCR-policy public key (PEM text, fingerprint) this project signs
    with: the canonical public half under secrets/pcr (ADR 0009 custody).
    The UKI's .pcrpkey section carries exactly these bytes (the item-5
    stage asserts that), so the enrolled token must carry them too.
    """
    from . import pcr_keys
    status, directory = pcr_keys.state(root)
    if status != "complete":
        raise SafetyError("PCR-policy key absent; cannot validate TPM2 "
                          "enrollment against the signed policy (run just pcr-keys)")
    manifest = read_json(regular_file(directory, "manifest.json"))
    pem = regular_file(directory, "pcr.pub").read_text()
    if "BEGIN PUBLIC KEY" not in pem:
        raise SafetyError("PCR-policy public key is not a bare PEM public key")
    return pem, manifest.get("pkfp", "")


def format_arguments():
    """The exact cryptsetup luksFormat argv (paths only; never secret bytes)."""
    return [
        "cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
        # Single exclusive writer inside a private profile directory; the
        # read-only container root has no /run/cryptsetup lock directory.
        "--disable-locks",
        "--label", LUKS_LABEL, "--key-slot", "0",
        "--key-file", "/workspace/recovery.key",
        "/workspace/data.img",
    ]


def scrub(path):
    """Best-effort overwrite-then-unlink for workspace copies of secrets."""
    if not path.exists():
        return
    with open(path, "r+b") as handle:
        handle.write(b"\0" * min(path.stat().st_size, MIB))
    path.unlink()


def provision_data(root, target, tools_label):
    """Format the profile's blank data partition into a unique LUKS2 volume.

    Runs the pinned cryptsetup from the tools image against a workspace
    copy of the partition region, then splices the formatted bytes into
    the profile disk host-side (the container never needs write access to
    the profile disk). Returns the evidence dictionary persisted as
    provision/data.json and referenced from the profile manifest.
    """
    identifier(tools_label)
    target = private_directory(target)
    builder.verify_tools(root, tools_label)
    tools_work = builder.parent(root) / builder.identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")

    disk = regular_file(target, "disk.raw")
    blank_before = assert_region_blank(disk, "The freshly copied factory disk")
    evidence = private_directory(target / "provision", create=True)
    secrets_dir = private_directory(target / "secrets", create=True)
    workspace = private_directory(evidence / "workspace", create=True)

    credential = generate_recovery_credential()
    write_secret(secrets_dir / "recovery.key", credential)
    # The container reads its own bind-mounted copy, so a failed or killed
    # run can scrub it without touching the profile's kept credential.
    write_secret(workspace / "recovery.key", credential)
    credential_sha256 = hashlib.sha256(credential).hexdigest()
    del credential

    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={workspace},dst=/workspace",
        image]
    try:
        builder.logged(evidence, "data-truncate", options + [
            "truncate", "--size", f"{DATA_BYTES}", "/workspace/data.img"], timeout=120)
        builder.logged(evidence, "data-luks-format", options + format_arguments(),
                       timeout=1800)
        # The recovery credential must actually verify against keyslot 0
        # before anything else happens (--test-passphrase: no activation,
        # works in the unprivileged container).
        builder.logged(evidence, "data-luks-verify", options + [
            "cryptsetup", "luksOpen", "--test-passphrase", "--disable-locks",
            "--key-file", "/workspace/recovery.key", "/workspace/data.img"],
            timeout=600)
        header_text = builder.logged(evidence, "data-luks-dump", options + [
            "cryptsetup", "luksDump", "--dump-json-metadata",
            "/workspace/data.img"], timeout=300)
        uuid = builder.logged(evidence, "data-luks-uuid", options + [
            "cryptsetup", "luksUUID", "/workspace/data.img"], timeout=300).strip()
        try:
            header = json.loads(header_text)
        except ValueError as error:
            raise SafetyError(f"luksDump did not produce JSON: {error}")
        if not re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid):
            raise SafetyError(f"Implausible LUKS2 uuid: {uuid!r}")
        validate_header(header, keyslots=["0"])

        formatted = (workspace / "data.img").read_bytes()
        if len(formatted) != DATA_BYTES:
            raise SafetyError("Formatted data image has unexpected size")
        header_blob = formatted[:HEADER_READ_BYTES]
        parse_header_json(header_blob)
        assert_binary_identity(header_blob, uuid=uuid)
        with open(disk, "r+b") as handle:
            handle.seek(DATA_OFFSET)
            handle.write(formatted)
            handle.flush()
            os.fsync(handle.fileno())
        del formatted

        if region_digest(disk, DATA_OFFSET) == blank_before:
            raise SafetyError("Formatting did not change the data region")
        # Re-read the spliced header from the disk itself, not the workspace.
        with open(disk, "rb") as handle:
            handle.seek(DATA_OFFSET)
            on_disk = handle.read(HEADER_READ_BYTES)
        parse_header_json(on_disk)
        assert_binary_identity(on_disk, uuid=uuid)
    finally:
        scrub(workspace / "recovery.key")
        scrub(workspace / "data.img")

    document = {
        "schema": 1,
        "volume": "luks2",
        "label": LUKS_LABEL,
        "uuid": uuid,
        "keyslots": ["0"],
        "keyslot_kdfs": {slot: kdf.get("kdf", {}).get("type")
                         for slot, kdf in header.get("keyslots", {}).items()},
        "cipher": header.get("segments", {}).get("0", {}).get("encryption"),
        "data_offset_bytes": header.get("segments", {}).get("0", {}).get("offset"),
        "recovery_credential": {
            "bits": RECOVERY_BYTES * 8,
            "path": "secrets/recovery.key",
            "sha256": credential_sha256,
            "escrow": "pending (Phase 5 item 7)",
            "transport": "file only; never in argv, serial or logs",
        },
        "blank_before_sha256": blank_before,
        "data_region_sha256": region_digest(disk, DATA_OFFSET),
        "tools_label": tools_label,
        "header": header,
        "scope": "Per-device LUKS2 volume from explicit provisioning; unique "
                 "volume material, recovery credential escrow-pending; not "
                 "production provisioning",
    }
    write_json(evidence / "data.json", document)
    return document
