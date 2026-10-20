"""Isolated signing step for the development boot artifacts.

Signs the byte-stable Unified Kernel Image and the systemd-boot loader with
the development image-signing key. The signing container sees exactly two
files from the custody tree — sb.key and sb.crt, both read-only — satisfying
the plan's rule that an isolated signing step receives only the required
private key; PK/KEK material and everything else under secrets/ stay
unreachable. Every signed image is verified (sbverify) and structurally
checked (covers_content): apart from the recomputed PE checksum and the
Certificate Table directory entry, the signed image must equal the unsigned
artifact byte for byte, with the appended region being exactly the described
certificate — proving the signature covers the exact content the uki/root
stages produced.

sbsign embeds a signing time, so the signature layer is NOT byte-reproducible
across rebuilds; this is recorded honestly instead of hidden. Reproducibility
claims attach to the covered content, whose digest is recorded and checked
against the unsigned artifact.
"""

from pathlib import Path
import re
import shutil
import struct
import tarfile

from . import builder, device, keys, uki as uki_module
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file,
    sha256, write_json,
)

LOADER_ARTIFACT = "systemd-bootx64.efi"
LOADER_MEMBER = "./usr/lib/systemd/boot/efi/systemd-bootx64.efi"


def commands(name):
    """Container command pair (sign, verify) for one artifact."""
    return (
        ["sbsign", "--key", "/keys/sb.key", "--cert", "/keys/sb.crt",
         "--output", f"/work/{name}", f"/work/inputs/{name}"],
        ["sbverify", "--cert", "/keys/sb.crt", f"/work/{name}"],
    )


def covers_content(unsigned, signed):
    """True when the signed image is the unsigned artifact plus only signature.

    sbsign appends the WIN_CERTIFICATE at the end of the file and records it
    in the Certificate Table data directory, and recomputes the PE checksum.
    Everything else must match the unsigned artifact byte for byte, and the
    directory must describe exactly the appended region — otherwise the
    signature does not cover the byte-stable content the build produced.
    """
    if len(signed) <= len(unsigned) or not unsigned.startswith(b"MZ") \
            or not signed.startswith(b"MZ"):
        return False
    signature = struct.unpack_from("<I", signed, 0x3C)[0]
    optional = signature + 24
    checksum_field = range(optional + 64, optional + 68)
    directory = optional + 112 + 4 * 8  # data directory 4: Certificate Table
    rva, size = struct.unpack_from("<II", signed, directory)
    for index in range(len(unsigned)):
        if unsigned[index] != signed[index] \
                and index not in checksum_field and index not in range(directory, directory + 8):
            return False
    return rva == len(unsigned) and size == len(signed) - len(unsigned)


def extract_loader(archive_path):
    """The exact loader binary the root archive ships."""
    with tarfile.open(archive_path, "r:") as archive:
        member = archive.getmember(LOADER_MEMBER)
        if not member.isreg() or not 0 < member.size < 8 * 1024 * 1024:
            raise SafetyError("Invalid loader member in the root archive")
        loader = archive.extractfile(member).read()
    if not loader.startswith(b"MZ"):
        raise SafetyError("Root-archive loader is not a PE image")
    return loader


def build(root, tools_label, root_label, uki_label, label):
    """Sign the UKI and loader; verify and strip-check both in-stage."""
    status, _ = keys.state(root)
    if status != "complete":
        raise SafetyError("Development signing hierarchy absent; run just keys first")
    custody = read_json(regular_file(Path(root) / "secrets", "manifest.json"))
    signer = custody.get("certificates", {}).get("sb", {}).get("sha256_fingerprint")
    if not re.fullmatch(r"[0-9a-f]{64}", signer or ""):
        raise SafetyError("secrets/manifest.json lacks the signing-certificate fingerprint")

    builder.verify_tools(root, tools_label)
    _, root_output, _ = device._stage_outputs(root, root_label, "appliance-root")
    archive = regular_file(root_output, "firearc-root.tar")
    _, uki_output, uki_result = device._stage_outputs(root, uki_label, "uki")
    unsigned_uki = regular_file(uki_output, device.UKI_ARTIFACT)
    if not uki_result.get("byte_identical_rebuild") or not uki_result.get("sections_verified"):
        raise SafetyError("Expected a byte-stable, section-verified UKI to sign")

    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")

    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    payload = work / "payload"
    (payload / "inputs").mkdir(mode=0o700, parents=True)
    output = work / "output"
    output.mkdir(mode=0o700)
    shutil.copyfile(unsigned_uki, payload / "inputs" / device.UKI_ARTIFACT)
    (payload / "inputs" / LOADER_ARTIFACT).write_bytes(extract_loader(archive))

    # The isolated signing step: only the required private key and its own
    # certificate enter the container, read-only; nothing else from secrets/.
    secrets = Path(root) / "secrets"
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={secrets / 'sb.key'},dst=/keys/sb.key,readonly",
        "--mount", f"type=bind,src={secrets / 'sb.crt'},dst=/keys/sb.crt,readonly",
        "--mount", f"type=bind,src={payload},dst=/work",
        image]
    try:
        content = {}
        for name in (device.UKI_ARTIFACT, LOADER_ARTIFACT):
            unsigned = (payload / "inputs" / name).read_bytes()
            digest = sha256(payload / "inputs" / name)
            content[name] = digest
            signing, verify = commands(name)
            builder.logged(work, f"sbsign-{name}", options + signing, timeout=300)
            builder.logged(work, f"sbverify-{name}", options + verify, timeout=120)
            if not covers_content(unsigned, regular_file(payload, name).read_bytes()):
                raise SafetyError(f"Signature on {name} does not cover the exact "
                                  f"byte-stable unsigned artifact")
            if name == device.UKI_ARTIFACT:
                sections, _ = uki_module.pe_sections(regular_file(payload, name).read_bytes())
                names = {section["name"] for section in sections}
                missing = [item for item in uki_module.REQUIRED_SECTIONS if item not in names]
                if missing:
                    raise SafetyError(f"Signed UKI lost required sections: {missing}")
            shutil.move(str(payload / name), str(output / name))
        write_json(work / "sign.json", {
            "schema": 1, "signer_fingerprint": signer,
            "signed": [device.UKI_ARTIFACT, LOADER_ARTIFACT],
            "content_sha256": content,
            "loader_source": {"root_label": root_label, "member": LOADER_MEMBER,
                              "root_tar_sha256": sha256(archive)},
            "uki_source": {"uki_label": uki_label,
                           "unsigned_sha256": sha256(unsigned_uki)},
            "signature_layer_byte_reproducible": False,
            "signature_layer_note": "sbsign embeds a signing time; reproducibility "
                                    "attaches to the covered content digest above",
            "tools_image": image,
            "custody": "Development sb key (ADR 0006); only sb.key/sb.crt entered "
                       "the signing container, read-only",
            "scope": "Development signatures; not production signing custody"})
        write_json(work / "result.json", {
            "passed": True,
            "artifacts": {device.UKI_ARTIFACT: sha256(output / device.UKI_ARTIFACT),
                          LOADER_ARTIFACT: sha256(output / LOADER_ARTIFACT)},
            "signed": True, "signatures_verified": True,
            "covers_exact_unsigned_content": True,
            "signer_fingerprint": signer,
            "boot_chain_qualified": False,
            "scope": "Boot artifacts signed and verified; Secure Boot enforcement "
                     "still requires variable-store enrollment"})
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Development-signed UKI and systemd-boot loader"}
