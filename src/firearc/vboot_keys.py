"""Development vboot key hierarchy under gitignored secrets/vboot/.

Mirrors the X.509 hierarchy's custody rules (ADR 0006) for coreboot vboot:
generated once on the build host by an isolated container that sees only an
empty secrets/vboot/ tree, the pinned tools image and the pinned futility
binary — no repository, no build outputs, no network. The private keyset
never leaves the secrets tree; stages consume it read-only by digest.

Key material: root RSA-4096 and firmware data key RSA-2048 (vboot's
algorithm enum has no plain RSA-3072; sizes chosen per the hardware/ODM
notes), converted from traditional PKCS#1 PEMs into the vb1 keyset layout
`futility sign --keyset` consumes.
"""

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess

from . import builder
from .builder import logged
from .integrity import (SafetyError, identifier, private_directory, read_json,
                        regular_file, sha256, write_json)

ROOT_BITS = 4096
FIRMWARE_BITS = 2048
KERNEL_SUBKEY_BITS = 2048
KEYSET_FILES = ("root_key.vbprivk", "root_key.vbpubk",
                "firmware_data_key.vbprivk", "firmware_data_key.vbpubk",
                "kernel_subkey.vbprivk", "kernel_subkey.vbpubk",
                "firmware.keyblock")
ALL_OUTPUTS = KEYSET_FILES + ("manifest.json",)


def state(root):
    """Classify secrets/vboot: 'absent'/'empty'/'complete'; partials fail."""
    directory = Path(root) / "secrets/vboot"
    if not directory.exists():
        return "absent", directory
    private_directory(directory)
    present = {name for name in ALL_OUTPUTS if (directory / name).is_file()}
    if present and not present >= set(ALL_OUTPUTS):
        raise SafetyError(
            f"Partial vboot keyset in secrets/vboot/ ({sorted(present)}); "
            f"refusing to generate beside it. Move the tree away or complete "
            f"it explicitly.")
    return ("complete" if present else "empty"), directory


def _tools(root, tools_label):
    work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")
    return image


def _futility(root, futility_label):
    """The pinned futility binary from its stage output, verified by receipt."""
    record = read_json(regular_file(Path(root) / "build", "state.json")) \
        .get("stages", {}).get("futility")
    if not record or record.get("id") != futility_label:
        raise SafetyError("futility stage record does not match its label")
    return regular_file(Path(root) / "build/firmware-build" / futility_label / "output",
                        "futility")


def ensure(root, tools_label, futility_label):
    """Generate the development vboot keyset once; report an existing one."""
    status, directory = state(root)
    if status == "complete":
        manifest = read_json(regular_file(directory, "manifest.json"))
        if manifest.get("schema") != 1 or not manifest.get("keys"):
            raise SafetyError("secrets/vboot/manifest.json does not describe a keyset")
        return {"passed": True, "already_present": True,
                "keys": manifest["keys"],
                "scope": "Existing development vboot keyset; nothing regenerated"}

    identifier(futility_label)
    futility = _futility(root, futility_label)
    image = _tools(root, tools_label)
    work = private_directory(Path(root) / "build", create=True) / "vboot-keys"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=True)
    # The generation container sees the vboot secrets tree alone, plus the
    # pinned futility binary read-only. No repository, no builds, no network.
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={futility},dst=/usr/local/bin/futility,readonly",
        "--mount", f"type=bind,src={directory},dst=/keys",
        image]
    try:
        logged(work, "genkey-root", options + [
            "openssl", "genrsa", "-traditional", "-out", "/keys/root_key.pem",
            str(ROOT_BITS)], timeout=600)
        logged(work, "genkey-firmware", options + [
            "openssl", "genrsa", "-traditional", "-out", "/keys/firmware_data_key.pem",
            str(FIRMWARE_BITS)], timeout=300)
        logged(work, "genkey-kernel-subkey", options + [
            "openssl", "genrsa", "-traditional", "-out", "/keys/kernel_subkey.pem",
            str(KERNEL_SUBKEY_BITS)], timeout=300)
        for role in ("root_key", "firmware_data_key", "kernel_subkey"):
            logged(work, f"convert-{role}", options + [
                "futility", "--vb1", "create", f"/keys/{role}.pem",
                f"/keys/{role}"], timeout=300)
        # The firmware keyblock carries the firmware data public key and is
        # signed by the root key: this is the chain the RO GBB root verifies.
        logged(work, "pack-keyblock", options + [
            "futility", "vbutil_keyblock", "--pack", "/keys/firmware.keyblock",
            "--datapubkey", "/keys/firmware_data_key.vbpubk",
            "--signprivate", "/keys/root_key.vbprivk"], timeout=300)
        for role in ("root_key", "firmware_data_key"):
            report = logged(work, f"show-{role}", options + [
                "futility", "--vb1", "show", f"/keys/{role}.vbpubk"], timeout=120)
            algorithm = ""
            for line in report.splitlines():
                if line.strip().startswith("Algorithm:"):
                    algorithm = line.split(":", 1)[1].strip()
            if not algorithm:
                raise SafetyError(f"Could not read the {role} vboot algorithm")
            logged(work, f"describe-{role}", options + [
                "futility", "--vb1", "show", f"/keys/{role}.vbprivk"], timeout=120)
        # The PEM intermediates are redundant secret copies; the vb1 keyset is
        # what every consumer uses. Remove them while only this step writes.
        logged(work, "remove-pem", options + [
            "rm", "/keys/root_key.pem", "/keys/firmware_data_key.pem",
            "/keys/kernel_subkey.pem"], timeout=120)
        for name in KEYSET_FILES:
            path = regular_file(directory, name)
            path.chmod(0o600)
        keys = {name: {"sha256": sha256(regular_file(directory, name)),
                       "bytes": regular_file(directory, name).stat().st_size,
                       "private": name.endswith(".vbprivk")}
                for name in KEYSET_FILES}
        missing = set(KEYSET_FILES) - set(keys)
        if missing:
            raise SafetyError(f"vboot keyset generation left files missing: {sorted(missing)}")
        manifest = {
            "schema": 1,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "root_rsa_bits": ROOT_BITS, "firmware_rsa_bits": FIRMWARE_BITS,
            "kernel_subkey_rsa_bits": KERNEL_SUBKEY_BITS,
            "format": "vb1 keyset (futility sign --keyset layout): root key "
                      "signs firmware.keyblock, which carries the firmware "
                      "data key; the kernel subkey rides the preamble",
            "keys": keys,
            "custody": "Development vboot credentials in gitignored secrets/vboot/; "
                       "generated on this host; never committed, never in builds. "
                       "Production vboot custody is a separate owner decision.",
        }
        write_json(directory / "manifest.json", manifest)
        (directory / "manifest.json").chmod(0o600)
    finally:
        pass
    return {"passed": True, "already_present": False, "keys": manifest["keys"],
            "scope": "Development vboot keyset generated under secrets/vboot/"}
