"""Development PCR-policy signing key under gitignored secrets/pcr/.

PLAN Phase 5 item 5 requires the PCR-policy signer to be a distinct role
from the db/UKI (sb) signer: this key authorizes expected TPM PCR 11 states
for data unlock; it never signs boot artifacts, and the sb key never signs
PCR policy. Generated once on the build host by an isolated container that
sees only an empty secrets/pcr/ tree and the pinned tools image — no
repository, no build outputs, no network.

Key material: one RSA-3072 pair. The public half is stored as a bare PEM
public key (SubjectPublicKeyInfo), not a certificate: the pinned
systemd-measure 257.13 rejects certificates passed to ``--public-key=``
("Failed to parse public key"), so a certificate would make the key
unusable by ukify/systemd-measure. RSA with PKCS#1 v1.5 SHA-256 signing is
deterministic, which keeps the PCR-signed UKI byte-reproducible — unlike
the sbsign layer, which embeds a signing time.

The manifest records ``pkfp`` — the SHA-256 of the raw ``RSAPublicKey``
DER — because that is the fingerprint systemd-measure embeds in every
.pcrsig entry (``pubkey_fingerprint()`` hashes ``i2d_PublicKey`` output).
Consumers compare .pcrsig entries against this value.

These are development credentials: no production custody claim. Production
PCR-policy custody and rotation remain open plan items (Phase 2 item 10).
"""

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil

from . import builder
from .builder import logged
from .integrity import (SafetyError, private_directory, read_json,
                        regular_file, sha256, write_json)

RSA_BITS = 3072
KEY_FILES = ("pcr.key", "pcr.pub")
ALL_OUTPUTS = KEY_FILES + ("manifest.json",)


def state(root):
    """Classify secrets/pcr: 'absent'/'empty'/'complete'; partials fail."""
    directory = Path(root) / "secrets/pcr"
    if not directory.exists():
        return "absent", directory
    private_directory(directory)
    present = {name for name in ALL_OUTPUTS if (directory / name).is_file()}
    if present and not present >= set(ALL_OUTPUTS):
        raise SafetyError(
            f"Partial PCR-policy keyset in secrets/pcr/ ({sorted(present)}); "
            f"refusing to generate beside it. Move the tree away or complete "
            f"it explicitly.")
    return ("complete" if present else "empty"), directory


def ensure(root, tools_label):
    """Generate the development PCR-policy key once; report an existing one."""
    status, directory = state(root)
    if status == "complete":
        manifest = read_json(regular_file(directory, "manifest.json"))
        if manifest.get("schema") != 1 or not manifest.get("pkfp"):
            raise SafetyError("secrets/pcr/manifest.json does not describe a keyset")
        return {"passed": True, "already_present": True,
                "pkfp": manifest["pkfp"],
                "scope": "Existing development PCR-policy key; nothing regenerated"}

    builder.verify_tools(root, tools_label)
    tools_work = builder.parent(root) / builder.identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")
    work = private_directory(Path(root) / "build", create=True) / "pcr-keys"
    # Evidence from an earlier failed attempt would collide with logged()'s
    # exclusive files; generation evidence is disposable and starts fresh.
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=True)
    # The generation container sees the PCR secrets tree alone — no
    # repository, no build outputs and no network. Only this step writes it.
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={directory},dst=/keys",
        image]
    try:
        versions = logged(work, "tool-versions", options + [
            "sh", "-c", "openssl version"], timeout=120)
        logged(work, "generate-pcr-key", options + [
            "openssl", "genrsa", "-out", "/keys/pcr.key", str(RSA_BITS)],
            timeout=600)
        logged(work, "export-public-key", options + [
            "openssl", "rsa", "-in", "/keys/pcr.key", "-pubout",
            "-out", "/keys/pcr.pub"], timeout=120)
        # The fingerprint systemd-measure records in .pcrsig entries:
        # SHA-256 over the raw RSAPublicKey DER (i2d_PublicKey). The DER
        # goes to a scratch file inside the container and is printed as
        # clean hex by od, so no raw bytes enter the log transcript.
        der = logged(work, "public-key-der", options + [
            "sh", "-c", "openssl rsa -pubin -in /keys/pcr.pub "
            "-RSAPublicKey_out -outform DER -out /tmp/pcr-der.bin "
            "&& od -An -v -tx1 /tmp/pcr-der.bin && rm -f /tmp/pcr-der.bin"],
            timeout=120)
        pkfp = sha256_of_hexdump(der)
        if not re.fullmatch(r"[0-9a-f]{64}", pkfp):
            raise SafetyError("Could not derive the PCR public-key fingerprint")
        for name in KEY_FILES:
            regular_file(directory, name).chmod(0o600)
        manifest = {
            "schema": 1,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "rsa_bits": RSA_BITS,
            "pkfp": pkfp,
            "format": "Bare PEM public key (SubjectPublicKeyInfo): the pinned "
                      "systemd-measure/ukify reject certificates as --public-key; "
                      "pkfp is SHA-256 over the raw RSAPublicKey DER, the value "
                      "systemd-measure embeds in every .pcrsig entry",
            "signature_scheme": "RSASSA-PKCS1-v1_5 with SHA-256 (deterministic; "
                                "the .pcrsig layer stays byte-reproducible)",
            "files": {name: {"sha256": sha256(regular_file(directory, name)),
                             "private": name.endswith(".key")}
                      for name in KEY_FILES},
            "role": "PCR-policy signer (PLAN Phase 5 item 5): authorizes "
                    "expected PCR 11 states for data unlock; deliberately "
                    "distinct from the sb/db image-signing role",
            "custody": "Development credential in gitignored secrets/pcr/; "
                       "generated on this host; never committed, never in "
                       "builds. Production PCR-policy custody and rotation "
                       "remain open decisions.",
            "tools": versions.strip().splitlines(),
            "scope": "Development PCR-policy key only; no production claim",
        }
        write_json(directory / "manifest.json", manifest)
        (directory / "manifest.json").chmod(0o600)
    except Exception as error:
        # Never leave a partial keyset behind: it would block the next run.
        shutil.rmtree(directory, ignore_errors=True)
        raise SafetyError(f"PCR key generation failed and secrets/pcr/ was "
                          f"reset: {error}")
    return {"passed": True, "already_present": False, "pkfp": pkfp,
            "scope": "Development PCR-policy key generated under secrets/pcr/"}


def sha256_of_hexdump(text):
    """SHA-256 of the bytes an ``od -An -v -tx1`` dump describes.

    The container prints the DER as whitespace-separated hex pairs (no
    offsets), so the dump parses without guessing at column layouts; any
    line that is not pure hex pairs fails closed.
    """
    import hashlib
    pairs = []
    for line in text.splitlines():
        for token in line.split():
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                raise SafetyError("Public-key DER dump is not clean hex")
            pairs.append(token)
    if not pairs:
        raise SafetyError("Public-key DER dump is empty")
    return hashlib.sha256(bytes.fromhex("".join(pairs))).hexdigest()
