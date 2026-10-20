"""Development key hierarchy for the secure boot chain.

Generates the development trust anchors and signing identity inside the
pinned tools container and stores them under gitignored ``secrets/`` at the
checkout root — outside source and build trees, so neither the project
digest nor ``just clean`` touches them, and the repository secrets scan
refuses that tree by name. Nothing here is committed to Git.

Hierarchy (UEFI variable chain):

    PK  (pk.key/pk.crt)   self-signed anchor; signs KEK updates
    KEK (kek.key/kek.crt) signed by PK; signs db updates
    db  (db.esl)          carries the image-signing certificate sb.crt
    SB  (sb.key/sb.crt)   signs systemd-boot and the UKI (codeSigning EKU)

Enrollment payloads follow the authenticated-variable format so the same
files work for every enrollment mechanism (offline variable-store surgery,
efi-updatevar or a first-party enrollment application):

    pk.auth  = ESL(pk.crt)  signed by pk.key   (initial self-enrollment)
    kek.auth = ESL(kek.crt) signed by pk.key
    db.auth  = ESL(sb.crt)  signed by kek.key

These are development credentials: generated once on the build host,
regenerable, with no production custody claim. Production signing and
rotation ceremony remain open plan items.
"""

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil

from . import builder
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, write_json,
)

CERT_DAYS = 3650  # ten development years; production lifetimes are a later decision
OWNER_GUID = "fa1ec0de-05ec-4a41-8a41-0000000000a1"  # fixed development owner GUID

SUBJECTS = {
    "pk": "/CN=FireArc Development Platform Key/",
    "kek": "/CN=FireArc Development Key Exchange Key/",
    "sb": "/CN=FireArc Development Image Signing/",
}

# (role key, role cert) files written by openssl; the SB certificate is the
# db content, so no separate db key/cert exists.
KEY_FILES = ("pk.key", "kek.key", "sb.key")
CERT_FILES = ("pk.crt", "kek.crt", "sb.crt")
ESL_FILES = ("pk.esl", "kek.esl", "db.esl")
AUTH_FILES = ("pk.auth", "kek.auth", "db.auth")
ALL_OUTPUTS = KEY_FILES + CERT_FILES + ESL_FILES + AUTH_FILES + ("manifest.json",)


def build_plan():
    """Ordered (name, command, outputs) generation steps, pure data."""
    steps = []

    def cert(role):
        subject = SUBJECTS[role]
        extra = ["-addext", "extendedKeyUsage=codeSigning"] if role == "sb" else []
        steps.append((
            f"generate-{role}",
            ["openssl", "req", "-new", "-x509", "-newkey", "rsa:3072",
             "-sha256", "-nodes", "-days", str(CERT_DAYS), "-set_serial", "1",
             "-subj", subject,
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "keyUsage=critical,digitalSignature", *extra,
             "-keyout", f"/keys/{role}.key", "-out", f"/keys/{role}.crt"],
            (f"{role}.key", f"{role}.crt")))

    for role in ("pk", "kek", "sb"):
        cert(role)

    # EFI signature lists; db carries the image-signing certificate.
    for name, source in (("pk", "pk.crt"), ("kek", "kek.crt"), ("db", "sb.crt")):
        steps.append((
            f"siglist-{name}",
            ["sbsiglist", "--owner", OWNER_GUID, "--type", "x509",
             "--output", f"/keys/{name}.esl", f"/keys/{source}"],
            (f"{name}.esl",)))

    # Authenticated variable payloads. PK is initially self-enrolled; KEK
    # updates are authorized by the current PK; db updates by the KEK.
    for name, key, cert_name in (("pk", "pk.key", "pk.crt"),
                                 ("kek", "pk.key", "pk.crt"),
                                 ("db", "kek.key", "kek.crt")):
        steps.append((
            f"varsign-{name}",
            ["sbvarsign", "--key", f"/keys/{key}", "--cert", f"/keys/{cert_name}",
             "--attr", "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,"
                       "TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
             "--output", f"/keys/{name}.auth",
             name.upper(), f"/keys/{name}.esl"],
            (f"{name}.auth",)))
    return steps


def state(root):
    """Classify the secrets tree: 'absent'/'empty' or 'complete'; partials fail."""
    directory = Path(root) / "secrets"
    if not directory.exists():
        return "absent", directory
    private_directory(directory)
    present = {name for name in ALL_OUTPUTS if (directory / name).is_file()}
    if present and not present >= set(ALL_OUTPUTS):
        raise SafetyError(
            f"Partial key hierarchy in secrets/ ({sorted(present)}); refusing to "
            f"generate beside it. Move the tree away or complete it explicitly.")
    return ("complete" if present else "empty"), directory


def ensure(root, tools_label):
    """Generate the development hierarchy once; report an existing one."""
    status, directory = state(root)
    if status == "complete":
        manifest = read_json(regular_file(directory, "manifest.json"))
        if manifest.get("schema") != 1 or not manifest.get("certificates"):
            raise SafetyError("secrets/manifest.json does not describe a hierarchy")
        return {"passed": True, "already_present": True,
                "certificates": {name: value["sha256_fingerprint"]
                                 for name, value in manifest["certificates"].items()},
                "scope": "Existing development hierarchy; nothing regenerated"}

    builder.verify_tools(root, tools_label)
    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SafetyError("Invalid pinned tools-image identity")
    work = private_directory(Path(root) / "build", create=True) / "keys"
    # Evidence from an earlier failed attempt would collide with logged()'s
    # exclusive files; generation evidence is disposable and starts fresh.
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=True)
    # The generation container sees the secrets tree alone — no repository,
    # no build outputs and no network. Only this step ever writes there.
    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={directory},dst=/keys",
        image]
    try:
        versions = builder.logged(work, "tool-versions", options + [
            "sh", "-c", "openssl version && sbsign --version && sbvarsign --version"],
            timeout=120)
        fingerprints = {}
        for name, command, outputs in build_plan():
            builder.logged(work, name, options + command, timeout=300)
            for output in outputs:
                regular_file(directory, output).chmod(0o600)
        for role, subject in SUBJECTS.items():
            report = builder.logged(work, f"describe-{role}", options + [
                "openssl", "x509", "-in", f"/keys/{role}.crt", "-noout",
                "-subject", "-serial", "-enddate", "-fingerprint", "-sha256"],
                timeout=120)
            fingerprint = ""
            for line in report.splitlines():
                if line.startswith("sha256 Fingerprint="):
                    fingerprint = line.split("=", 1)[1].replace(":", "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise SafetyError(f"Could not read the {role} certificate fingerprint")
            fingerprints[role] = {
                "subject": subject,
                "sha256_fingerprint": fingerprint,
                "file": f"{role}.crt",
            }
        manifest = {
            "schema": 1,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "owner_guid": OWNER_GUID,
            "rsa_bits": 3072, "dev_validity_days": CERT_DAYS,
            "certificates": fingerprints,
            "chain": {"pk.auth": "signed by pk (initial self-enrollment)",
                      "kek.auth": "signed by pk",
                      "db.auth": "signed by kek; db carries sb.crt"},
            "tools": versions.strip().splitlines(),
            "custody": "Development credentials in gitignored secrets/; "
                       "generated on this host; never committed, never in builds. "
                       "Production custody and rotation remain open decisions.",
            "scope": "Development trust hierarchy only; no production claim",
        }
        write_json(directory / "manifest.json", manifest)
        (directory / "manifest.json").chmod(0o600)
    except Exception as error:
        # Never leave a partial hierarchy behind: it would block the next run.
        shutil.rmtree(directory, ignore_errors=True)
        raise SafetyError(f"Key generation failed and secrets/ was reset: {error}")
    return {"passed": True, "already_present": False,
            "certificates": {name: value["sha256_fingerprint"]
                             for name, value in fingerprints.items()},
            "scope": "Development hierarchy generated under secrets/"}
