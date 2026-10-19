"""Bounded public-input verification and private local state helpers.

The host is trusted; these checks prevent accidental traversal, symlink use,
wrong artifacts and credential import. They are not a hostile-host sandbox.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


class SafetyError(ValueError):
    """An input or state precondition was not satisfied. Never bypass it."""


SHA256 = re.compile(r"[0-9a-f]{64}")
PRIVATE_PEM = re.compile(rb"(?:^|\n)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
TOKENS = re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b")


def relative_name(name, *, allow_backslash=False):
    if not isinstance(name, str) or not name or len(name) > 4096:
        raise SafetyError("Empty or oversized relative path")
    path = PurePosixPath(name)
    if (path.is_absolute() or str(path) != name or ".." in path.parts
            or not path.parts or any(ord(c) < 32 for c in name) or ("\\" in name and not allow_backslash)):
        raise SafetyError(f"Unsafe relative path: {name!r}")
    return path


def public_name(name):
    path = relative_name(name)
    if (any(p.lower() in {".git", "private", "secrets", ".ssh", "lab-keys"} for p in path.parts)
            or path.suffix.lower() in {".key", ".p12", ".pfx"}
            or path.name == ".env" or path.name.startswith(".env.")):
        raise SafetyError(f"Potential private credential path refused: {name}")
    return path


def regular_file(root, name):
    """Reject symlinks in every relative component, not just the final file."""
    parts = relative_name(name).parts
    path = Path(root)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise SafetyError(f"Not a real directory: {path}")
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        wanted = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not wanted(mode):
            raise SafetyError(f"Not a regular file/directory (symlinks refused): {path}")
    return path


def sha256(path, *, scan_private=False):
    digest = hashlib.sha256()
    carry = b""
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if scan_private and PRIVATE_PEM.search(carry + chunk):
                raise SafetyError(f"Private-key material in public input: {path}")
            carry = chunk[-256:]
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path, expected, *, scan_private=False):
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise SafetyError("Expected an explicit SHA-256 pin")
    if sha256(path, scan_private=scan_private) != expected:
        raise SafetyError(f"SHA-256 mismatch: {path}")


def parse_manifest(data):
    if not data or len(data) > 4 * 1024 * 1024:
        raise SafetyError("Missing or oversized manifest")
    entries = {}
    for row in data.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", row)
        if not match:
            raise SafetyError("Malformed SHA256SUMS entry")
        digest, name = match.groups()
        public_name(name)
        if name in entries or len(entries) >= 10000:
            raise SafetyError("Duplicate entry or oversized manifest")
        entries[name] = digest
    return entries


def verify_archive(directory, manifest_pin):
    manifest = regular_file(directory, "SHA256SUMS")
    verify_file(manifest, manifest_pin)
    entries = parse_manifest(manifest.read_bytes())
    for name, digest in entries.items():
        verify_file(regular_file(directory, name), digest, scan_private=True)
    return entries


def read_json(path):
    if Path(path).stat().st_size > 4 * 1024 * 1024:
        raise SafetyError(f"Oversized JSON: {path}")
    return json.loads(Path(path).read_text())


def write_json(path, value):
    """Exclusive creation: never truncate an existing evidence/state file."""
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def private_directory(path, *, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise SafetyError(f"Expected owned 0700 directory: {path}")
    return path


def identifier(value):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise SafetyError("Identifier must be 1–32 lowercase letters/digits/hyphens, starting with a letter")
    return value


def safe_qemu_path(path):
    value = str(Path(path).absolute())
    if "," in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SafetyError("QEMU paths must not contain commas or control characters")
    return value
