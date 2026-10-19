"""Non-installing diagnostics and repository-only credential screening."""

import os
from pathlib import Path
import platform
import shutil
import subprocess

from .inputs import load_lock
from .integrity import PRIVATE_PEM, TOKENS, SafetyError, public_name, regular_file, sha256


def doctor(root):
    pins = load_lock(root, "host-tools")["tools"]
    tools = {}
    for name in (*pins, "git", "just", "docker", "mkosi", "rauc", "dracut", "ukify", "tpm2_getcap"):
        path = shutil.which(name)
        item = {"available": path is not None}
        if path:
            item["path"] = path
            if name in pins:
                item["sha256"] = sha256(path)
                item["pin_matches"] = item["sha256"] == pins[name]["sha256"]
            args = ["-V"] if name == "debugfs" else ["--version"]
            try:
                result = subprocess.run([path, *args], capture_output=True, text=True, timeout=10)
                item["version_output"] = (result.stdout + result.stderr).splitlines()[:2]
            except subprocess.TimeoutExpired:
                item["error"] = "version query timed out"
        tools[name] = item
    qemu_ready = (platform.system() == "Linux" and platform.machine() == "x86_64"
                and all(tools[name].get("pin_matches") for name in ("qemu-system-x86_64", "qemu-img")))
    return {"qemu_tools_ready": qemu_ready, "tools": tools, "python": platform.python_version(),
            "host": platform.platform(), "disk_free_bytes": shutil.disk_usage(root).free,
            "kvm_accessible": os.access("/dev/kvm", os.R_OK | os.W_OK),
            "scope": "Read-only availability/compatibility report; no packages installed, no release/build qualification"}


def scan_repository(root):
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).decode().split("\0")
    checked = 0
    absent = 0
    for name in sorted(set(filter(None, names))):
        public_name(name)
        if name.split("/", 1)[0] in {"build", "run", "artifacts", "secrets", "private"}:
            raise SafetyError(f"Private/generated tree included in repository scan: {name}")
        try:
            path = regular_file(root, name)
        except FileNotFoundError:
            # git ls-files --cached includes paths deleted/renamed in the working
            # tree. There are no current bytes to scan; do not follow symlinks or
            # relax the regular-file checks for paths that are still present.
            absent += 1
            continue
        carry = b""
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                data = carry + chunk
                if PRIVATE_PEM.search(data) or TOKENS.search(data):
                    raise SafetyError(f"Possible credential in {name}; content withheld")
                carry = data[-512:]
        checked += 1
    return {"passed": True, "files_checked": checked, "files_absent": absent,
            "scope": "Private PEM/known token/path patterns only; not proof that arbitrary secrets are absent"}
