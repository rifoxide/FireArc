"""Explicit signed development shell, never part of normal boot artifacts."""

import os
from pathlib import Path
import shutil
import sys
import tempfile

from . import device, pipeline, profile
from .inputs import load_lock
from .integrity import SafetyError, regular_file, sha256


def boot(root):
    """Boot a disposable factory disk into Bash in the verified Debian root."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SafetyError("just shell needs an interactive terminal (stdin and stdout)")
    tools = {}
    pins = load_lock(root, "host-tools")["tools"]
    for name in ("qemu-system-x86_64", "swtpm"):
        executable = shutil.which(name)
        if not executable or sha256(Path(executable)) != pins[name]["sha256"]:
            raise SafetyError(f"Host {name} is absent or does not match the pinned tool")
        tools[name] = executable
    # Hold the same lock as build/clean for the whole session: no stage backing
    # file may be replaced or pruned underneath QEMU's snapshot overlays.
    with pipeline.project_lock(root):
        pipe = pipeline.Pipeline(root, online=False)
        disk_label = pipe.ensure("shell-device")["id"]
        flash_label = pipe.ensure("shell-enroll")["id"]
        _, disk_output, _ = device._stage_outputs(root, disk_label, "shell-device")
        _, flash_output, _ = device._stage_outputs(root, flash_label, "shell-enroll")
        disk = regular_file(disk_output, "device.raw")
        flash = regular_file(flash_output, "enrolled.rom")
        # Fresh TPM and blank factory /data: never copy an existing profile's
        # credentials, recovery key, data or TPM identity into the shell VM.
        with tempfile.TemporaryDirectory(prefix=".shell-", dir=Path(root) / "build") as temporary:
            work = Path(temporary)
            tpm = work / "tpm"
            tpm.mkdir(mode=0o700)
            print("\nDEVELOPMENT SHELL — disposable VM; saved devices are untouched.\n"
                  "Verified Debian root is read-only; /run and /tmp are temporary.\n"
                  "/data is not provisioned. Exit powers off; Ctrl-A then X exits QEMU.\n"
                  "If the firmware menu waits, press Enter.\n", file=sys.stderr, flush=True)
            with profile.Machine(work, tools["qemu-system-x86_64"], tools["swtpm"],
                                 flash, disk, tpm, work / "serial.log",
                                 kvm=os.access("/dev/kvm", os.R_OK | os.W_OK),
                                 interactive=True) as machine:
                try:
                    code = machine.session.process.wait()
                    if code != 0:
                        raise SafetyError(f"Shell VM exited with rc={code}")
                finally:
                    machine.session.quit()
