"""FireArc project build interface."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import builder, keys, pipeline, pcr_keys, profile, vboot_keys
from .host import doctor, scan_repository
from .inputs import validate_locks
from .integrity import SafetyError

ROOT = Path(__file__).resolve().parents[2]

# One maintainer command instead of a public wrapper for every DAG node.
BUILD_STAGES = ("tools", "root", "rootfs", "check-initrd", "check-rootfs", "sbom",
                "firmware-build", "firmware-layout", "futility", "firmware-sign",
                "uki", "pcr-sign", "sign", "enroll", "device")


def create_parser():
    """Describe the interface without acquiring locks or running operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "verify-inputs", "secrets", "status"):
        commands.add_parser(name)
    commands.add_parser("shell", help="Boot a disposable signed development VM into a Debian root shell")
    commands.add_parser(
        "keys", help="Generate (once) the development signing hierarchy under secrets/")
    commands.add_parser(
        "vboot-keys", help="Generate (once) the development vboot keyset under secrets/vboot/")
    commands.add_parser(
        "pcr-keys", help="Generate (once) the development PCR-policy key under secrets/pcr/")
    for name in ("bootstrap", "build", "check-boot", "check-secure-boot",
                 "check-firmware-vboot", "verify-build"):
        commands.add_parser(name)
    firmware = commands.add_parser("firmware-sources", help="Acquire verified pinned firmware sources")
    firmware.add_argument("--online", action="store_true", help="Allow pinned source downloads")
    stage = commands.add_parser("stage", help="Build or audit one intermediate stage offline")
    stage.add_argument("name", choices=BUILD_STAGES)
    for name in ("clean", "reproduce"):
        command = commands.add_parser(name)
        command.add_argument("--yes", action="store_true", help="Confirm deletion of the generated outputs")
    provision = commands.add_parser("device-provision",
                                    help="Explicitly create or replace a persistent device profile")
    provision.add_argument("--name", required=True)
    provision.add_argument("--replace", action="store_true",
                           help="Discard the existing profile state and start a fresh device")
    boot = commands.add_parser("device-boot",
                               help="Cold-start a persistent device profile with its swtpm")
    boot.add_argument("--name", required=True)
    boot.add_argument("--count", type=int, default=2)
    boot.add_argument("--tcg", action="store_true",
                      help="Force the TCG software-accelerated machine (KVM is the default profile)")
    enroll = commands.add_parser("data-enroll",
                                 help="One TPM2 enrollment session for a profile's data volume")
    enroll.add_argument("--name", required=True)
    reboot = commands.add_parser("device-reboot",
                                 help="Warm-reset a running profile in one powered session")
    reboot.add_argument("--name", required=True)
    reboot.add_argument("--resets", type=int, default=2)
    stop = commands.add_parser("device-stop",
                               help="Boot to the marker, then stop the machine via QMP powerdown")
    stop.add_argument("--name", required=True)
    powercut = commands.add_parser("device-powercut",
                                   help="Cut power hard after a verified boot (SIGKILL QEMU+swtpm)")
    powercut.add_argument("--name", required=True)
    snapshot = commands.add_parser("device-snapshot",
                                   help="Copy the whole persistent device state into a named snapshot")
    snapshot.add_argument("--name", required=True)
    snapshot.add_argument("--label", required=True)
    restore = commands.add_parser("device-restore",
                                  help="Explicitly restore persistent state from a named snapshot")
    restore.add_argument("--name", required=True)
    restore.add_argument("--label", required=True)
    prune = commands.add_parser("prune",
                                help="Delete superseded stage evidence (keeps only current)")
    prune.add_argument("--keep", type=int, default=0,
                       help="How many superseded evidence directories to keep per stage")
    return parser


def _key_command(command):
    """Keep key roles separate while sharing their locked tools preparation."""
    with pipeline.project_lock(ROOT):
        pipe = pipeline.Pipeline(ROOT)
        tools = pipe.ensure("tools")["id"]
        if command == "keys":
            return keys.ensure(ROOT, tools)
        if command == "vboot-keys":
            return vboot_keys.ensure(ROOT, tools, pipe.ensure("futility")["id"])
        if command == "pcr-keys":
            return pcr_keys.ensure(ROOT, tools)
    raise SafetyError(f"Unknown key command: {command}")


def _device_command(args):
    """Every saved-device operation holds the lock for its entire session."""
    with pipeline.project_lock(ROOT):
        if args.command == "device-provision":
            return profile.provision(ROOT, args.name, replace=args.replace)
        if args.command == "device-boot":
            return profile.boot(ROOT, args.name, count=args.count, tcg=args.tcg)
        if args.command == "data-enroll":
            return profile.data_enroll(ROOT, args.name)
        if args.command == "device-reboot":
            return profile.reboot(ROOT, args.name, resets=args.resets)
        if args.command == "device-stop":
            return profile.stop(ROOT, args.name)
        if args.command == "device-powercut":
            return profile.powercut(ROOT, args.name)
        if args.command == "device-snapshot":
            return profile.snapshot(ROOT, args.name, args.label)
        if args.command == "device-restore":
            return profile.restore(ROOT, args.name, args.label)
    raise SafetyError(f"Unknown device command: {args.command}")


def execute(args):
    """Dispatch parsed arguments; command implementations own their work."""
    if args.command == "shell":
        from .shell import boot
        boot(ROOT)
        return
    if args.command == "doctor":
        return doctor(ROOT)
    if args.command == "verify-inputs":
        validate_locks(ROOT)
        builder.lock(ROOT)
        builder.root_lock(ROOT)
        return {"passed": True, "scope": "Specification and project input locks"}
    if args.command == "secrets":
        return scan_repository(ROOT)
    if args.command in ("keys", "vboot-keys", "pcr-keys"):
        return _key_command(args.command)
    if args.command.startswith("device-") or args.command == "data-enroll":
        return _device_command(args)
    if args.command == "clean":
        with pipeline.project_lock(ROOT):
            pipeline.clean(ROOT, confirmed=args.yes)
        return {"passed": True, "removed": "build/"}
    if args.command == "reproduce":
        return pipeline.reproduce(ROOT, confirmed=args.yes)
    if args.command == "stage":
        return pipeline.run(ROOT, args.name)
    if args.command == "prune":
        with pipeline.project_lock(ROOT):
            return pipeline.prune(ROOT, keep=args.keep)
    return pipeline.run(ROOT, args.command,
                        online=getattr(args, "online", False) or args.command == "bootstrap")


def main():
    args = create_parser().parse_args()
    try:
        result = execute(args)
        if args.command != "shell":
            print(json.dumps(result, indent=2, sort_keys=True))
    except (SafetyError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; no incomplete stage is published as successful.", file=sys.stderr)
        sys.exit(130)
