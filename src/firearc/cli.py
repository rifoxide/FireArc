"""FireArc project build interface."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import builder, keys, pipeline, profile, vboot_keys
from .host import doctor, scan_repository
from .inputs import validate_locks
from .integrity import SafetyError

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "verify-inputs", "secrets", "status"):
        commands.add_parser(name)
    keys_command = commands.add_parser(
        "keys", help="Generate (once) the development signing hierarchy under secrets/")
    commands.add_parser(
        "vboot-keys", help="Generate (once) the development vboot keyset under secrets/vboot/")
    for name in ("bootstrap", "build-tools", "build-root", "build-rootfs", "build", "sbom", "firmware-sources", "firmware-build", "futility", "firmware-sign", "firmware-layout", "uki", "sign", "enroll", "device", "check-boot", "check-secure-boot", "check-firmware-vboot", "check-initrd", "check-rootfs", "verify-build"):
        command = commands.add_parser(name)
        command.add_argument("--online", action="store_true", help="Allow pinned dependency downloads")
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
    args = parser.parse_args()
    try:
        if args.command == "doctor": result = doctor(ROOT)
        elif args.command == "verify-inputs":
            validate_locks(ROOT)
            builder.lock(ROOT)
            builder.root_lock(ROOT)
            result = {"passed": True, "scope": "Specification and project input locks"}
        elif args.command == "secrets": result = scan_repository(ROOT)
        elif args.command == "keys":
            with pipeline.project_lock(ROOT):
                pipe = pipeline.Pipeline(ROOT)
                result = keys.ensure(ROOT, pipe.ensure("tools")["id"])
        elif args.command == "vboot-keys":
            with pipeline.project_lock(ROOT):
                pipe = pipeline.Pipeline(ROOT)
                result = vboot_keys.ensure(ROOT, pipe.ensure("tools")["id"],
                                           pipe.ensure("futility")["id"])
        elif args.command == "clean":
            with pipeline.project_lock(ROOT): pipeline.clean(ROOT, confirmed=args.yes)
            result = {"passed": True, "removed": "build/"}
        elif args.command == "reproduce": result = pipeline.reproduce(ROOT, confirmed=args.yes)
        elif args.command == "device-provision":
            with pipeline.project_lock(ROOT):
                result = profile.provision(ROOT, args.name, replace=args.replace)
        elif args.command == "device-boot":
            with pipeline.project_lock(ROOT):
                result = profile.boot(ROOT, args.name, count=args.count, tcg=args.tcg)
        elif args.command == "device-reboot":
            with pipeline.project_lock(ROOT):
                result = profile.reboot(ROOT, args.name, resets=args.resets)
        elif args.command == "device-stop":
            with pipeline.project_lock(ROOT):
                result = profile.stop(ROOT, args.name)
        elif args.command == "device-powercut":
            with pipeline.project_lock(ROOT):
                result = profile.powercut(ROOT, args.name)
        elif args.command == "device-snapshot":
            with pipeline.project_lock(ROOT):
                result = profile.snapshot(ROOT, args.name, args.label)
        elif args.command == "device-restore":
            with pipeline.project_lock(ROOT):
                result = profile.restore(ROOT, args.name, args.label)
        elif args.command == "prune":
            with pipeline.project_lock(ROOT):
                result = pipeline.prune(ROOT, keep=args.keep)
        else:
            result = pipeline.run(ROOT, args.command, online=getattr(args, "online", False) or args.command == "bootstrap")
        print(json.dumps(result, indent=2, sort_keys=True))
    except (SafetyError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; no incomplete stage is published as successful.", file=sys.stderr)
        sys.exit(130)
