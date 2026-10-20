"""FireArc project build interface."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import builder, pipeline, profile
from .host import doctor, scan_repository
from .inputs import validate_locks
from .integrity import SafetyError

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "verify-inputs", "secrets", "status"):
        commands.add_parser(name)
    for name in ("bootstrap", "build-tools", "build-root", "build-rootfs", "build", "sbom", "firmware-sources", "firmware-build", "firmware-layout", "device", "check-boot", "check-initrd", "check-rootfs", "verify-build"):
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
    prune = commands.add_parser("prune",
                                help="Delete superseded stage evidence (keeps current + previous)")
    prune.add_argument("--keep", type=int, default=1,
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
        elif args.command == "clean":
            with pipeline.project_lock(ROOT): pipeline.clean(ROOT, confirmed=args.yes)
            result = {"passed": True, "removed": "build/"}
        elif args.command == "reproduce": result = pipeline.reproduce(ROOT, confirmed=args.yes)
        elif args.command == "device-provision":
            with pipeline.project_lock(ROOT):
                result = profile.provision(ROOT, args.name, replace=args.replace)
        elif args.command == "device-boot":
            with pipeline.project_lock(ROOT):
                result = profile.boot(ROOT, args.name, count=args.count)
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
