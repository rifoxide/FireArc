"""FireArc project build interface."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import builder, pipeline
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
        command.add_argument("--yes", action="store_true", help="Confirm deletion of the generated build tree")
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
        else:
            result = pipeline.run(ROOT, args.command, online=getattr(args, "online", False) or args.command == "bootstrap")
        print(json.dumps(result, indent=2, sort_keys=True))
    except (SafetyError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; no incomplete stage is published as successful.", file=sys.stderr)
        sys.exit(130)
