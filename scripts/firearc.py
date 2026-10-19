#!/usr/bin/env python3
"""FireArc's explicit, offline-first laboratory workflows. Run --help first."""

import argparse
import json
from pathlib import Path
import signal
import subprocess
import sys

sys.dont_write_bytecode = True

from firearc_lib import baseline, builder
from firearc_lib.host import doctor, scan_repository
from firearc_lib.inputs import import_baseline, validate_locks, verify_reference
from firearc_lib.integrity import SafetyError

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "verify-inputs", "secrets"):
        commands.add_parser(name)
    for name in ("research-verify", "baseline-import"):
        command = commands.add_parser(name)
        command.add_argument("--reference", type=Path, required=True)
    command = commands.add_parser("builder-import-metadata", help="Import and authenticate public Debian snapshot metadata")
    command.add_argument("--reference", type=Path, required=True)
    for name in ("builder-plan", "builder-fetch", "builder-build", "builder-export"):
        command = commands.add_parser(name)
        command.add_argument("--label", required=True)
        if name in {"builder-plan", "builder-fetch"}:
            command.add_argument("--allow-network", action="store_true", help="Explicitly allow pinned base/package acquisition")
        if name == "builder-export":
            command.add_argument("--resume-export", help="Finish a recorded, fully copied export without rebuilding or recopying")
    for name in ("image-summary", "image-smoke"):
        command = commands.add_parser(name)
        command.add_argument("--tools", required=True)
        command.add_argument("--label", required=True)
    command = commands.add_parser("baseline-new", help="Explicitly create a new EXP-029 fixture; never overwrite")
    command.add_argument("device")
    command.add_argument("--tpm", action="store_true", help="Attach isolated persistent swtpm, not the host TPM")
    command = commands.add_parser("baseline-run", help="Boot an existing fixture without resetting its state")
    command.add_argument("device")
    command.add_argument("--label", required=True, help="New evidence label; existing labels cannot be replaced")
    command.add_argument("--scenario", choices=baseline.SCENARIOS, default="good")
    command.add_argument("--timeout", type=int, default=180)
    command = commands.add_parser("baseline-control")
    command.add_argument("device")
    command.add_argument("operation", choices=("status", "reboot", "stop", "powercut"))
    args = parser.parse_args()
    if args.command == "doctor":
        result = doctor(ROOT)
    elif args.command == "verify-inputs":
        validate_locks(ROOT)
        builder.lock(ROOT)
        result = {"passed": True, "scope": "Specification hash and input-lock structure; no build/security qualification"}
    elif args.command == "secrets":
        result = scan_repository(ROOT)
    elif args.command == "research-verify":
        result = verify_reference(ROOT, args.reference)
    elif args.command == "baseline-import":
        result = import_baseline(ROOT, args.reference)
    elif args.command == "baseline-new":
        result = baseline.new_device(ROOT, args.device, tpm=args.tpm)
    elif args.command == "baseline-run":
        result = baseline.run_device(ROOT, args.device, label=args.label, scenario=args.scenario, timeout=args.timeout)
    elif args.command == "builder-import-metadata":
        result = builder.import_metadata(ROOT, args.reference)
    elif args.command == "builder-plan":
        result = builder.plan_tools(ROOT, args.label, allow_network=args.allow_network)
    elif args.command == "builder-fetch":
        result = builder.fetch_tools(ROOT, args.label, allow_network=args.allow_network)
    elif args.command == "builder-build":
        result = builder.build_tools(ROOT, args.label)
    elif args.command == "builder-export":
        result = builder.export_tools(ROOT, args.label, resume_export=args.resume_export)
    elif args.command in {"image-summary", "image-smoke"}:
        result = builder.smoke_image(ROOT, args.tools, args.label, build=args.command == "image-smoke")
    else:
        result = baseline.control_device(ROOT, args.device, args.operation)
    print(json.dumps(result, indent=2, sort_keys=True))


def interrupted(signum, frame):
    raise KeyboardInterrupt("Interrupted; owned child processes will be stopped")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (SafetyError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; inspect the retained evidence before retrying.", file=sys.stderr)
        sys.exit(130)
