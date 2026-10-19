# FireArc

QEMU-first development of FireArc's verified boot chain and atomic OS updates.
The authoritative scope and implementation gates are in [PLAN.md](PLAN.md).

## Current milestone

Phase 0 / Phase 1 foundation: requirement traceability, locked research inputs,
offline safety tests, an independent headless EXP-029 regression harness, and a
signed-snapshot, offline/rootless mkosi builder smoke test.

**This is not yet the final appliance.** The reusable research fixture boots a
signed UKI directly and powers off after verifying its Debian root. It does not
implement systemd-boot, bootable appliance mkosi builds, encrypted data, RAUC
updates or attestation. The separate mkosi smoke output is nonbootable/unsigned.
See [progress](docs/progress.md) for actual results and remaining gates.

## Safe local checks

Requires Linux, Python 3.11+ and Git; `just` is an optional command wrapper.
The tests use only the Python standard library and synthetic disposable inputs.

```sh
just doctor
just check
# Without just:
python3 -B scripts/firearc.py --help
python3 -B -m unittest discover -s tests -v
```

These commands do not install packages, generate keys, launch VMs or access the
old project's private credentials. `doctor` reports missing future build tools;
the local QEMU binary pins are compatibility checks, not a portable build lock.

## Reproduce the research boot

The approved local research checkout supplies **public artifacts**, not keys:

```sh
just research-verify /home/rifat/projects/project_firearc
just baseline-import /home/rifat/projects/project_firearc
just baseline-new baseline-a
just baseline-run baseline-a --label good-a
just baseline-run baseline-a --label good-b
```

Import first verifies all files in five pinned historical manifests and checks
the nine source checkouts. It copies only 13 allowlisted public runtime/metadata
files into ignored `artifacts/research/exp-029/`. No old script is executed, and
the reference project is never a writable QEMU disk or firmware backing file.
Subsequent boots use only the imported files in this repository.

Each explicit `baseline-new` creates its own flash and root/hash overlays.
`baseline-run` **requires an existing device** and preserves its flash/disks.
Existing imports, device names and evidence labels cannot be overwritten.

Optional software-TPM attachment and corruption controls are documented in
[the laboratory runbook](docs/lab.md). Automated serial evidence contains only
this locked-root research self-test, not a support login or recovery session.

## Security and implementation rules

- No production or research private signing keys in Git, builds or imports.
- `run/` includes private per-VM TPM state; never publish or commit it.
- No host block-device writes, host TPM passthrough, host mounts or external VM
  networking are used by this milestone.
- No silent resets, re-enrollment or formatting after a failed boot.
- Do not bypass a hash mismatch to make a demonstration succeed.
- Production trust, firmware-root protection and physical hardware results are
  separate gates, not implied by QEMU success.
- `just secrets` screens known credential patterns; it cannot prove that every
  possible secret is absent. Review every publication.
- Git commit signing is temporarily deferred by the owner (ADR 0004). Boot/update
  signing and production key custody remain required. This milestone does not
  generate a Git signing key or change global Git settings.

## Documents

- [Requirements](docs/requirements.md) and [threat model](docs/threat-model.md)
- [Research reuse inventory](docs/reuse-inventory.md)
- [Decisions](docs/decisions/README.md) and [risk register](docs/risks.md)
- [Laboratory runbook](docs/lab.md) and [progress](docs/progress.md)
- [Development builder](docs/builder.md) and [builder results](docs/experiments/EXP-002-builder-smoke.md)
