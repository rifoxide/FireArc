# Commands

`just --list` is the supported command surface. `scripts/firearc.py` is the only
executable project entry point; the justfile forwards to its tested CLI.
Build stages resolve verified dependencies automatically. Never invent a build
label, edit a success receipt, or bypass a failed integrity check.

## Everyday workflow

```sh
just doctor
just check
just bootstrap                    # explicit pinned Debian acquisition
just firmware-sources --online    # explicit pinned firmware acquisition
just keys                         # development EFI hierarchy, once
just vboot-keys                   # separate vboot role, once
just pcr-keys                     # separate PCR-policy role, once
just build                        # offline normal signed OS artifacts
just verify-build
just shell                        # disposable root console, not a saved device
```

Keys are reused after validation, never silently regenerated. A running Docker
daemon is required by builds. On a systemd Docker host, start it with
`sudo systemctl start docker` if needed. Network acquisition is confined to
`bootstrap` and explicitly online firmware acquisition (plus the explicitly
confirmed two-round reproduction experiment); build/audit/stage commands do
not accept `--online`. Firmware acquisition also checks/acquires the pinned
coreboot SDK, even when its source checkout is already cached.

The [shell](validation/development-shell.md) opens Bash as UID 0 inside the
verified read-only Debian root. `/run` and `/tmp` are temporary and `/data` is
unprovisioned. Saved devices and their credentials are not attached. Type `exit`
to power off or Ctrl+A, then X to quit QEMU. This replaces the old standalone
`boot-live` runner; it is not a console on an enrolled saved device.

## Independent boot gates

```sh
just check-boot
just check-secure-boot
just check-firmware-vboot
```

These retain their independent positive/negative controls. `verify-build`
performs static and filesystem audits; it is not a substitute for boot gates.

## Saved devices

```sh
just device-provision --name dev1
just data-enroll --name dev1
just device-boot --name dev1 --count 2
just device-reboot --name dev1 --resets 2
just device-stop --name dev1
just device-powercut --name dev1
just device-snapshot --name dev1 --label baseline
just device-restore --name dev1 --label baseline
```

`device-provision --replace` and `device-restore` explicitly discard or rewind
state. `device-powercut` deliberately kills the VM/TPM. These operations are not
aliases for ordinary boot and remain separate commands. Recovery custody is
still an owner decision; no production escrow claim is implied.

## One maintainer entry point for stages

Use `just stage <name>` only when an intermediate artifact/audit is wanted.
Ordinary `build`, shell and device commands select their dependencies themselves.

| Former command | Current command |
| --- | --- |
| `just build-tools` | `just stage tools` |
| `just build-root` | `just stage root` |
| `just build-rootfs` | `just stage rootfs` |
| `just check-initrd` | `just stage check-initrd` |
| `just check-rootfs` | `just stage check-rootfs` |
| `just sbom` | `just stage sbom` |
| `just firmware-build` | `just stage firmware-build` |
| `just firmware-layout` | `just stage firmware-layout` |
| `just futility` | `just stage futility` |
| `just firmware-sign` | `just stage firmware-sign` |
| `just uki` | `just stage uki` |
| `just pcr-sign` | `just stage pcr-sign` |
| `just sign` | `just stage sign` |
| `just enroll` | `just stage enroll` |
| `just device` | `just stage device` |

The old standalone `test`, `verify-inputs` and `secrets` recipes are consolidated
into `just check`, which runs all three checks. Their underlying validation code
is retained. Dated ADRs and validation records retain their historical command
spelling; use this table when reproducing them. The CLI lists accepted stages:

```sh
python3 -B scripts/firearc.py stage --help
```

## Inspect and clean

```sh
just status
just prune                    # safe routine cleanup
just prune --keep 1           # retain one additional generation per stage
```

Pruning preserves current outputs, pinned downloads, saved profiles/snapshots
and profile-pinned disk/firmware generations. For completed boot checks, it
verifies successful receipts before removing only unpublished `device-*.raw`
working copies. Logs, serial evidence, flash variants and receipts remain.
Published, failed/incomplete current checks and symlinked scratch files are not
authorization to delete data. Scratch symlinks or tampered receipts fail closed.

**Destructive full reset / reproduction:**

```sh
just clean --yes
just reproduce --yes
```

Both erase `build/`, including **all saved device data, per-device recovery
credentials and TPM state**. They preserve source and the development signing
identities under `secrets/`. Use `prune` instead unless that loss is intended.
Reproduction is an explicit two-round acquisition/build/check experiment, not
an ordinary offline build or a generic machine-wide Docker cleanup.
