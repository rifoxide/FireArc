# FireArc

Verified boot and atomic OS updates for an x86-64 appliance. The implementation
contract is [PLAN.md](PLAN.md); current status is [progress](docs/progress.md).

**Current scope: the enforced secure boot chain and Phase 5 TPM-bound data.**
The development chain reaches a verified read-only root and mounts encrypted
`/data` after TPM unlock. Escrow and the full refusal matrix remain open;
Phases 6–13 (updates, cloud and product services) remain deferred. See
[PLAN §1.3](PLAN.md) and the [validation records](docs/validation/README.md).
These are development credentials and QEMU proofs, not a production release.

## Build from a checkout

Prerequisites: Linux amd64, Python 3.11+, Git, `gpgv`, Docker with a running daemon,
and working unprivileged user/mount/network namespaces with subordinate UID/GID
mappings. `just` is the command runner. No host packages are installed by builds.

```sh
git clone git@github.com:rifoxide/FireArc.git
cd FireArc
just doctor
just check
just bootstrap       # network: download exact pinned Debian dependencies
just firmware-sources --online
just keys            # generate/reuse the development EFI signing hierarchy
just vboot-keys      # separate firmware-signing identity
just pcr-keys        # separate PCR-policy-signing identity
just build           # offline: kernel/root/initramfs, verity and signed UKI
just verify-build    # static initrd/unit checks and filesystem corruption tests
```

Generated binaries have stable paths under **`build/output/`**:
`kernel.efi`, `initrd.img`, `root.tar`, `root.ext4`, `root.verity`,
`verity-authority.json`, `uki-a.efi`, `uki-a-pcr.efi`, `uki-a-signed.efi`,
and `sbom.json`. Dependencies and successful builds
are selected automatically; commands never require manual attempt labels.

Git contains source, configuration and exact version/URL/hash locks—not package
caches, downloaded sources, compiled images, private keys or device state.
`locks/debian-build.json` pins authenticated Debian metadata and the entire tools
dependency closure; `locks/root.json` pins the root closure. Firmware repository
URLs/commits and SDK digest are in `locks/firmware-sources.json`.

## Boot directly into a Debian root shell

```sh
# If the Docker daemon is stopped:
sudo systemctl start docker
just shell
```

This explicitly builds a **separate signed development image** and boots Bash
as root inside the verified Debian filesystem. The root remains read-only;
`/run` and `/tmp` are writable temporary storage. The VM has a fresh TPM and
unprovisioned `/data`: it never opens or changes your saved device profiles.
Disk and firmware writes go into disposable QEMU overlays.

Type `exit` to power off, or **Ctrl+A, then X** to quit QEMU. If the firmware
menu waits, press Enter. The first run may need a few minutes to build the shell
image from the already acquired pinned inputs. No shell is enabled in normal
boot images. This is a development chroot console with initrd PID 1, not yet a
full appliance switch-root/service boot. See
[development shell validation](docs/validation/development-shell.md).

## Clean reconstruction and reproducibility

```sh
just clean --yes         # remove only this checkout's generated build/ tree
just bootstrap
just build
just verify-build
just reproduce --yes     # two empty-cache download/build/check rounds + hash comparison
```

**`clean` and `reproduce` delete saved devices under `build/devices/`, including
model disks, per-device recovery keys and TPM state.** Only use them when that
loss is intended. For ordinary cleanup use `just prune`, which preserves devices,
snapshots, current outputs, validation evidence and signing keys.

`build/reproducibility.json` records the two-round result. Docker's shared,
content-addressed image/layer store is not globally pruned; package caches and
project outputs are redownloaded/rebuilt, and tools builds disable layer reuse.
See [build instructions](docs/builder.md) for trust and environment boundaries.

**Current outputs are development build artifacts, not a deployable appliance.**
Signed firmware/systemd-boot/UKIs, verity and TPM-bound LUKS2 are implemented in
the development harness. Production custody, hardware acceptance, complete A/B
updates, rollback and approved recovery remain pending.

## Layout

| Path | Purpose |
| --- | --- |
| `src/firearc/` | Dependency acquisition, build pipeline and validation code |
| `images/` | Root image, initramfs module and filesystem recipes |
| `containers/builder/` | Digest-pinned Debian tools environment |
| `locks/` | Specification, upstream versions, metadata and dependency pins |
| `tests/` | Offline safety, pipeline and component tests |
| `docs/` | Requirements, decisions, design and component validation |
| `build/` | Ignored downloads, logs, state and generated binaries |

## Commands

| Task | Command |
| --- | --- |
| Build / audit / interactive console | `just build`, `just verify-build`, `just shell` |
| Run offline checks | `just check` |
| Qualify the boot chain | `just check-boot`, `just check-secure-boot`, `just check-firmware-vboot` |
| Provision and enroll data | `just device-provision --name dev1`, `just data-enroll --name dev1` |
| Cold boot a saved device | `just device-boot --name dev1 --count 2` |
| Inspect / safely reclaim obsolete output | `just status`, `just prune` |
| Build one intermediate stage | `just stage rootfs` |

`just --list` shows the supported recipes. The [command reference](docs/commands.md)
covers all stages, device lifecycle operations and migration from the old
per-stage commands. `scripts/firearc.py` is the single executable entry point.

## Documentation

- [Commands](docs/commands.md), [development](docs/development.md), [build system](docs/builder.md)
- [Boot-chain guide](docs/bootchain-guide.html) (self-contained HTML)
- [Requirements](docs/requirements.md), [threat model](docs/threat-model.md)
- [Root image](docs/appliance-root.md), [verity](docs/root-filesystem.md), [initramfs](docs/initramfs.md)
- [Decisions](docs/decisions/README.md), [risks](docs/risks.md), [validation](docs/validation/README.md)
