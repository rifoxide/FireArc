# FireArc

Verified boot and atomic OS updates for an x86-64 appliance. The implementation
contract is [PLAN.md](PLAN.md); current status is [progress](docs/progress.md).

## Build from a checkout

Prerequisites: Linux amd64, Python 3.11+, Git, `gpgv`, Docker with a running daemon,
and working unprivileged user/mount/network namespaces with subordinate UID/GID
mappings. `just` is the command runner. No host packages are installed by builds.

```sh
git clone git@github.com:rifoxide/FireArc.git
cd FireArc
just doctor
just check
just bootstrap       # network: download exact pinned dependencies
just build           # offline: builder, kernel/root/initramfs, ext4 and verity
just verify-build    # static initrd/unit checks and filesystem corruption tests
```

Generated binaries have stable paths under **`build/output/`**:
`kernel.efi`, `initrd.img`, `root.tar`, `root.ext4`, `root.verity`, and
`verity-authority.json`. Dependencies and successful builds are selected
automatically; commands never require manual attempt labels.

Git contains source, configuration and exact version/URL/hash locks—not package
caches, downloaded sources, compiled images, private keys or device state.
`locks/debian-build.json` pins authenticated Debian metadata and the entire tools
dependency closure; `locks/root.json` pins the root closure. Firmware repository
URLs/commits and SDK digest are in `locks/firmware-sources.json`.

## Clean reconstruction and reproducibility

```sh
just clean --yes         # remove only this checkout's generated build/ tree
just bootstrap
just build
just verify-build
just reproduce --yes     # two empty-cache download/build/check rounds + hash comparison
```

`build/reproducibility.json` records the two-round result. Docker's shared,
content-addressed image/layer store is not globally pruned; package caches and
project outputs are redownloaded/rebuilt, and tools builds disable layer reuse.
See [build instructions](docs/builder.md) for trust and environment boundaries.

**The current outputs are unsigned build inputs, not a deployable appliance.**
Firmware builds, signed systemd-boot/UKIs, installed A/B layout, TPM-bound LUKS2,
RAUC activation/rollback, recovery and hardware acceptance remain pending.

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

Useful commands: `just status`, `just build-tools`, `just build-root`,
`just build-rootfs`, `just check-initrd`, `just check-rootfs`.

## Documentation

- [Development](docs/development.md), [build system](docs/builder.md)
- [Requirements](docs/requirements.md), [threat model](docs/threat-model.md)
- [Root image](docs/appliance-root.md), [verity](docs/root-filesystem.md), [initramfs](docs/initramfs.md)
- [Decisions](docs/decisions/README.md), [risks](docs/risks.md), [validation](docs/validation/README.md)
