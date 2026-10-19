# Build system

The supported workflow starts from a checkout and public upstream downloads.
No preexisting local images, source checkouts, certificates or keys are inputs.

## Host requirements

- Linux amd64, Python 3.11+, Git, `gpgv`, `unshare` and subordinate UID/GID helpers.
- Docker CLI/daemon accessible to the build user; `just` for the documented commands.
- Unprivileged user, mount, PID and network namespaces, with subordinate mappings.
- Sufficient disk space (allow at least 20 GiB) and HTTPS access to Docker Hub and
  `snapshot.debian.org` during bootstrap/reproduction.
- Checkout paths without commas or control characters (Docker mount syntax).

Host Python/kernel/namespace helpers and Docker remain trusted environmental
dependencies. Their portability/security qualification is distinct from the
locked package closure; `just doctor` reports the host, never installs software.

## Interface

```sh
just bootstrap
just build
just verify-build
```

`bootstrap` is explicit network acquisition. Builds are offline unless `--online`
is deliberately supplied to acquire missing dependencies. `build-tools`,
`build-root`, `build-rootfs`, `check-initrd` and `check-rootfs` resolve dependencies
automatically. `status` reports successful stages. Internal IDs are generated
automatically and are useful only for diagnostics.

Stage fingerprints include source/configuration/lock inputs and dependency
receipts. Only successful stages publish state; stale inputs invalidate it.
Cached manifests and files are checked before reuse. Concurrent build/cleanup
operations are excluded with a checkout-local lock.

## Dependency authentication

`locks/debian-build.json` fixes the Debian amd64 OCI manifest/config digests,
keyring SHA-256, snapshot URL/time, both InRelease/Release/raw-index hashes,
explicit tools package versions and the complete resolved-closure fingerprint.
`locks/root.json` does the same for root package selection.

1. Acquire the exact OCI base from Docker Hub. Its publisher signature is not
   independently verified; the reviewed digest is the bootstrap trust anchor.
2. Copy only the public Debian archive keyring from a never-started container;
   verify its hash against the lock.
3. Download both snapshot InRelease files over HTTPS and verify their Debian
   signatures. Match authenticated Release bytes to their pins.
4. Download compressed indexes using signed sizes/hashes, bound decompression,
   and match the raw indexes to the signed Release and project locks.
5. Run pinned APT planning with an empty status and no network. Check the entire
   selected package-record set against its locked closure fingerprint.
6. Download exactly those package URLs; verify every size and SHA-256 before use.

The immutable snapshot's metadata expiry is explicitly waived, not its signature
or hash authentication. No `trusted=yes` or unauthenticated fallback is used.
The generated package manifests list every exact version, architecture, path,
size and digest. Source/CVE/license review remains a release gate.

## Isolated build and outputs

The tools container is built with no network, no privileged mode and no reused
Docker build layers. Only public staged inputs enter its context. Export copies
public tools/CA paths, not homes, host credentials, device nodes or private keys.
The exported filesystem is inventoried without following symlink targets.

The pinned mkosi 25.3 archive implementation receives a narrow local delta in
`containers/builder/build.sh`: sort tar members by name and give PAX extended
headers stable names. Both expected upstream source fragments must match exactly
once or the builder fails. The modified source is covered by the exported tools
inventory and project fingerprint; the upstream package/version pin is unchanged.

mkosi uses the pinned Debian tools tree under recorded host Python. Image builds
run in rootless namespaces, including a private network namespace, and use
offline repart—not loop devices, host mounts or privileged Docker retries.
Verity and static audit containers have no network, host devices or capabilities.

The immutable ext4 recipe explicitly fixes its public directory-hash seed and
initializes inode tables/journal eagerly. The filesystem UUID and creation epoch
were already fixed; neither alone fixes the directory-hash seed. This setting
applies only to the generic read-only root payload, never to device identities,
LUKS keys, software-TPM state or signatures.

`build/output/` exposes stable aliases to the current immutable payloads.
`build/state.json` and per-stage receipts retain exact identities and hashes.
Logs, generated packages and images stay outside Git.

## Clean test

`just clean --yes` deletes only `build/`, refusing symlinked/mounted cleanup
targets. `just reproduce --yes` performs two empty-project-cache acquisition,
build and validation cycles and compares kernel, initramfs, root tar, ext4,
verity and authority hashes. It fails if any payload differs. The report is
`build/reproducibility.json`; shared Docker content layers are not pruned.

This test currently covers OS build inputs, not firmware, signed envelopes,
provisioned device randomness or the complete secured appliance lifecycle.
