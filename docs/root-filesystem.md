# Root filesystem and verity payloads

`images/rootfs/` defines the offline ext4 payload format. The project build takes
an already-built [appliance root stage](appliance-root.md), freezes its filesystem
bytes, then constructs and fully verifies a separate dm-verity tree.

```sh
just build-rootfs
just check-rootfs
```

The pipeline selects successful dependencies automatically. These commands do not download dependencies unless explicitly requested with `--online`,
activate device-mapper, mount filesystems, provision disks or launch a VM.
They use the existing pinned tools image/tree. Root assembly runs through mkosi
and offline systemd-repart in unprivileged namespaces; verity operates on regular
files in nonprivileged, network-disabled containers.

## Payload contract

- ext4 data image: exactly 4 GiB, all 1,048,576 blocks of 4,096 bytes protected.
- Separate hash image: 128 MiB; SHA-256, format 1, 4,096-byte hash blocks,
  offset zero and **no on-disk verity superblock**.
- Public deterministic salt:
  `SHA256("firearc-root-verity-v1" + NUL + raw_SHA256_of_frozen_ext4)`.
  Salt is not a password or secret.
- `verity-authority.json` records the expected digest, salt and complete geometry.
  The build checks source/output hashes and does not modify root content after
  computing verity. Headerless verification supplies every parameter explicitly.
- The staging GPT exists only to let offline repart build/split the root file.
  It has no ESP/data/A/B slots and must not be mistaken for the installed disk.

The authority JSON is an **unsigned build input**, not an independently trusted
file to read from a mutable partition during boot. Its values must be included in
the signed UKI, and the initramfs must reject absent/malformed authority. Verity
alone does not authenticate this local JSON or encrypt the filesystem.

## Regression checks

`check-rootfs` runs a read-only ext4 consistency check, verifies the good
originals, makes private copies, then
requires integrity denial for a changed final data byte, a changed hash-tree
byte, and a coherent replacement root/tree pair checked against the original
digest. The replacement pair must first pass against its own digest. A final
valid verification and artifact hashes ensure the originals remain unchanged.

Neither a generic nonzero exit nor a permission error counts as a successful
negative test. Tests require the pinned tool's integrity-specific diagnostic and
exit code. Logs and failed copies are retained; there is no overwrite/reset path.

## Remaining integration

This supplies frozen inputs for the [pre-mount dracut gate](initramfs.md). Its
implementation and static/logic tests do not establish a qualified boot path. Still required:
signed slot authority, validated same-disk partition discovery, full verification
before a read-only mapping/mount, no raw-root fallback, bounded failure handling,
and signed systemd-boot/UKI boot tests. Runtime corruption, filesystem/verity
cross-build reproducibility, and A/B activation remain separate acceptance gates.

Results: [appliance root validation](validation/appliance-root.md).
