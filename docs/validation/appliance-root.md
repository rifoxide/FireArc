# Root and initramfs validation

## Required checks

- Locked root account, unprovisioned machine identity and exact installed packages.
- Required kernel features, kernel/initramfs/EFI inputs and aligned systemd tools.
- Exact embedded gate code/units, executable entry point, required mount/default
  target links, forbidden-module omissions, no-shell/generator masks and no
  authority in a generic initrd.
- Pinned systemd verification of unpacked units, without starting them.
- Fixed-size ext4 consistency, full-range headerless verity verification, changed
  data/tree rejection and coherent replacement-pair rejection under original
  authority. Good originals must still verify and match their input hashes.

Offline unit tests execute the actual shell parser with synthetic device/tool
backends: missing/duplicate/malformed authority, inconsistent slot/cmdline,
ambiguous devices, wrong disk/size/ESP, preexisting mapping, failed verification/
open, and writable-mapping cleanup are covered without host device access.

## Results

The restructured project passed these checks through `just verify-build`.
The clean-clone and both repeated-download builds also passed component checks;
their payload reproducibility comparison failed (see [build validation](build-system.md)).
Per-stage result/command/log files and verified receipts are retained under
`build/`, with stable binary aliases under `build/output/`.

These checks do not prove a signed boot, trusted EFI handoff, actual unit timing,
runtime dm-verity enforcement, watchdog/fallback, TPM data policy or hardware
security. Generic authority is absent until slot-specific signed UKI assembly.
G3/G4 remain open until actual positive/negative boot tests pass.

See [root image](../appliance-root.md), [filesystem/verity](../root-filesystem.md)
and [initramfs](../initramfs.md) for component contracts.
