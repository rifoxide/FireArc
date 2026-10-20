# Build-system validation

## Acceptance contract

- A checkout must acquire public pinned inputs without another workspace or
  committed downloads/binaries.
- Both Debian repository signatures and index/package size/hash authority must
  pass. Exact closure fingerprints must match.
- Builds must run offline with the documented namespace/container boundaries.
- Failed or stale stages must not become current successful dependencies.
- Commands must not require manual labels or build-directory knowledge.
- Clean reconstruction and byte-identical payload checks are separate results.

## Current verification

Fresh public metadata acquisition passed signature/hash checks. `just bootstrap`
resolved the exact locked tools/root closures (231 and 170 packages), and the
label-free `just build` and `just verify-build` completed successfully.

An isolated local Git clone of the source-only working snapshot passed all 67
offline tests. Its fresh upstream acquisition/build/verification also passed.

### Byte reproducibility: PASS (2026-10-20)

`just reproduce --yes` completed two full empty-cache download/build/verification
rounds. All six payload hashes — kernel, initramfs, root tar, ext4, verity tree
and verity authority — are byte-identical between rounds. The machine-readable
record is `build/reproducibility.json` (`passed: true`, one host/Python).

Earlier rounds had failed with differing ext4/verity/authority (and a differing
root tar in the separate clone). Successful reconstruction and component checks
alone do not establish reproducibility; this comparison does, within its scope.

Scope limits: single host, single Python, shared Docker content cache preserved,
and only the OS build payloads above. Firmware, signed envelopes, device
provisioning randomness and cross-host reproduction remain unproven.

### Reproducibility diagnosis and fix

Comparing every root tar member's content and metadata found no differences
between the main and separate-clone archives; only enumeration order differed.
The pinned mkosi tar command did not request sorting. A fail-closed local delta
now supplies name sorting and stable PAX header names.

`dumpe2fs -h` on both ext4 images showed identical UUID/geometry/creation times
but different directory-hash seeds. The rootfs recipe now explicitly fixes that
public seed and requests eager inode-table/journal initialization.

After both fixes, the two clean rounds above passed byte-identical; all 69
offline tests pass and `just verify-build` passes with the patched builder.

Commands: [build system](../builder.md). Machine-readable results are generated
under ignored `build/`; `build/reproducibility.json` contains the clean comparison.
Firmware/signing/device-lifecycle qualification is outside this build test.
