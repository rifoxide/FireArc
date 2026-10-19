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

The main checkout completed both empty-cache download/build/verification rounds,
but **byte reproducibility failed**: kernel, initramfs and root tar matched;
ext4, verity and authority hashes differed. The separate clone also produced a
different root tar. The cause is not yet diagnosed. Successful reconstruction
and component checks do not establish reproducibility. The generated comparison
is retained in `build/reproducibility.json` until the next clean run replaces it.

### Reproducibility diagnosis and fix under test

Comparing every root tar member's content and metadata found no differences
between the main and separate-clone archives; only enumeration order differed.
The pinned mkosi tar command did not request sorting. A fail-closed local delta
now supplies name sorting and stable PAX header names.

`dumpe2fs -h` on both ext4 images showed identical UUID/geometry/creation times
but different directory-hash seeds. The rootfs recipe now explicitly fixes that
public seed and requests eager inode-table/journal initialization. A new clean
comparison must pass before the byte-reproducibility failure is considered fixed.
The patched builder/root/rootfs and static initrd/corruption checks pass through
`just verify-build`; all 69 offline tests pass. The clean comparison is running.

Commands: [build system](../builder.md). Machine-readable results are generated
under ignored `build/`; `build/reproducibility.json` contains the clean comparison.
Firmware/signing/device-lifecycle qualification is outside this build test.
