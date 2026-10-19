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
is retained in `build/reproducibility.json`.

Commands: [build system](../builder.md). Machine-readable results are generated
under ignored `build/`; `build/reproducibility.json` contains the clean comparison.
Firmware/signing/device-lifecycle qualification is outside this build test.
