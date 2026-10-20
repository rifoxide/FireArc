# ADR 0007 — offline variable-store enrollment for the device firmware

**Status:** Accepted 2026-10-21 (Phase 2, plan item 12; chain step 3c of the
current goal).

## Context

Signing the boot artifacts is inert until the firmware trusts the signing
certificate: enforcement needs PK/KEK/db in the UEFI variable store and a
`SecureBoot` variable set to 1. The firmware image is a monolithic coreboot
ROM whose SMMSTORE FMAP region carries the variable store (ADR 0005's
layout); there is no OVMF-style CODE/VARS split, no built-in headless
enrollment application, and the plan requires headless, evidence-producing
enrollment — no interactive firmware menu. The alternatives were (a) a
guest-side enrollment application built from the pinned EDK II sources and
run once per device inside a booted guest, or (b) offline construction of
the variable store directly into the flash image on the build host.

Three facts from the pinned sources and real boots decided the question:

1. The store format is exactly the pinned EDK II `VariableFormat.h`:
   a 72-byte `gEfiSystemNvDataFvGuid` firmware-volume header (checksum
   summing to zero), a 28-byte authenticated variable-store header
   (`gEfiAuthenticatedVariableGuid`, FORMATTED/HEALTHY), and 60-byte packed
   `AUTHENTICATED_VARIABLE_HEADER` entries with 4-byte entry alignment and
   `ALIGNMENT 1` (no name/data padding). The payload sizes the variable
   store at 64 KiB (`PcdVariableStoreSize`) inside the 256 KiB region.
2. Stored variables are not re-verified when read: `GetVariable` serves the
   store directly, and the pinned `DxeImageVerificationLib` gates all image
   verification solely on the `SecureBoot` global variable (skip if absent
   or 0). Nothing in this payload writes `SecureBoot` at boot, and the
   payload-initialized stores of real boots confirm it is never created.
3. Authenticated-variable descriptors (`.auth` payloads) are consumed at
   *write* time only, so offline surgery writes the ESL payloads and the
   entry timestamps directly; the pinned `AuthVariableLib` uses `certdb`
   only for variables other than PK/KEK/db/dbx, so no certificate-database
   entries are needed.

## Decision

**Offline construction (option b): the `enroll` pipeline stage (`just
enroll`) builds the entire variable store host-side and splices it into the
erased SMMSTORE region of the verified firmware-build ROM**, producing
`enrolled.rom` as a first-class artifact. The store carries the development
hierarchy's ESLs (PK, KEK in `gEfiGlobalVariableGuid`; db in
`gEfiImageSecurityDatabaseGuid`), the payload's empty `certdb`, and the two
mode variables that gate enforcement and update policy — `SecureBoot=1`,
`SetupMode=0`.

The stage fails closed on every assumption: the pristine region must be
fully erased (existing variables are never overwritten), construction must
be byte-deterministic (double build), the store must re-parse to exactly the
intended variables, and every byte outside the region, the flash map and the
image size must be unchanged. Enrollment restages automatically whenever the
generated hierarchy payloads change (they are stage inputs).

This stays honest about what it is not: no boot is executed here, so
enforcement and rejection behavior are proven separately (step 3d); the
dbx policy remains open (plan item 12); and the timestamps reuse the
generated `.auth` payloads, so future guest-side authenticated updates must
carry later timestamps.

## Observed consequence worth recording

Starting from an erased store, this firmware **auto-enrolls its own default
PK/KEK/db/dbx** (observed in every pristine-start boot's post-run flash
copy; ~46 KiB including a 19,976-byte dbx). Those defaults are not our
trust anchors, and enforcement never ran against them (`SecureBoot` absent
— which is also why our development-signed artifacts kept booting). The
enrolled image replaces them wholesale: the store is constructed, not
patched, so no authorization root we did not install survives. Whether the
payload's auto-enroller stays dormant when a store already carries a PK is
a boot-time behavior the step-3d proofs will evidence.
