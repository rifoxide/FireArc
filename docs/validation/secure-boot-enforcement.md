# Secure Boot enforcement proofs

**Scope:** boot-time qualification of the enforced chain (chain step 3d,
plan items 13 of Phase 2 and Phase 4). The `check-secure-boot` stage
(`just check-secure-boot`) boots the enrolled self-built firmware four
times on QEMU Q35 with one boot payload variable each; every run leaves
its full serial log, QEMU command, flash copy and parsed-store evidence
in the stage directory.

## The four sessions (2026-10-21, all passing)

| Session | Disk payload | Required outcome | Observed |
| --- | --- | --- | --- |
| good | sb-signed loader + sb-signed UKI | boots to the verified sysroot; kernel prints `secureboot: Secure boot enabled` | passed (both markers, no denial) |
| tampered | signed UKI with one `.linux` byte flipped | no guest code executes | refused — payload refusal + `Acc…ess denied` |
| modified | unsigned UKI with a perturbed `.cmdline` byte | no guest code executes | refused — same denial |
| tampered-loader | ESP loader with one byte flipped | firmware refuses the boot manager itself | refused — BDS `Access Denied` |

A negative session passes only when **no kernel execution marker** appears
(EFI stub, `Linux version`, the required boot marker) while the machine
reached an explicit refusal verdict. Denial phrases are matched against
whitespace-normalized serial text: the firmware console wraps lines at VGA
width mid-word (`Acc\r\ness denied`), which once cost three 15-minute
timeouts before the normalization was added.

## Store survival and write confinement (positive session)

- The post-boot flash copy's variable store still carries **exactly the
  enrolled variables** — the payload's default-key auto-enroller did not
  replace or extend our hierarchy (`re_enrolled_defaults: false`).
- Runtime-added variables are ordinary BDS/boot-manager state (`Boot0000`,
  `BootOrder`, `ConOut`, …) — no re-enrolled trust anchors among them.
- Guest writes remain confined to the **SMMSTORE** region; FMAP,
  COREBOOT and BOOTSPLASH are byte-identical after boot.

## Mechanism, stated honestly

Enforcement on this firmware is **db digest anchoring**: the payload's
crypto library stubs certificate verification (`BaseCryptLibMbedTls`
`CryptAuthenticodeVerify` returns FALSE unconditionally — ADR 0007), so
certificate entries in db authorize nothing, while SHA-256 digest entries
authorize the exact images they anchor. Consequences:

- Content integrity is enforced end-to-end: any byte change to loader,
  kernel, initrd or command line changes the digest and is refused
  (sessions 2–4).
- **Same-content signature changes are indistinguishable** — an unsigned
  rebuild with byte-identical content presents the same covered digest,
  and provenance proofs ("signed by the wrong key") are not expressible.
  The gate therefore proves content-tamper refusal, not signer identity;
  the openssl `BaseCryptLib` selection in our own firmware build is the
  tracked fix (firmware/vboot phase, chain step 4).

## In-stage verification (fail-closed)

- The positive run must show both the runtime read-only markers and the
  kernel's `secureboot: Secure boot enabled` line (the in-band proof of
  the `SecureBoot` variable the firmware honors).
- Every negative run must terminate with a refusal verdict within a
  bounded timeout; silence alone is treated as refusal only after the
  bounded wait, and any kernel execution fails the stage.
- Enrolled-store digests are recomputed from the sign-stage outputs at
  ensure time, so re-signed artifacts re-enroll automatically (the
  signature layer is excluded from the anchored digest, but the stage
  tracks the artifact generation regardless).

## Open items (honest)

- **Cold-start/reboot persistence** of the enforcing state across power
  cycles is not yet separately evidenced (the store-survival check covers
  one boot).
- **Unauthorized variable-update refusal** (guest attempts to modify
  PK/KEK/db) is not yet probed.
- dbx carries no revocations (plan Phase 2 item 12).
- Development keys (ADR 0006), QEMU harness, host-anchored verifier
  (ADR 0005): not physical-device or production qualification.
