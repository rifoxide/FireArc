# ADR 0006 — development key hierarchy for the secure boot chain

**Status:** Accepted 2026-10-20 (Phase 2, plan items 8/9/11; owner priority
"signed UKI" for the current goal).

## Context

The enforced secure boot chain needs a signing identity before anything can
be signed, rejected or enrolled: `SecureBoot=1` requires a PK in the
variable store; db must authorize the systemd-boot and UKI signatures. The
plan requires the hierarchy to live outside source and build trees, survive
`just clean`, never enter Git, and expose only public certificates to
firmware builds and only the required private key to an isolated signing
step. Production custody is a separate, still-open decision (plan item 10).

## Decision

**A three-role development hierarchy, generated once on this host inside the
pinned tools container** (OpenSSL 3.5.7, sbsigntool 0.9.4 from the pinned
Debian snapshot — no host tools touch key material):

| Role | Credential | Purpose |
| --- | --- | --- |
| UEFI PK | `pk.key` / `pk.crt` | variable-store anchor; authorizes KEK updates |
| UEFI KEK | `kek.key` / `kek.crt` | authorizes db updates |
| EFI image signing | `sb.key` / `sb.crt` | signs systemd-boot and the UKI; its certificate is the db content |

Certificates are self-signed RSA-3072 / SHA-256, `digitalSignature` key
usage, `codeSigning` EKU on the signing certificate only, fixed subjects,
serial 1, ten development years. No separate db key exists: **db carries the
signing certificate** (`db.esl` = `sb.crt`), so image verification is one
exact certificate match.

Authenticated variable payloads follow the UEFI time-based format and the
standard chain — `pk.auth` signed by the (new) PK itself, `kek.auth` by the
PK, `db.auth` by the KEK — so the same files serve any enrollment mechanism
(offline variable-store surgery, `efi-updatevar`, or a first-party
enrollment application).

**Custody (development only):** everything lives under gitignored `secrets/`
at the checkout root — mode 0700/0600, outside `src/` and `build/` so the
project digest and `just clean` never touch it, and the repository secrets
scan refuses that tree by name. Nothing is committed. Public fingerprints
are recorded below because they are public information once devices are
enrolled; private keys never leave the tree.

Generated 2026-10-20 (SHA-256 certificate fingerprints):

```
pk  25689aeb24cc7c55f36a506311e065da60675feb88da825f2f5bdf0e879f308b
kek d024bfdac4a255b1642f05c7725374b1350949fbc10b144335440e52939309cb
sb  a53c55f29155cee65c7252913b40749a6e8c9279ade37b5fbc62cae900d30044
```

**Trust domains stay separate:** these credentials authorize nothing outside
this development environment. Production credentials require the
offline-root/HSM/two-person ceremony of plan item 10 and never derive from
these keys.

**Role slots beyond the three generated ones** (defined now, generated when
their phases open): firmware authorization (vboot RW regions, Phase 2 item
6), RAUC bundle signing (Phase 6), PCR-policy signing (Phase 5), recovery
authorization (Phase 9), and per-device CA/attestation identity (Phase 5/8).

## Consequences

- Regenerating the hierarchy invalidates every enrolled device profile;
  rotation means re-enrollment, and dev rotation is acceptable by design.
- A compromised build host compromises these keys — accepted, because the
  documented QEMU threat model already trusts the host (ADR 0005). This is
  not a production-custody claim.
- The signing step (next) mounts **only `sb.key`/`sb.crt`**; firmware/build
  stages see **only public certificates**. `just keys` is idempotent and
  fails closed on partial hierarchies, deleting a failed generation attempt.
