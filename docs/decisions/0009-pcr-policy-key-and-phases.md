# ADR 0009 — PCR-policy signing key, phase selection and the measurement model

**Status:** Accepted 2026-10-21 (PLAN Phase 5 item 5).

## Context

Phase 5 binds future LUKS2 data unlock to the platform's measured state:
item 5 requires per-release signed PCR 11 authorizations for the UKIs and
the exact data-unlock phase, with the PCR-policy signer kept separate from
the db signer. Before this ADR the groundwork (items 1–4,
`docs/validation/tpm-measurements.md`) had established the binding surface
(PCR 7 + 11; never firmware identity or signature presence) but nothing
signed anything, and two facts made naive adoption impossible to trust
blindly:

* The observed PCR 11 event log carries **two events per UKI section**
  (the section *name* hash, then the content hash), `.pcrpkey` **is**
  measured while `.pcrsig` is exempt, sections are measured at PE
  `VirtualSize` (not `SizeOfRawData`), and the initrd legitimately ends
  with padding zeros — every one of these details changes the value a
  policy must pin.
* `systemd-pcrphase-initrd.service` runs in the (systemd-based dracut)
  initrd and measures `enter-initrd` through `/dev/tpmrm0` — an extend
  that never appears in the firmware TCG2 event log, so log replay alone
  under-reports the real PCR state.

## Decision

**A dedicated PCR-policy key role, an `enter-initrd`-only phase set, and a
from-first-principles measurement model as a stage gate.**

1. **Key role** (`just pcr-keys`, `secrets/pcr/`): one development RSA-3072
   pair, generated under the ADR 0006 custody rules (isolated container,
   no network, no build tree). It is deliberately distinct from the sb/db
   image-signing role; neither key ever enters the other's signing
   container. The public half is stored and embedded as a **bare PEM
   public key**, because the pinned systemd-measure 257.13 rejects
   certificates passed to `--public-key=`. The manifest records `pkfp` —
   SHA-256 over the raw `RSAPublicKey` DER — the exact fingerprint
   systemd-measure writes into every `.pcrsig` entry.
2. **Signature scheme**: RSASSA-PKCS1-v1_5 with SHA-256, which is
   deterministic. Unlike the sbsign layer (which embeds a signing time and
   is honestly non-reproducible), the PCR-carrying UKI is
   byte-reproducible, and the `pcr-sign` stage enforces a byte-identical
   double build.
3. **Phase set**: `enter-initrd` only. It is measured by
   systemd-pcrphase-initrd early in the initrd — before the verity gate
   and before any future unlock (items 8–10) — so authorizing it means
   exactly "unlock after the initrd barrier, on this UKI content". Later
   phases (`sysinit`, `ready`) are deliberately not signed: unlock must
   not be authorized after switch_root, and signing more states would
   only weaken the policy. When the unlock ordering is designed (item 10),
   this constant — not the key — is what moves.
4. **Stage gate** (`just pcr-sign`): ukify rebuilds the UKI from the uki
   stage's receipt-covered section inputs with `--pcr-banks=sha256
   --pcr-private-key --pcr-public-key --phases=enter-initrd`, adding
   `.pcrsig` and `.pcrpkey`. The stage then fails closed unless
   **four independent computations agree**: the from-spec model of the
   stub's measurement behavior (`pcr_sign.expected_pcr11`: name+NUL hash,
   VirtualSize-exact content hash, systemd's section-table order,
   `.pcrsig` exempt, `.pcrpkey` measured, phase words without NUL), the
   pinned systemd-measure's own prediction over the same inputs, the
   TPM2-spec PolicyPCR digest recomputed from the marshalled forms
   (`pcr_sign.policy_pcr_digest`), and the openssl verification of the
   embedded signature over that policy digest with the embedded public
   key. Downstream, `sign` signs this PCR-carrying UKI (so Secure Boot's
   db anchor covers the policy sections too) and refuses unsigned-of-PCR
   input.
5. **Publication**: `uki-a.efi` (unsigned, no policy) and
   `uki-a-pcr.efi` (policy-carrying, SB-unsigned) stay separate artifacts;
   the reproducibility comparison covers both (both are deterministic).

## Consequences

* Regenerating the PCR key changes PCR 11 (`.pcrpkey` is measured), but
  the fingerprint cascade restages `pcr-sign` → `sign` → `enroll` →
  `device` and the boot gates automatically — there is no manual step to
  forget.
* Only the slot-A UKI exists today; slot B will reuse this stage
  verbatim when the update phase arrives.
* The validation is log-derived, not a TPM quote (Phase 8); the
  boot-time proof compares replay + phase-extend against the signed
  value (`docs/validation/pcr-authorizations.md`).
* Production PCR-policy custody and rotation remain open (Phase 2
  item 10), exactly as for the SB and vboot hierarchies.
