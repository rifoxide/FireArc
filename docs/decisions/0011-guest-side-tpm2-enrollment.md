# ADR 0011 — Guest-side TPM2 enrollment of the data volume

**Status:** Accepted 2026-10-21 (PLAN Phase 5 item 8).

## Context

Item 6 gave every device a per-device LUKS2 volume unlocked only by its
recovery credential. Item 8 requires TPM2 enrollment via
`systemd-cryptenroll` with **explicit PCR 7 binding** and the **signed
PCR 11 policy** from item 5, validated against the current boot. Two hard
constraints shaped the design:

* **Sealing must see the real boot state.** The token must be sealed
  against the PCR values of an actual measured boot of this exact
  software (PCR 7 = the enrolled Secure Boot variables; PCR 11 = the
  stub's UKI measurements plus the `enter-initrd` phase). A standalone
  swtpm with zeroed PCRs would produce a worthless or dangerous policy,
  so enrollment cannot run host-side against a bare TPM.
* **The signed policy is the update story.** Enrolling with
  `--tpm2-public-key` + `--tpm2-public-key-pcrs` creates a
  PolicyAuthorize: any future UKI signed by the same PCR-policy key
  carries a `.pcrsig` that re-authorizes the *new* measurements without
  re-enrollment (item 11's requirement, by construction).

## Decision

**Enrollment runs inside the booted guest, in the initrd, at the
`enter-initrd` phase; the harness transports the recovery credential on a
one-shot raw disk; every boot probes the unlock and reports its verdict
on the serial contract.**

1. **Tools, not modules**: the `crypt`/`systemd-cryptsetup` dracut
   modules stay omitted (no automatic crypttab path, no prompts). The
   audit (`check-initrd`) instead requires the exact binaries:
   `systemd-cryptenroll`, `systemd-cryptsetup`, `cryptsetup`, the
   `libcryptsetup-token-systemd-tpm2.so` plugin and `dd` (the minimal
   initrd ships cat/od but neither dd nor head/tail; binary-exact
   credential extraction needs dd).
2. **Enrollment unit** (`firearc-data-enroll.service`, in the dev cpio —
   its bytes are part of the measured, signed initrd): gated on the
   one-shot transport (a 512-byte raw IDE disk whose first 32 bytes are
   the `FIREARC-ENROLL-KEY-V1` magic and whose next 32 bytes are the
   credential), it runs
   `systemd-cryptenroll --tpm2-device=/dev/tpmrm0 --tpm2-pcrs=7
   --tpm2-public-key=/.extra/tpm2-pcr-public-key.pem
   --tpm2-public-key-pcrs=11
   --tpm2-signature=/.extra/tpm2-pcr-signature.json
   --unlock-key-file=…`. systemd-stub (257) exposes the UKI's
   `.pcrsig`/`.pcrpkey` in the initrd under `/.extra/` (v254+ layout —
   the older `/.tpm2-*` paths do not exist). The credential file is
   overwritten from urandom and removed after use; it never appears on
   the serial console.
3. **Probe unit** (`firearc-data-probe.service`, required by
   `initrd.target`): on every boot, ordered after the root integrity
   gate (`sysroot.mount`) and `systemd-pcrphase-initrd` — item 10's
   ordering rule encoded from day one — it detects the token and runs a
   real unattended unlock (`systemd-cryptsetup attach … tpm2-device=auto`,
   detach again), reporting `FIREARC_DATA_UNLOCK_OK` / `…_REFUSED` /
   `…_TOKEN_ABSENT` on the console. The sealed region is identity, never
   scratch: the mapping is closed immediately and the per-boot digest
   assertion proves no writes.
4. **Harness op** (`just data-enroll --name devN`, `profile.data_enroll`):
   builds the one-shot transport (0600, scrubbed after the session),
   boots the profile once, requires `ENROLL_OK` **and** `UNLOCK_OK` in
   the same session (the "validate against the current boot" clause),
   then verifies the mutated header host-side: keyslots exactly `["0","1"]`,
   one `systemd-tpm2` token binding keyslot 1, plain PCR set `{7}`,
   signed PCR set `{11}`, SHA-256 bank, and the token's base64 PEM equal
   to `secrets/pcr/pcr.pub` byte for byte. The profile records the new
   region digest, the token inventory and the policy key fingerprint.
5. **Interrupted sessions** are a first-class case: the op sets
   `enroll_pending` before powering on (load tolerates region divergence
   only while it is set); a session that enrolled but failed validation
   leaves the marker, and the next `data-enroll` run adopts the
   host-side-validated token or refuses — never a silent wedge, never a
   silent re-seal.
6. **Temporary credentials**: there are none beyond the recovery
   credential, which is *not* temporary — it is the item-7 escrow
   material and stays as keyslot 0. Removal would destroy escrow
   recovery; item 8's clause is satisfied by never introducing a
   separate throwaway key.

## Consequences

* Proven on real profiles (2026-10-21): dev9 enrolls and unlocks
  unattended across cold boots (`UNLOCK_OK` on the enrollment boot and
  both following boots); dev10 — dev9's disk transplanted onto a fresh
  swtpm identity — boots its verified root but gets `UNLOCK_REFUSED`
  (the item 12 direction, previewed). Full evidence in
  `docs/validation/data-provisioning.md`.
* The token's SRK is ECC; swtpm handles it in seconds — no unlock-time
  penalty observed (unlock completes well within the boot window).
* An update changing the initrd/UKI (including these very units)
  changes PCR 11; the token stays valid only because the new UKI is
  signed by the same PCR-policy key. This compatibility is item 11's
  test matrix, not a claim of this ADR.
* PCR 7 binds the enrolled variable-store state: a firmware re-enroll
  with different db/dbx deliberately breaks unlock (fail closed).
* Production remains different in kind: no interactive operator, no
  interactive TPM, and enrollment at manufacturing under two-person
  control. This ADR is the development-trust-domain form.
