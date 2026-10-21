# PCR 11 policy signing validation (Phase 5 item 5)

## Scope

`just pcr-sign` (ADR 0009) embeds signed PCR 11 authorizations (`.pcrsig`)
and the PCR-policy public key (`.pcrpkey`) into the slot-A UKI. This
document records why the signed value is the value the platform actually
measures, and what is honestly not claimed. All evidence is the pinned
toolchain (systemd 257.13-1~deb13u1, openssl 3.5.7) on this development
host, inside the development trust domain (ADR 0005/0008).

## The measurement model, established from platform evidence

The model `src/firearc/pcr_sign.py` implements was derived from the pinned
sources (`src/boot/stub.c` measure_sections, `src/fundamental/uki.h`,
`src/measure/measure.c` of 257.13-1~deb13u1) and validated against the
dev5 boot evidence (event-log dump + replay in `tpm_evidence.py`):

* Per UKI section, systemd-stub extends PCR 11 **twice**: with
  SHA-256(section name + NUL), then SHA-256(section content at PE
  **VirtualSize**) — in its fixed section-table order
  (`.linux .osrel .cmdline .initrd .ucode .splash .dtb .uname .sbat
  .pcrsig .pcrpkey …`).
* `.pcrsig` is exempt (`unified_section_measure`); **`.pcrpkey` is
  measured** — adding the policy key changes PCR 11, which is why key
  regeneration must (and does, via the fingerprint cascade) restage the
  chain.
* Byte-exactness matters and was caught twice: the combined initrd keeps
  up to four legitimate trailing zero bytes (cpio 4-byte alignment), and
  `.sbat` carries a trailing NUL. Stripping "padding" from either changes
  the hash.

Platform-derived vectors (dev5 run 0001, byte-identical in run 0002):

| Quantity | Value |
| --- | --- |
| Replayed event log, PCR 11 after the 12 section events | `5c2cbc4a9e90f076e8c06ad8e2af71131c8bf4569de75b84c5da60d70544b89d` |
| Model over the same section bytes | identical |
| After the `enter-initrd` phase extend | `9f14d1bd3f993c9a0e8c18d47dd826e40083a7b47e67fe2bcc6298b8ea0371a2` |
| Pinned systemd-measure prediction (byte-exact inputs) | identical |
| TPM2 PolicyPCR digest over that value | `14b80bca06b4b48671c459a59c58846fba5a82cab486579191c0d179428cb8d3` |

These values are pinned as goldens in `tests/test_pcr_sign.py`; any model
refactor that drifts from the platform fails the offline suite.

## The phase extend is real but log-invisible

`systemd-pcrphase-initrd.service` runs and finishes early in the initrd
(observed at t≈1.2 s, before the verity markers at t≈9.6 s in dev5) and
measures `enter-initrd` through `/dev/tpmrm0`. That extend does not go
through the firmware TCG2 log, so the event-log replay alone
under-reports the TPM state. The signed policy therefore covers
*sections + phase word* (SHA-256 of the word, no NUL — per
`measure_phase` in the pinned sources), which is the state at the future
data-unlock point. Honest limitation: without a TPM userspace stack in
the payload and with sysfs PCR reads deadlocking here, the TPM-side value
could not be read directly; the binding rests on (a) the replay equality
above, (b) the unit's success in the boot evidence, (c) the shared
pinned-source algorithm, and (d) the boot-time comparison below.

## In-stage verification (fails closed, four independent ways)

For the built `uki-a-pcr.efi` the `pcr-sign` stage requires all of:

1. **Content identity**: every non-policy section equals the unsigned
   UKI's byte for byte; `.pcrpkey` equals the public key in
   `secrets/pcr/`; the double build is byte-identical (deterministic
   PKCS#1 v1.5 — verified twice in scratch and enforced per build).
2. **From-spec model**: `expected_pcr11` over the exact VirtualSize
   section bytes including `.pcrpkey`, plus the phase word.
3. **Pinned tool agreement**: `systemd-measure calculate` over the same
   inputs must return the same value (it computes with its own model).
4. **Signature chain**: the `.pcrsig` entry must authorize PCR 11 with
   the manifest's `pkfp`, carry the TPM2-spec `policy_pcr_digest` over
   the expected value, and verify under openssl (`dgst -sha256 -verify
   pcr.pub`) inside the pinned container image.

## Boot-time proof

The enforcing chain was rebuilt through `pcr-sign` → `sign` → `enroll` →
`device`, and a fresh device profile (`dev6`) provisioned from the
current generation cold-booted twice through vboot + digest-anchored
Secure Boot on the PCR-carrying signed UKI. Both boots' event-log dumps
replay to **14 PCR 11 events** (seven sections × two events — the extra
pair is `.pcrpkey`, confirming it is measured), and

    replayed-PCR11 ⊕ SHA-256("enter-initrd")

>equals the value the stage computed, recorded and signed —
`3c337ac11d03ab86ec4eb697596827073c17ba55b98b560f52a072816e2b2aa0` in
both `runs/0001` and `runs/0002` (identical replay across cold starts,
consistent with the stability table in tpm-measurements.md).

Evidence: `build/devices/dev6/runs/000{1,2}/serial.log` and
`build/images/<pcr-sign-id>/pcr.json` (same generation by provenance).
The full enforcing gates re-passed on this chain afterwards:
`check-secure-boot` (signed boot with the kernel Secure Boot line;
tampered UKI, modified-content UKI and tampered loader refused with no
guest code; store survives) and `check-boot` (positive markers with a
clean runtime re-read, preverify denial at the flipped offset, mid-session
corruption answered with dm-verity EIO; writes confined to
SMMSTORE/RW_NVRAM).

## Not claimed

* No TPM quote / remote attestation (Phase 8); replay is log-derived.
* PCR 7 binding happens at enrollment (item 8), not here.
* Only slot A exists; slot B arrives with the update phase.
* Development credentials; production PCR-policy custody is open.
* The `.pcrsig`/`.pcrpkey` sections are inside the sbsign-covered PE, so
  the db digest anchor (ADR 0007) covers them — but the
  same-content-signature indistinguishability caveat of ADR 0007 applies
  to the whole file, policy sections included.

## Evidence pointers

- `src/firearc/pcr_sign.py` — model, digest computation, stage.
- `src/firearc/pcr_keys.py` — key role, `pkfp` convention.
- `tests/test_pcr_sign.py` — platform goldens and tamper cases.
- `build/images/<pcr-sign-id>/pcr.json` — per-build expected value,
  policy digest, tool agreement, custody note.
