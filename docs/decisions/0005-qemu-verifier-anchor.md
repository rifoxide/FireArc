# ADR 0005 — the initial firmware verifier in QEMU is host-anchored only

**Status:** Accepted 2026-10-20 (Phase 2, plan item 7).

## Context

FireArc's secured boot chain eventually needs a root verifier: the first code
that decides which firmware, payload and OS images may run. On real hardware
this anchor is physical (write-protected flash, boot ROM, discrete TPM). The
current qualification environment is QEMU Q35 with the self-built monolithic
coreboot/EDK II ROM. The pinned board FMAP contains no vboot regions at all,
so no verified-boot RO region exists in the image yet, and the pinned payload
carries no TPM stack, so no firmware measurements exist either.

## Decision

We state the anchor explicitly and keep the limitation in every claim:

- **The initial trusted-firmware input in QEMU is the host.** The harness — a
  host-trusted process — copies the pinned, digest-verified ROM built by
  `just firmware-build` into the per-run/device writable flash image. Nothing
  inside the emulated machine verifies that image before the CPU resets into
  it; QEMU's pflash is fully writable by construction.
- **The integrity boundary is therefore the QEMU threat model already
  documented in `docs/threat-model.md`:** the host, QEMU, swtpm custody, the
  harness and the approved firmware base are trusted; malicious disk/ESP/
  update content and controlled boot-state changes are in scope; **a malicious
  host is out of scope and unprotected against.** A host administrator can
  replace the firmware, snapshot or reset TPM state, or restore an entire old
  machine — the harness fails closed when that happens outside recorded
  guest execution (identity-continuity assertions), but it cannot prevent it.
- **No firmware-verification claim is made from the OS gate.** SMMSTORE
  write-confinement, boot markers and dm-verity prove the development gate's
  own properties, never verified boot. When firmware verified boot (vboot or
  an equivalent protected-RO model) is adopted, it requires a board-layout
  change (vboot FMAP regions do not exist in the pinned layout), separate
  signing keys (Phase 2 items 9–11) and its own qualification record; until
  then gate G2's firmware-verification components remain **blocked, not
  implied**.
- **On real hardware the anchor changes:** the reference board's write-
  protected flash/boot ROM becomes the physical root, and this ADR is
  superseded by the hardware qualification records.

## Consequences

- Firmware/OS security claims derived from QEMU runs must be phrased as
  "under a trusted host", which `docs/validation/*` already does.
- Any future "RO verifier" demo inside QEMU (e.g. a vboot-enabled layout)
  still inherits the host anchor; it can demonstrate mechanism and negative
  controls, never resistance to a malicious host.
- This decision unblocks Phase 2 items 4/7 documentation-wise; it does not
  create signing authority or key custody (those remain owner decisions).
