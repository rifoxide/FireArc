# ADR 0010 — Per-device LUKS2 data volumes and recovery-credential custody

**Status:** Accepted 2026-10-21 (PLAN Phase 5 item 6).

## Context

Phase 5 gives persistent data per-device encryption: item 6 requires
LUKS2 volumes created **only during explicit provisioning**, unique
random volume material, a separate high-entropy recovery credential, and
a hard rule that a populated shared LUKS header never enters the factory
image (PLAN §1.6: "unique per device; never a fleet-wide factory key").
Before this ADR the harness disk had no data partition at all, nothing
provisioned one, and the recovery-credential requirements of items 7 and
14 had no artifact to attach to.

Three constraints shaped the design:

* The pinned tools closure already contains `cryptsetup-bin=2:2.7.5`
  (and `systemd-cryptsetup=257.13` for item 8's enrollment), so
  provisioning uses the same digest-verified tooling as every other
  stage — no new packages, no host cryptsetup.
* Build containers run unprivileged (`--cap-drop=ALL`, read-only root,
  no `/run/cryptsetup`), so activation (`luksOpen` with device-mapper)
  is impossible there; formatting a plain image file and splicing it
  into the profile disk host-side keeps the container's job exactly
  `luksFormat`/`luksDump`/`--test-passphrase`.
* Item 7 forbids the credential in serial capture, CLI arguments or
  general logs; item 14 requires escrowed recovery to work later. The
  credential therefore needs a defined home and hygiene from the moment
  it exists.

## Decision

**A blank `FIREARC_DATA` partition in the factory image; the volume is
born at `device-provision` time from fresh entropy; the recovery
credential lives under the profile's private `secrets/` with escrow
explicitly pending.**

1. **Geometry** (`device.py`): a fourth GPT partition `FIREARC_DATA`
   (Linux LUKS type GUID, 256 MiB provisional — PLAN §4.3 keeps sizes
   provisional) after the verity-hash partition. The `device` stage
   asserts the assembled region is blank and records it; `luks.py`
   independently re-asserts the blank region on the profile copy before
   formatting. Two fail-closed checks, two code paths.
2. **Provisioning** (`luks.provision_data`, invoked by
   `profile._provision`): the pinned cryptsetup formats a workspace
   copy of the region — `--type luks2 --batch-mode --disable-locks
   --label FIREARC_DATA --key-slot 0 --key-file …` with cryptsetup 2.7
   defaults (argon2id, aes-xts-plain64, 16 MiB metadata area) — and the
   formatted bytes are spliced into the profile disk host-side. The
   stage then verifies the credential against keyslot 0
   (`luksOpen --test-passphrase`, no activation), parses the on-disk
   header (magic/version, u64 hdr_size, JSON from 0x1000 — validated
   against real cryptsetup output), checks the inventory contract
   (keyslots exactly `["0"]`, no tokens, one crypt segment) both from
   `luksDump` and from the spliced disk bytes, and refuses if the
   region did not change.
3. **Credential**: 256 bits from the host kernel CSPRNG, written 0600
   to `<profile>/secrets/recovery.key`, passed to cryptsetup **only by
   file handle**, scrubbed from the workspace afterwards, and recorded
   (digest only) in `provision/data.json` with
   `escrow: "pending (Phase 5 item 7)"`. The provisioning evidence
   never contains the bytes (asserted in tests and re-checked on the
   real profiles).
4. **Identity**: the sealed region becomes device identity —
   `profile.load` re-digests it against the provisioning evidence, and
   every boot session records and asserts `data_sha256` alongside the
   flash/TPM digests, so nothing in the boot path may touch the volume
   silently.
5. **Inner filesystem**: deliberately not created. Nothing unlocks the
   volume yet (items 8–10); first-mount formatting belongs to the
   unlock work. Item 6 stays exactly scoped: volume, credential,
   factory-blank rule.

## Consequences

* Provisions are unique by construction: fresh volume key, fresh
  argon2id salts, fresh UUID per device (demonstrated on dev7/dev8 —
  `docs/validation/data-provisioning.md`).
* Re-provisioning is the explicit `--replace` path (whole profile
  wipe); there is no reformat-in-place and no path that could clone a
  populated header between devices.
* The old dev6 profile (pre-data layout) still boots; profiles without
  a `data` block simply skip the data identity checks.
* Open items carried forward: escrow path for the credential (item 7 —
  the "pending" marker is the reminder), TPM2 token enrollment
  (item 8), unlock/mount ordering (items 9–10), and header-backup
  retention semantics (items 14–15). Production entropy and custody
  (HSM-class provisioning, two-person control) remain H-interface
  concerns: this ADR is the development-trust-domain form.
