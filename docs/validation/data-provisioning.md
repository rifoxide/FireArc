# Per-device LUKS2 data provisioning and TPM2 enrollment — validation evidence

**Scope:** PLAN Phase 5 items 6 (per-device LUKS2 volumes created only
during explicit provisioning) and 8 (TPM2 enrollment with explicit PCR 7
binding plus the signed PCR 11 policy) in the development trust domain —
ADR 0010, ADR 0011, `src/firearc/luks.py`, `device.py`/`profile.py` wiring.
Recorded 2026-10-21. Not production provisioning, not physical-device
qualification, and not yet unlock/mount ordering, escrow or updates
(items 7, 9–15).

## What the implementation claims

1. The factory image (`device` stage disk) carries a **blank**
   `FIREARC_DATA` partition — no populated LUKS header, no header
   template, nothing copyable between devices.
2. The volume is created exactly once, at `device-provision` time, from
   fresh entropy: unique volume key, unique argon2id salts, unique UUID.
3. One separate recovery credential (256 bits) is the sole keyslot;
   it never rides a command line, the serial console, or any evidence
   file.
4. The sealed region is device identity: boots never touch it
   (asserted per session), and `profile.load` refuses drift from the
   provisioning evidence.

## In-stage checks (fail closed, every provisioning)

| Check | Mechanism |
| --- | --- |
| Factory region blank | whole-region digest vs. the all-zeros digest, asserted on the profile copy **before** formatting (and independently asserted in the `device` stage on the assembled disk) |
| Format really happened | region digest must differ from blank after the splice |
| Credential unlocks | `cryptsetup luksOpen --test-passphrase` (no activation) against keyslot 0, inside the pinned tools container |
| Header is on disk, twice | LUKS2 magic/version + u64 `hdr_size` + JSON from `0x1000` parsed from the workspace image **and** re-read from the spliced profile disk |
| Inventory contract | `luksDump --dump-json-metadata`: keyslots exactly `["0"]`, no tokens, exactly one `crypt` segment; uuid and `FIREARC_DATA` label present in the binary header |
| Credential hygiene | credential passed only via `--key-file`; workspace copy scrubbed; evidence records its digest, never its bytes |

The on-disk header expectations were validated against real
cryptsetup 2.7.5 output from the pinned tools image before being pinned
as tests (`tests/test_luks.py` carries the synthetic LUKS2 builder and
the geometry/blank/contract vectors; 15 tests).

## Real-run evidence (2026-10-21)

* **`device` stage** (`device-52f6214214de`): 4-partition GPT
  (ESP / ROOT_A / HASH_A / DATA), `data_partition_blank: true` in the
  stage result; independent re-check of the published artifact digests
  the whole 256 MiB region to the all-zeros value.
* **Requalification on the new geometry:** `just check-boot` (positive
  boot with clean runtime re-read, preverify denial at the flipped
  byte, mid-session dm-verity EIO) and `just check-secure-boot`
  (signed boot under Secure Boot; tampered UKI / modified-content UKI /
  tampered loader all refused with no guest code) both pass on the
  4-partition disk.
* **dev7** (first provisioned data volume): uuid
  `594aa03c-c379-4812-ba8e-f4f3af8a2fa1`, argon2id keyslot 0,
  aes-xts-plain64, 16 MiB metadata offset, region digest
  `0fbdd213…`; recovery credential 0600, verify rc=0. Two cold boots
  pass, and `data_sha256` is part of the boot identity — unchanged
  across both boots (nothing in the boot path touches the sealed
  region).
* **dev8** (second device): uuid `d9716349-a8a6-4bbc-bef4-31299f1c1d88`;
  region digest, keyslot salt, digest salt and credential all differ
  from dev7 — per-device uniqueness demonstrated on real provisions,
  from byte-identical factory images.
* **Credential hygiene, re-checked on the real profiles:** the
  credential bytes appear in **zero** files under either profile except
  `secrets/recovery.key` itself.

## TPM2 enrollment evidence (item 8, 2026-10-21)

* **dev9** (`just data-enroll`, run 0002, 40 s): guest enrolls the token
  at `enter-initrd` (`New TPM2 token enrolled as key slot 1`,
  `FIREARC_DATA_ENROLL_OK`) and the same session's probe validates the
  policy against the live boot (`FIREARC_DATA_UNLOCK_OK`). Host-side
  verification: keyslots exactly `0,1`; one `systemd-tpm2` token bound to
  keyslot 1; plain PCR set `7`, signed PCR set `11`, SHA-256 bank; the
  token's base64 policy key equals `secrets/pcr/pcr.pub` byte for byte
  (pkfp `4aaa9ed7…`). Profile records the new region digest and token
  inventory.
* **Cross-boot unattended unlock** (dev9 runs 0003/0004, cold starts):
  `FIREARC_DATA_UNLOCK_OK` on both boots, region digest unchanged
  (per-boot identity assertion — unlock never writes the volume).
* **Moved-disk refusal** (dev10: dev9's disk transplanted onto a fresh
  swtpm identity, recorded as `disk-transplant`): the machine still
  boots its verified read-only root, but the probe reports
  `FIREARC_DATA_UNLOCK_REFUSED` — the sealed blob is worthless to a
  foreign TPM. This is the item-12 direction previewed; full matrix is
  items 11–13.
* **Gate requalification on the changed chain** (new initrd tools, new
  units, re-signed PCR 11 policy `8b034d55…`): `check-initrd` (tool
  presence asserted), `check-boot` and `check-secure-boot` all pass.

Findings that shaped the implementation (all reproduced before being
fixed): plain `cryptsetup` is not in the minimal initrd (probe initially
returned rc=127 — the diagnostic markers `FIREARC_PROBE_LUKSDUMP_RC` /
`…_TOKENS` now pin its presence); systemd-stub 257 exposes the UKI's
signature files under `/.extra/`, not `/.tpm2-*`; the real token JSON
uses `tpm2-pcrs` (plain set) vs `tpm2_pubkey_pcrs` (signed set) with the
policy key as base64 PEM in `tpm2_pubkey`.

## Honest boundaries

* The recovery credential is **escrow-pending** (item 7): it exists
  only under the dev profile's 0700 `secrets/` directory. No approved
  custody path, no two-person control, no escrow record exists yet —
  the `escrow: "pending (Phase 5 item 7)"` marker in
  `provision/data.json` is the explicit reminder.
* No inner ext4 and no unlock in the boot path: nothing mounts the
  volume (items 9–10); first-mount formatting belongs to that work.
  The per-boot probe attaches and detaches the mapping for validation
  only — unlock ordering and `/data` mounts are still unimplemented.
* Entropy is the host kernel CSPRNG (dev harness); production
  provisioning entropy and custody remain an H interface.
* `--disable-locks` is safe here because provisioning is a single
  exclusive writer inside a private profile directory; it would be
  wrong in a concurrent context.
* Sizing (256 MiB) is provisional per PLAN §4.3.
