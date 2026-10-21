# Per-device LUKS2 data provisioning — validation evidence

**Scope:** PLAN Phase 5 item 6 (per-device LUKS2 volumes created only
during explicit provisioning) in the development trust domain —
ADR 0010, `src/firearc/luks.py`, `device.py`/`profile.py` wiring.
Recorded 2026-10-21. Not production provisioning, not physical-device
qualification, and not yet any unlock/enrollment (items 7–15).

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

## Honest boundaries

* The recovery credential is **escrow-pending** (item 7): it exists
  only under the dev profile's 0700 `secrets/` directory. No approved
  custody path, no two-person control, no escrow record exists yet —
  the `escrow: "pending (Phase 5 item 7)"` marker in
  `provision/data.json` is the explicit reminder.
* No inner ext4 and no unlock: nothing in the boot path opens the
  volume (items 8–10). First-mount formatting belongs to that work.
* Entropy is the host kernel CSPRNG (dev harness); production
  provisioning entropy and custody remain an H interface.
* `--disable-locks` is safe here because provisioning is a single
  exclusive writer inside a private profile directory; it would be
  wrong in a concurrent context.
* Sizing (256 MiB) is provisional per PLAN §4.3.
