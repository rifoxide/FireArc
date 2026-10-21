# TPM measurement investigation for the Phase 5 policy design

## Scope

PLAN Phase 5 items 1–4 (measurement groundwork for the future LUKS2
PCR-sealed data policy): confirm TPM 2.0 discovery, collect the firmware
event log, map every measurement to its producer, and characterize the
replayed PCR banks across unchanged boots and one-at-a-time variants.
All evidence is QEMU Q35 + swtpm + KVM under the development trust domain
(ADR 0005 host anchor; ADR 0008 vboot). Nothing here is a TPM quote or
remote attestation — those are Phase 8.

## Readout mechanism (and why not sysfs PCR files)

The kernel in the pinned payload exposes `/sys/class/tpm/tpm0/pcr-sha256/N`,
but under this QEMU tpm-tis + swtpm setup **the second per-PCR sysfs read
deadlocks** (observed 2026-10-21, kernel 6.12): one read returns, the next
blocks forever in the driver (uninterruptible), while the rest of the boot
continues. The readout therefore does not use TPM commands or sysfs PCR
files at all. The boot marker unit mounts securityfs and dumps
`/sys/kernel/security/tpm0/binary_bios_measurements` as hex
(`od -An -v -tx1`) to the serial device between
`FIREARC_PCR_DUMP_BEGIN` / `FIREARC_PCR_DUMP_END` markers; the profile boot
session waits for the end marker (diagnostic only — an incomplete dump is
recorded, never fatal). The host-side `src/firearc/tpm_evidence.py`
extracts the dump (tolerating interleaved console lines, failing closed on
missing brackets), parses the crypto-agile TCG PC-Client log, and replays
the SHA-256/SHA-1 banks with extend semantics.

Caveat, stated plainly: **replayed values are log-derived, not
TPM-attested truth.** The firmware could emit a log that diverges from the
actual extends; nothing here cryptographically binds the log to the TPM
(that is what Phase 8 quotes are for). Direct `/dev/tpmrm0` PCR reads from
the pinned payload are impossible for a different reason: the payload
ships no TPM userspace stack.

## Discovery (item 1)

swtpm 2.0 over the QEMU ISA TIS device: the kernel binds exactly one
`tpm_tis` device (`/sys/class/tpm/tpm0`, `tpm_version_major=2`, with
`/dev/tpm0` and `/dev/tpmrm0`); a duplicate ACPI MSFT0101 object fails
probe `-EBUSY`, so exactly one TPM owns the MMIO region (fail-closed).
Cold starts re-establish this every boot (`FIREARC_TPM_TIS_OK` gate).
The log's Spec ID event advertises four banks (SHA-1/256/384/512);
firmware and stub measure SHA-1+SHA-256 (at minimum) per event; replay
below uses SHA-256.

## Log and producers (items 2–3)

Baseline boot: **51 events**, replayed nonzero SHA-256 PCRs:
**0, 1, 2, 3, 4, 5, 6, 7, 9, 11** (8, 10, 12–23 stay zero — no option ROMs
or measured shutdown in this configuration). The log handoff is contiguous:
coreboot → EDK II → systemd-boot → systemd-stub → kernel EFI stub, with no
duplicate TPM initialization and no unmeasured gap between producers.

| PCR | Extends | Producers (observed) |
| --- | --- | --- |
| 0 | 5 | CRTM version (Spec ID), coreboot SCRTM version, platform firmware blob, separators |
| 1 | 13 | coreboot `0xDA0000` config events (NetworkBoot, Ps2Controller, SerialRedirection, Type1UUID, Type2SN, USB stack), EDK II boot-services applications (device paths), firmware-blob variant `0x80000009` |
| 2/3/6 | 1 each | Separator only (no option ROMs on Q35) |
| 4 | 5 | EDK II actions (launching boot option), boot-services drivers |
| 5 | 5 | GPT event (disk partition table), `loader.conf` (systemd-boot), exit-boot-services actions |
| 7 | 6 | **SecureBoot, PK, KEK, db, dbx** variables (EFI variable events), separator |
| 9 | 2 | systemd-boot `LOADED_IMAGE::LoadOptions`, kernel EFI stub `Linux initrd` |
| 11 | 12 | systemd-stub: one event per UKI section (`.osrel`, `.cmdline`, `.uname`, `.linux`, `.initrd`, ...) |

## Stability and sensitivity (item 4)

**Stability:** two cold starts of the same device profile (dev5 runs 0001/
0002, fresh swtpm state each boot) plus an independent probe boot of the
same disk+flash produce byte-identical replayed SHA-256 banks across all
24 PCRs. Measurement replay is deterministic for unchanged inputs.

**One-at-a-time variants** (same disk unless noted, fresh swtpm per boot;
"differs" = replayed SHA-256 bank):

| Variant | Booted | PCR diff vs baseline | Reading |
| --- | --- | --- | --- |
| firmware-build output (devkey GBB root + devkey-signed RW) | yes | **none** | vboot signing identity is NOT reflected in the measurements; enforcement lives in verification/refusal, not in PCR 0/1 |
| enrolled firmware (our PK/KEK/db/dbx, digest-anchor db) | yes | **4, 7** | policy state measured: PCR 7 carries our variables (db 1741 B vs auto-enrolled 6133 B, empty dbx vs 19996 B) plus two `EV_EFI_VARIABLE_AUTHORITY2` events recording the enforcing verification authority; one boot-services-driver measurement differs (PCR 4) |
| unsigned UKI in the ESP (signature layer only) | yes | **none** | systemd-stub measures UKI content sections and skips the signature sections, so signed-vs-unsigned is invisible to PCR 11 — the db digest anchor is what distinguishes it (check-secure-boot) |
| UKI content change (one byte in `.osrel`) | yes | **4, 9, 11** | content sections are measured (PCR 11); the loader's LoadOptions change with the title (PCR 9); one action-adjacent driver measurement shifts (PCR 4) |

Policy consequences for Phase 5 items 5/8 recorded honestly:

- PCR 7 + PCR 11 (with PCR 9 as loader context) are the meaningful binding
  surface for data unlock: they capture Secure Boot state and UKI content.
- **Do not claim firmware-identity binding via PCR 0/1** with this coreboot
  configuration — a devkey-verified firmware measures identically to ours.
- **Do not claim signature-presence binding via PCR 11** — the signature
  sections are not measured; that guarantee belongs to the db anchor.
- Refused boots (tampered UKI under enforcement) never reach measurement
  completion; refusal is the gate, not a PCR value.

## Evidence pointers

- `build/devices/dev5/runs/000{1,2}/serial.log` — stability dumps
  (`FIREARC_PCR_DUMP_*` brackets).
- `src/firearc/tpm_evidence.py` — extraction/parser/replay (unit-tested
  against a synthetic agile log).
- Probe serials for the variant table were scratch (deleted after the
  investigation); the probe method is documented above and reproducible
  with `device.start_vm` + fresh swtpm state per boot.

## Investigation incidents

- The enrolled-firmware probe initially refused dev5's UKI (`Access denied`)
  because the enroll stage output predated the current signed UKI
  (stale digest anchor). Re-running `just enroll` re-anchored it; the
  pipeline's fingerprint cascade prevents this for stage consumers, but
  hand-copied ROMs bypass that protection — always re-copy from the
  current generation.

## Item 5 design groundwork (PCR authorizations)

What the pinned tooling provides (verified against the locked debs, not
internet hearsay):

- `systemd-measure` ships in the pinned `systemd=257.13-1~deb13u1` package
  (`/usr/lib/systemd/systemd-measure`) and `systemd-cryptenroll` +
  `systemd-cryptsetup` in `systemd-cryptsetup=257.13-1~deb13u1` — both
  already pinned in `locks/root.json`; no new packages are needed for
  signing or enrollment. ukify is *not* in the pinned set (our UKI
  assembly is its own stage; the sign stage will call systemd-measure
  directly).
- The PCR 11 measurement algorithm was verified empirically against the
  observed log: each UKI section is measured at its PE `VirtualSize`
  (byte-exact match for `.linux` and `.osrel` digests; `SizeOfRawData`
  padding is not measured). The observed log carries **two deterministic
  events per section** (distinct digests, both replay-stable); the second
  is the plain content hash. The authoritative expected-value computation
  for signing must come from the pinned `systemd-measure` itself rather
  than a re-derived formula.
- The unlock flow per the stub documentation: UKIs with `.pcrsig`/
  `.pcrpkey` sections get them exposed as
  `/.extra/tpm2-pcr-signature.json` + `/.extra/tpm2-pcr-public-key.pem`
  (and `/run/systemd/…` after tmpfiles), which `systemd-cryptsetup`,
  `systemd-cryptenroll` and `systemd-creds` consume automatically. The
  `.pcrsig` section is excluded from the PCR 11 measurement (it covers the
  measurement it signs), so adding signatures does not shift PCR 11 —
  consistent with the observed identical replay of signed vs unsigned
  UKIs.
- **Gap: no phase markers.** `systemd-pcrphase*` services (pinned,
  present in the systemd package) extend PCR 11 with boot-milestone
  strings, but our initrd does not run them — the observed PCR 11 ends
  after the section measurements. The "exact data-unlock phase" binding
  of PLAN item 5 therefore needs the pcrphase units enabled in the initrd
  (or an equivalent explicit milestone measurement) as part of the
  LUKS2 work.
- Key separation: the PCR-policy signer (the key whose public half rides
  in `.pcrpkey` and authorizes expected PCR values) must be a distinct
  role from the db/UKI signer per PLAN item 5 — a new gitignored keyset
  under `secrets/`, generated by the existing keys stage pattern.
