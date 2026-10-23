# Implementation progress

**Updated:** 2026-10-21. **Stage:** Phase 5 (TPM-bound data) in progress —
signed PCR 11 authorizations, per-device LUKS2 volumes, TPM2 enrollment,
crypttab-driven unlock and ordered encrypted `/data` mounts implemented.
The current pinned version passes cold/warm boots and mount-failure refusal;
a distinct retained/candidate systemd-version pair, the complete refusal matrix,
and escrow remain open. The complete secured appliance is not yet implemented.

### Latest: Phase 5 items 9–10

- Pinned cryptsetup generator + crypttab, explicit root/PCR-phase dependencies,
  `sysroot-data.mount` with `rw,noexec,nodev,nosuid`; the probe no longer unlocks.
- Filesystem birth requires a persisted, one-time transport grant. Retries
  preserve ext4 or refuse; they cannot silently format again. The transport
  uses an explicit disk serial rather than nondeterministic `/dev/sdb`.
- Enrolled identity covers both LUKS metadata copies and the whole keyslot area;
  mutable filesystem ciphertext is no longer incorrectly treated as identity.
- `data-verified`: enrollment, two cold boots and one warm reset passed.
  `data-updated`: latest OS/firmware with retained data/TPM/UEFI variables,
  two cold boots passed without re-enrollment (lab transition, not RAUC/A/B).
  All 259 tests, three boot-chain gates, initrd audit and `verify-build` passed. A disposable
  filesystem-corruption test refused boot without changing partition bytes;
  restoring its snapshot restored successful boot.
- See [validation](validation/data-mount.md) and [ADR 0012](decisions/0012-crypttab-data-mount-gate.md).
  Item 9 remains partially open for cross-version qualification; service bind
  mounts await actual consumers. No Phase 6–13 implementation or G5 exit claim.

## Repository interface cleanup

- Intermediate recipes are consolidated into `just stage <name>`; the three
  boot gates, key roles and destructive device operations remain explicit.
  `just check` still runs input validation, the secret scan and all offline tests.
- Removed the old standalone `boot-live` runner and duplicate HTML command map;
  `just shell` is the supported disposable console and [Commands](commands.md)
  is the canonical reference/migration table. The HTML boot-chain guide remains.
- Pruning now verifies successful check receipts before removing unpublished
  working disks. Logs, flash evidence, current outputs and saved devices remain.
  Incomplete/failed current checks and published disk artifacts are preserved;
  tampered receipts and scratch symlinks fail closed.
- Firmware SDK acquisition now belongs to `firmware-sources --online`, not a
  removed online-build alias; a cached source receipt still checks the SDK.
- Routine cleanup reclaimed 34.14 GiB of working disks. All 256 saved device/key
  files were SHA-256-identical before and after pruning.
- 281 offline tests pass. This cleanup does not change guest unlock/mount policy
  or claim new boot-chain qualification.

## VGA development shell

- `just shell` now opens a GTK QEMU VGA window with the Q35 keyboard, using
  `/dev/tty1` and `TERM=linux`. Host TTYs are no longer required; a graphical
  desktop is. Normal boot gates remain headless/serial.
- No additional host option ROM is loaded. Snapshot-backed disk/pflash, fresh
  TPM, verified-root/data ordering and saved-device isolation are unchanged.
- Shell-only boot-log routing adds VGA as the primary Linux/initrd console while
  retaining serial kernel diagnostics. The selected command line is embedded,
  section-checked and recorded consistently in the device manifest. Boot output
  is not cleared for Bash, and the pending-job spinner stops before its prompt.
- 293 offline tests pass. Live requalification of boot-log routing is pending:
  the owner's running VM holds the project lock and has been left untouched.
- Earlier, the standard offline Docker-backed command opened the window;
  owner closure exited QEMU cleanly and removed temporary state. Signed disk and
  firmware receipts still matched. Live keyboard/TTY assertions were not captured
  before closure; see [shell validation](validation/development-shell.md).

## Host-side script refactor

- Split CLI parser construction, command execution and output/error handling.
  Shared locked helpers replace repeated key/device orchestration; the checkout
  launcher stays thin. No commands, flags, defaults or exit codes changed.
- Normal and shell image stages share the verified UKI/PCR/sign/enroll/device
  builders while keeping separate dependency namespaces and artifacts.
- Added characterization tests before structural changes: operation arguments,
  lock ownership/release, key dependency order, stdout JSON, errors and interrupts.
  Both image variants retain the same builder calls and exception propagation.
- 292 offline tests pass. All 28 command-help outputs matched the pre-refactor
  bytes, and all 23 launcher/guest/input files were unchanged. No guest policy,
  provisioning behavior, signing identity or saved device data was changed;
  this is not new boot qualification.

## Implemented

- Project-owned source package under `src/firearc/`, image policies under
  `images/`, a pinned builder under `containers/builder/`, and exact input locks.
- Label-free build commands, automatic dependency resolution/build IDs,
  input-sensitive cache invalidation and verified success receipts.
- Public upstream bootstrap: digest-pinned Debian image/keyring, signed snapshot
  metadata, complete package-closure fingerprints and size/SHA-256 checks.
- Offline tools build and rootless mkosi kernel/root/initramfs assembly.
- Fixed 4 GiB ext4 payload, headerless verity tree and explicit hash/geometry.
- Initramfs gate with strict embedded authority and slot/command-line checks,
  same-disk/boot-ESP validation, full preverification, read-only mapping/mount,
  no raw-root fallback and no-shell failure units.
- Static embedded-code/unit audit and copied-payload corruption controls.
- Clean/reproduction commands that rebuild from empty project output directories.
- Preliminary CycloneDX 1.5 inventory of the locked root closure (`just sbom`),
  with a deterministic serial number derived from the closure fingerprint.
- Exact-commit acquisition of the pinned upstream firmware repositories
  (`just firmware-sources --online`), with per-source tree records and offline
  re-verification. The fourteen pinned submodules are materialized inside the
  coreboot/EDK II checkouts under a gitlink census enforced against each parent
  tree, declining every unlisted upstream submodule. Nothing is trusted yet.
- Self-built QEMU Q35 firmware (`just firmware-build`): the pinned closure
  compiles offline in the pinned coreboot SDK container into the monolithic
  8 MiB ROM with the EDK II payload, with manifest-bound inputs, toolchain
  digests and CBFS inventory. `just check-boot` now boots the self-built
  firmware (writable SMMSTORE pflash, AHCI disk) instead of host OVMF; the
  integrity gate passes and the corruption control still denies.
- Firmware flash-layout inspection (`just firmware-layout`): the ROM's FMAP is
  parsed and archived offline with region roles — SMMSTORE variable store,
  FMAP descriptor, preserved BOOTSPLASH, COREBOOT CBFS code; no gaps and no
  vboot regions exist in the pinned layout. The boot gate additionally
  requires every flash byte outside SMMSTORE to survive each run unchanged;
  both baseline boots confined 33,586 bytes of variable initialization to
  SMMSTORE (see [firmware-layout validation](validation/firmware-layout.md)).
- Persistent installed-device profile (`just device-provision`/
  `just device-boot`): a per-device directory carries the OS disk, the
  writable firmware copy and one isolated swtpm TPM 2.0 state dir across cold
  starts. Two cold-start boots each reached the verified-root marker, bound
  the TPM through ACPI/TIS (`tpm_version_major=2`, `/dev/tpm0`, `/dev/tpmrm0`)
  and confined all flash writes to SMMSTORE; SMMSTORE and TPM state carried
  over between boots byte-exactly and are asserted stable outside guest
  execution. Found and fixed on the way: a dev-unit shutdown race against
  `switch_root` (now `poweroff -f`). See
  [device-profile validation](validation/device-profile.md).
- Explicit device lifecycle operations over a local-only QMP socket
  (`just device-reboot`/`device-stop`/`device-powercut`/`device-snapshot`/
  `device-restore`), closing gate G1: a warm-reset loop kept flash/TPM
  powered through three boots in one session (markers each boot, NVRAM
  carried and evolved); an abrupt power cut after a verified boot was
  recovered from on the next cold start with no silent NVRAM/TPM reset; state
  restoration happened only by explicit snapshot restore, and a failed
  session adopts its observed identity with an explicit failed record. Two
  real appliance findings recorded honestly: the payload intermittently
  parks at its interactive boot menu (mostly from pristine variable stores,
  once from an initialized one; harness sends a bounded, recorded ENTER over
  QMP), and the ACPI power button is not handled by the minimal root
  (`device-stop` records it and stops the machine itself). Orphaned
  QEMU/swtpm now die with the harness (`PR_SET_PDEATHSIG`).
- Phase 1 complete: TCG and KVM are distinct qualified profiles
  (`device-boot --tcg`, per-run `accel` records; ~75 s vs ~23 s per verified
  cold boot), persistent monolithic flash carries across cold starts and
  warm-reset loops (PLAN 1.12), and no session ever has a network device
  (`-net none`, PLAN 1.15).
- Post-mapping runtime corruption gate (PLAN Phase 3 item 12 complete): the dev
  unit now blocks `initrd.target` (requires + Before), so after the verified
  markers it can drop caches and re-read the whole verity-mapped root while
  the machine is still up; `check-boot` gained a third discipline that flips
  a root byte mid-session after the mapping is up — dm-verity returned an
  I/O error (`FIREARC_RUNTIME_CORRUPT_EIO`) while the uncorrupted control
  read clean. Found and fixed while qualifying: `dd` is absent from the
  minimal dracut initramfs (the read uses coreutils cat), and the unit's old
  guest-side poweroff was dead code anyway (switch_root stops the unit
  before it runs).
- Firmware evidence capture completed and a third byte-identical build
  (PLAN Phase 2 items 2 and 7): the firmware-build stage now archives the
  expanded Kconfig, the payload DSC/FDF (resolved from the DSC's
  FLASH_DEFINITION), an explicit empty patch record, and per-step
  build-command digests; the rebuilt ROM reproduced `e2e1cc04…` byte-for-byte
  and passed the full three-discipline check-boot gate again. ADR 0005
  records that the initial firmware verifier in QEMU is host-anchored only —
  no verified-boot claims until a protected-RO layout, signing keys and
  their own qualification exist.
- vboot adoption investigated (PLAN Phase 2 item 5,
  `docs/validation/firmware-vboot.md`): the pinned board ships upstream vboot
  machinery (config + RW_A/RW_AB 8 MiB layouts); adoption needs a custom fmd
  restoring SMMSTORE, flash-backed VBNV under QEMU, a recovery payload
  decision and — the blocker — a vboot signing key hierarchy.
- Scope re-focused by owner decision (2026-10-20): **the current goal is the
  enforced secure boot chain only.** PLAN §1.3 now records the chain links
  with done/remaining status, the five-step critical path (key hierarchy →
  unsigned UKI → enrollment/signing with rejection proofs → vboot adoption →
  requalification), the exit criteria (G2 plus the enforcement core of G4),
  and the deferral of Phases 5–13 until the chain is complete; Phases 14–19
  remain post-qualification product work. Every phase heading in PLAN.md
  carries its ACTIVE/DEFERRED/LATER disposition accordingly.
- Unsigned slot-A **Unified Kernel Image** built and boot-qualified (PLAN
  Phase 3 item 11, Phase 4 items 3–4; `just uki`): the pinned ukify
  (tools image) combines the root archive's own linuxx64.efi stub and
  os-release with the frozen kernel, dracut initramfs and an appended cpio
  carrying the verity authority and dev unit — one systemd version (257.13)
  across loader, stub and ukify. In-stage evidence: UKI built twice and
  byte-identical, every payload section (.osrel/.cmdline/.uname/.linux/
  .initrd) verified against its exact input file, `rauc.slot=A` embedded.
  The device ESP now carries only systemd-boot + `EFI/Linux/firearc-a.efi`
  (type-2 entry; no separate kernel/initramfs), and the full three-discipline
  check-boot gate re-passed on the UKI: good boot + clean runtime re-read,
  preverify denial at the exact flipped offset, mid-session post-mapping
  corruption → dm-verity EIO. `just build` publishes `uki-a.efi`; unsigned —
  signing and Secure Boot enrollment are the next chain links.
- **Development key hierarchy generated** (chain step 3a; PLAN Phase 2 items
  8/9 annotated, 11 in progress; ADR 0006, `just keys`): three dev roles —
  PK, KEK and the EFI image-signing key whose certificate becomes the db
  content — RSA-3072 self-signed, generated inside the pinned tools
  container (openssl 3.5.7 / sbsigntool 0.9.4), stored under gitignored
  `secrets/` (0700/0600, outside source/build trees, never committed, fails
  closed on partial hierarchies). Time-based enrollment payloads follow the
  standard chain (`pk.auth` self-signed, `kek.auth` by PK, `db.auth` by KEK)
  so any enrollment mechanism can consume them. Public fingerprints are
  recorded in the ADR; production custody/ceremony remain open (item 10).
- **Boot artifacts signed and boot-qualified** (chain step 3b; PLAN Phase 4
  item 5 annotated; `just sign`): a new isolated signing stage signs the
  UKI and the systemd-boot loader with the development sb key — the signing
  container mounts only `sb.key`/`sb.crt` read-only, satisfying the plan's
  exposure rule; PK/KEK material never enters it. Both artifacts are
  sbverify-verified in-stage and structurally content-checked (only the PE
  checksum and Certificate-Table entry may differ; the appended region must
  be exactly the described certificate). The signature layer is honestly
  recorded as non-byte-reproducible (sbsign embeds signing time);
  reproducibility attaches to the covered content, which `just reproduce`
  compares. The device stage now refuses unsigned artifacts, and the full
  three-discipline check-boot gate re-passed on the signed disk (Secure
  Boot still unenforced — signatures are carried, not yet required).
  `just build` publishes `uki-a-signed.efi`; regenerating keys restages
  signatures automatically (custody manifest is a stage input).
- **Variable-store enrollment implemented** (chain step 3c; PLAN Phase 2
  item 12 annotated; ADR 0007, `just enroll`): the dev PK/KEK/db plus
  `SecureBoot=1`/`SetupMode=0` are constructed offline into the erased
  SMMSTORE region of the firmware-build ROM, producing the `enrolled.rom`
  artifact. Every structure matches the pinned EDK II sources exactly
  (28-byte authenticated store header, 60-byte packed auth entries,
  4-byte entry alignment, the payload's 64 KiB `PcdVariableStoreSize`
  convention), and the parser was validated against ground truth — real
  payload-initialized stores from boot evidence. Two decisive findings
  from that evidence: the payload auto-enrolls its own default
  PK/KEK/db/dbx on pristine-start boots (replaced wholesale by our
  constructed store), and it never creates the `SecureBoot` variable —
  which the pinned `DxeImageVerificationLib` requires before verifying
  anything, explaining why our differently-signed artifacts kept booting.
  The stage fails closed (erased-region check, byte-deterministic double
  build, re-parse round trip, confinement to SMMSTORE) and restages when
  the generated hierarchy payloads change.
- **Secure Boot enforcement proven** (chain step 3d; PLAN Phase 2 item 13
  and §1.3 annotated; `just check-secure-boot`,
  [validation](validation/secure-boot-enforcement.md)): four QEMU Q35
  sessions on the enrolled self-built firmware. The signed chain boots to
  the verified sysroot with the kernel reporting `secureboot: Secure boot
  enabled`; a tampered UKI (one `.linux` byte), a modified-content UKI
  (perturbed `.cmdline`) and a tampered loader are all refused with
  explicit denial evidence and **no guest code executed**; the enrolled
  store survives the boot (defaults never re-enrolled) and guest writes
  stay confined to SMMSTORE. Root cause found and recorded in ADR 0007:
  the payload links `BaseCryptLibMbedTls` whose `CryptAuthenticodeVerify`
  is an unconditional stub, so db **certificate** entries authorize
  nothing while **SHA-256 digest entries** do — enrollment anchors the
  exact signed loader and UKI digests, extracted from their PKCS#7
  signatures (`enroll.signed_digest`, authoritative for both sbsign and
  the firmware). Honest limitation: authenticode excludes the signature
  layer, so same-content signature changes (including none) are
  indistinguishable — the proven guarantee is content integrity; the
  openssl `BaseCryptLib` selection in our own firmware build is deferred
  to the vboot step. Harness fixes on the way: refusal phrases match
  whitespace-normalized serial (the console wraps `Acc\r\ness denied`
  mid-word — this cost three 15-minute timeouts), and QMP socket paths
  are length-guarded against the 108-byte UNIX limit.
- **vboot protected-RW verification adopted and proven** (chain step 4;
  PLAN Phase 2 items 5–6 annotated; ADR 0008): the firmware now builds with
  `CONFIG_VBOOT` on the tracked `q35-vboot.fmd` (SMMSTORE restored 64
  KiB-aligned, RW_NVRAM for flash-backed VBNV, FWID regions sized for the
  real strings). New stages: `futility` (signing tool built from the pinned
  vboot sources, offline), `vboot-keys` (dev keyset under secrets/vboot/:
  root RSA-4096, firmware data key RSA-2048 — vboot's enum has no plain
  RSA-3072), `firmware-sign` (signs RW, **installs our GBB root key** — the
  coreboot build ships upstream test devkeys there and an empty root
  verifies trivially), `check-firmware-vboot` (four sessions with per-boot
  swtpm: signed RW executes with no recovery indication; tampered RW,
  attacker-keyed RW and the no-recovery-payload variant refuse with no
  guest code; writes confined to SMMSTORE + RW_NVRAM). The flash-layout
  classifier was requalified for the nested vboot map (schema 2) and the
  firmware-build now injects and pins the reviewed fmd. Two proof subtleties
  recorded honestly: bytes beyond the vblock's signed body are unverified
  free space (a tamper there is correctly accepted), and a refused RW boots
  the RO recovery payload (full EDK II, still Secure Boot gated) rather
  than halting — the no-recovery-payload session provides the dead-machine
  form. Hardware/ODM transfer notes started at
  `docs/hardware-odm-notes.md`.
- **Step-5 requalification on the enforcing image complete** (ADR 0008):
  `enroll` now consumes the firmware-sign output, so the enforcing image
  carries the vboot-verified RW (our GBB root) *and* the enrolled Secure Boot
  varstore — `check-secure-boot` passes end to end (vboot RW → digest-anchored
  Secure Boot → signed UKI → dm-verity root); `check-boot` requalified on the
  signed firmware (three disciplines, write confinement); device profiles
  provision from `firmware-sign` now — `dev4` cold-boots twice with flash/TPM
  identity continuity on the vboot image. The check-firmware-vboot gate
  (added with step 4) covers the firmware-layer proofs. The current goal's
  exit criteria (G2 + enforcement core of G4) are met on the development
  trust domain; remaining G4 scope (physical, custody, release) stays open.
- Bounded evidence retention tightened (`just prune`): keeps only the
  state-referenced current generation plus device-profile-pinned
  provenance (was current + previous), build ids no longer truncate
  stage names to 15 characters, and the truncated legacy prefixes
  (`check-secure-bo-`, `firmware-source-`) are resolved so those stages
  actually prune; ~64 GB more freed on the development host.
- Development installed-device profile (`just device`): a GPT disk with ESP,
  slot-A root and hash partitions assembled offline from the frozen payloads,
  with systemd-boot taken from the same root archive.
- QEMU Q35 boot gate verification (`just check-boot`): the development disk
  boots through systemd-boot on the self-built coreboot/EDK II firmware; the
  initramfs gate performs full verity preverification, read-only mapping and
  sysroot mount, with a corrupted-root negative control that is denied at the
  exact flip offset. Runtime execution found and fixed four real gate defects.
- Phase 5 measurement groundwork: the boot marker unit dumps the firmware TCG
  event log from securityfs to serial (kernel sysfs per-PCR reads deadlock
  under this QEMU tpm-tis setup after the first read), and
  `src/firearc/tpm_evidence.py` extracts, parses (crypto-agile) and replays
  the banks host-side, with a producer map and an expected/observed
  sensitivity table in
  [TPM measurement validation](validation/tpm-measurements.md). Two honest
  negatives shape the future PCR policy: vboot firmware identity is not
  measured, and UKI signature sections are skipped (the db digest anchor owns
  both distinctions).
- **Signed PCR 11 authorizations embedded in the slot-A UKI** (PLAN Phase 5
  item 5 complete; ADR 0009,
  [validation](validation/pcr-authorizations.md); `just pcr-keys`/
  `just pcr-sign`): a dedicated dev PCR-policy key (RSA-3072, bare PEM
  public key — the pinned systemd-measure rejects certificates) lives under
  `secrets/pcr/` isolated from the sb/db role; the pcr-sign stage rebuilds
  the UKI with the pinned ukify adding `.pcrsig`/`.pcrpkey` for phase
  **enter-initrd** only (pcrphase-initrd's /dev/tpmrm0 extend is real but
  log-invisible; later phases stay unsigned so unlock is authorized in the
  initrd alone). The stage fails closed on four independent agreements —
  the from-spec stub model (name+NUL hash, VirtualSize-exact content hash,
  table order, `.pcrsig` exempt, `.pcrpkey` measured — validated against the
  dev5 replayed log and pinned as test goldens), the pinned
  systemd-measure prediction, the TPM2-spec PolicyPCR digest, and openssl
  verification of the embedded signature. Deterministic PKCS#1 v1.5 keeps
  the policy layer byte-reproducible (double-build enforced, still covered
  by `just reproduce`); `sign` signs this UKI so the db anchor covers the
  policy sections, and the enforcing chain restages through it. Findings on
  the way: `.pcrpkey` changes PCR 11 (key regenerations must and do
  restage the chain), and section content is measured at PE VirtualSize
  (the combined initrd's trailing cpio padding zeros and `.sbat`'s NUL are
  measured content).
- **Per-device LUKS2 data volumes** (PLAN Phase 5 item 6 complete;
  ADR 0010, [validation](validation/data-provisioning.md)): the factory
  disk gained a blank `FIREARC_DATA` partition (256 MiB provisional),
  asserted blank by two independent checks; `device-provision` now
  formats it into a unique LUKS2 volume with the pinned cryptsetup 2.7.5
  (argon2id, aes-xts-plain64) and a 256-bit recovery credential as the
  sole keyslot. The credential is file-handle-only (never argv, serial
  or evidence — re-checked on the real profiles), kept 0600 under the
  profile's `secrets/`, and marked escrow-pending (item 7). The stage
  verifies the credential unlocks (`--test-passphrase`), parses the
  spliced on-disk header both from `luksDump` and from the disk bytes
  (magic/u64 hdr_size/JSON at 0x1000, validated against real cryptsetup
  output), and refuses blank-to-blank formats. Uniqueness proven on real
  provisions (dev7/dev8: distinct uuid, salts, region digests,
  credentials from byte-identical factory images); the sealed region is
  now device identity — asserted per boot session, drift refused at
  `load`. Both enforcing gates re-passed on the 4-partition geometry.
- **TPM2 enrollment with unattended unlock** (PLAN Phase 5 item 8
  complete; ADR 0011, [validation](validation/data-provisioning.md)):
  `just data-enroll` boots the profile once with a one-shot credential
  transport disk and lets the guest enroll at `enter-initrd` —
  `systemd-cryptenroll` with plain PCR 7 binding plus the signed PCR 11
  policy from the UKI's `/.extra` stub files — then validates in the
  same boot with a real unattended attach, and verifies the mutated
  header host-side (keyslots exactly 0+1, one systemd-tpm2 token, signed
  key byte-equal to `secrets/pcr/pcr.pub`). Every boot now carries a
  data-unlock probe on the serial contract (`UNLOCK_OK`/`REFUSED`/
  `TOKEN_ABSENT`), ordered after the root gate and the enter-initrd
  phase — item 10's rule encoded early. Proven on real profiles: dev9
  unlocks unattended across cold boots (region digest stable — unlock
  never writes); dev10 (dev9's disk transplanted onto a fresh swtpm)
  boots its verified root but the probe reports `UNLOCK_REFUSED` — the
  item-12 direction previewed. Interrupted enrollment sessions are a
  first-class case (`enroll_pending` transaction marker + host-side-
  validated adoption). Findings pinned: plain cryptsetup was missing
  from the minimal initrd (probe rc=127 → now asserted by check-initrd);
  stub 257 exposes signature files under `/.extra/`, not `/.tpm2-*`.
- Operations note (recorded after investigating): external `docker image
  prune` deleted the digest-pinned tagless tools and SDK images; the harness
  now treats a cached tools stage whose image is absent from docker as stale
  and rebuilds it. Docker image ids are not rebuild-stable (the rebuilt tools
  image got a new digest while its pinned package inputs stayed identical),
  so the reproducibility claim lives in the package pins, not the image id.

## Validation

The label-free bootstrap/build/verification pipeline and 243 offline tests pass.
The fresh-clone build/verification passed, and `just reproduce --yes` completed
two empty-cache download/build/verification rounds with **byte-identical
payloads** (kernel, initramfs, root tar, ext4, verity tree, authority). The
earlier failures from unsorted tar members and an unpinned ext4 directory-hash
seed are fixed. Scope limits (single host/Python, preserved Docker content
cache, OS payloads only) are recorded with the result.
The development device boot gate passed under QEMU Q35 with KVM, first under
the host OVMF fixture and then with the self-built coreboot/EDK II firmware,
including the corrupted-root denial control; see
[device boot validation](validation/device-boot.md) for evidence and limits.
Results are recorded in [build-system validation](validation/build-system.md)
and [root validation](validation/appliance-root.md); no unrun clean-build or
byte-reproducibility result is implied by the implementation list above.

## Next gates

1. Phase 5 items 7 and 9–15: escrow of the recovery credential (owner
   decision pending on the secret-handling path), crypttab/unlock
   ordering with `/data` mounts (items 9–10), the A/B update-compat,
   move/refusal and tamper matrix (items 11–13), and the escrow
   rehearsal (items 14–15).
2. Phase 6+ (RAUC updates, health/rollback, attestation, recovery, release
   hardening/CI) per PLAN §1.2 after the data-unlock chain lands.
G0/G1/G3 and later acceptance gates remain open. Hardware, legal review,
production signing custody and external design documents are still dependencies.
Git commit signing is temporarily deferred under ADR 0004; boot/update/release
signatures are not waived.
