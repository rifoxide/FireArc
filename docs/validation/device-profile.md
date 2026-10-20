# Persistent device profile validation

## Scope

`just device-provision --name <n>` explicitly creates a persistent
installed-device profile under `build/devices/<n>/`, and
`just device-boot --name <n> --count <k>` cold-starts it k times. A profile is
mutable machine state, deliberately outside the reproducible stage graph: the
OS disk, the writable firmware copy (whose SMMSTORE region carries UEFI
variables) and one isolated swtpm TPM 2.0 state directory survive every boot.
Every machine session runs under a **local-only QMP control socket** (unix
socket inside the run directory; never TCP) so the harness — not the guest —
ends each session, and serial evidence is captured headlessly per run.
Interactive support sessions that could contain recovery secrets are not
captured at all.

Operator operations on a running profile, all explicit and recorded in the
profile's operations history:

| Command | What it does |
| --- | --- |
| `just device-reboot --name <n> --resets <k>` | warm-reset loop in ONE powered session (same QEMU+swtpm; flash/TPM stay powered through every reset); ends on a full verified boot |
| `just device-stop --name <n>` | boot to the verified marker, request power-down over QMP; whether the appliance honors the ACPI power button is recorded, and the harness stops the machine itself if it does not |
| `just device-powercut --name <n>` | let the machine settle into the booted OS, then SIGKILL QEMU and swtpm (no TPM2_Shutdown, no variable flush) and assert nothing silently reset |
| `just device-snapshot --name <n> --label <l>` | immutable, digest-verified copy of disk + flash + TPM state |
| `just device-restore --name <n> --label <l>` | the only state-restoration path: explicit operator command, never implicit |

A failed session that already ran the machine adopts the observed flash/TPM
identity as the new baseline with an explicit `failed` operations record —
later sessions assert continuity from what actually happened, and nothing is
ever silently reset. QEMU and swtpm carry `PR_SET_PDEATHSIG`, so orphaned
machines cannot outlive the harness process.

This is the development trust domain: unsigned profile, host-trusted QEMU and
swtpm custody, no PCR measurements (the pinned EDK II payload contains no TPM
stack).

## State layout and operations

| Path | Role |
| --- | --- |
| `disk.raw` | persistent OS disk (copy of the device-stage disk at provision time) |
| `flash.rom` | persistent writable firmware copy; SMMSTORE variables evolve across boots |
| `tpm/` | per-device swtpm state (`tpm2-00.permall`), created on first boot |
| `runs/<nnnn>/` | per-cold-start evidence: serial log, swtpm log, run record |
| `profile.json` | provenance (exact disk/firmware stage labels and digests), boot count, last post-boot identity |

Provisioning refuses to overwrite an existing profile unless `--replace` is
passed — an ordinary command never silently resets flash/TPM identity. Each
cold start is a fresh QEMU process plus a fresh `swtpm socket --tpm2` instance
over the same state files; swtpm terminates when QEMU disconnects.

Every cold start must reach the verified read-only sysroot marker
(`FIREARC_DEV_BOOT_OK`), must bind a TPM 2.0 device through ACPI/TIS
(`FIREARC_TPM_TIS_OK`), and must keep all flash writes inside SMMSTORE
(`FIREARC_TPM_TIS_MISSING`, verity denial or outside-store writes fail the
gate). Between boots — including across separate `device-boot` invocations —
the SMMSTORE digest and the TPM state inventory must be byte-stable unless the
guest changed them; movement outside guest execution fails closed.

## Qualification evidence (2026-10-20, KVM)

Profile `dev1`, two cold starts (`--count 2`):

- Both boots reached all boot markers and `FIREARC_TPM_TIS_OK`. Console
  diagnostics: class `tpm tpmrm`, `/sys/class/tpm/tpm0` with
  `tpm_version_major=2`, and both `/dev/tpm0` and the resource manager
  `/dev/tpmrm0` present. The kernel's built-in `tpm_tis` driver
  (`CONFIG_TCG_TIS=y` in the Debian kernel) binds QEMU's `tpm-tis` device
  through the TPM2 ACPI table (`MSFT0101`); no initrd TPM support is needed.
- Flash: run 1 initialized the erased variable store (33,892 bytes changed
  inside SMMSTORE; `FMAP`/`BOOTSPLASH`/`COREBOOT` byte-identical to the
  pristine ROM). Run 2 began from exactly run 1's post-boot SMMSTORE digest
  and evolved it further (34,104 bytes, still confined).
- TPM: run 1 created `tpm2-00.permall`; run 2 began from exactly run 1's
  state-file digests and the kernel's TPM startup changed state again inside
  the boot. State persisted across both cold starts.
- Disk: byte-identical after both boots (read-only verity root, nothing wrote).

### Gate G1 sequence (profile `dev2`, 2026-10-20, KVM)

Eleven recorded operations, audit trail in the profile:

- **2 cold starts**: variable store initialized then evolved inside SMMSTORE
  only; TPM state carried byte-exactly between boots; markers reached.
- **Warm-reboot loop (`--resets 2`)**: one QEMU process and one swtpm process
  served 3 boots. The dev unit's terminal marker printed 6 times (twice per
  boot) and the TPM TIS marker 3 times (once per boot); the variable store was
  carried across resets and evolved (`…62cf2 → …a28ae`), never restored to the
  pristine image; every flash write stayed confined to SMMSTORE; QEMU exited
  rc 0 under QMP control.
- **Stop**: power-down requested over QMP after the verified marker; the
  appliance **ignored the ACPI power button** for the bounded 30 s window
  (recorded `acpi_powerdown_honored: false`), and the harness stopped the
  machine itself (clean rc 0). An earlier stop attempt failed closed before
  this behavior was understood (see findings); its observed state was adopted
  with an explicit failed-operation record.
- **Snapshot `pre-powercut`**: disk + flash + TPM copied, manifest digests
  recorded, immutable afterwards.
- **Power cut**: after the marker the machine settled into the fully booted
  OS, then QEMU and swtpm were SIGKILLed (rc −9). The variable store had
  moved only by that session's legitimate guest writes and did not revert to
  the pristine image; TPM state survived; the next cold start booted the
  machine from exactly the post-cut state (crash recovery).
- **Explicit restore `pre-powercut`**: state replaced by operator command,
  identity baseline reset to the snapshot's; the following boot reached the
  verified marker from the restored identity.

## Findings recorded during qualification

- **Payload boot-menu stall (intermittent, real defect):** the EDK II payload
  sometimes parks at its interactive menu ("ENTER to boot directly") and
  never auto-continues — observed twice for 16+ minutes from pristine
  variable stores and once from an initialized store (TCG run 0011), while
  many other boots auto-continued (3 stalls / 8+ passes observed). The
  harness sends a bounded ENTER keypress over QMP (`input-send-event`;
  QEMU 11 removed `sendkey`) after 45 s of serial silence, at most 3 times,
  every keypress recorded in run evidence (`menu_unstick_keypresses`); the
  nudge fired for real during qualification (runs 0007 and 0011). The
  payload's menu behavior needs review before release.
- **ACPI power button is not handled** by the development appliance: a QMP
  `system_powerdown` request is ignored for the whole bounded window (no
  logind power-key handling in the minimal root). `device-stop` records this
  honestly and stops the machine itself. The production appliance needs an
  explicit power-button policy.
- **The dev unit's poweroff is best-effort only:** the unit runs in the
  initrd, and switch_root's `initrd-cleanup.service` stops it — including its
  grace sleep — before its fallback `poweroff -f` can run. Every session is
  therefore ended by the harness over QMP (orderly quit, powerdown request
  or hard kill), and QEMU/swtpm carry `PR_SET_PDEATHSIG` so orphaned
  machines die with the harness process.

- **Duplicate ACPI TPM object:** QEMU's board ACPI exposes the TPM as two
  `MSFT0101` devices; the second probe fails `-EBUSY` on the same MMIO region,
  so exactly one TPM chip binds. No duplicate TPM resource is usable — the
  failure is fail-closed — but the artifact is worth knowing when reading
  boot logs.
- **CRB not assumed:** QEMU also offers `tpm-crb`; this profile qualifies TIS
  only and does not assume interface interchangeability.
- **Firmware TPM usage is absent:** the pinned payload contains no Tcg2/TPM2
  stack (0 matches in the ROM) and coreboot selects no TPM bus interface for
  this board, so no firmware measurements occur. TPM measurements remain
  Phase 5 work.
- **Shutdown race (fixed):** the dev unit previously used
  `systemctl --no-block --force poweroff`, which once lost the race to
  `switch_root` and booted into the real root's login prompt. The unit now
  issues the immediate `poweroff -f` syscall (systemctl fallback retained).
- QEMU provides no persistent CMOS backend; no CMOS state is carried.

### Accelerator profiles

`device-boot --tcg` forces the software-accelerated machine; every run
records its accelerator. Qualified 2026-10-20 on `dev2`: the TCG profile
passed the same marker/TPM/write-confinement gate in ~75 s wall time versus
~23 s for KVM (≈3.2×), with one boot-menu stall observed under TCG from an
already-initialized store (unstuck by the recorded ENTER nudge). There are no
firmware TPM measurements to compare between profiles yet — the pinned
payload has no TPM stack (Phase 5 will revisit).

## Limits

- swtpm state is host-readable state; a host administrator can snapshot or
  replace it (QEMU threat model: host trusted).
- Identity continuity is asserted at boot boundaries (digests before/after),
  not continuously during a boot.
- One host, one profile, KVM; TCG cold-start equality is a separate profile
  (PLAN 1.16).
