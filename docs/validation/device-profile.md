# Persistent device profile validation

## Scope

`just device-provision --name <n>` explicitly creates a persistent
installed-device profile under `build/devices/<n>/`, and
`just device-boot --name <n> --count <k>` cold-starts it k times. A profile is
mutable machine state, deliberately outside the reproducible stage graph: the
OS disk, the writable firmware copy (whose SMMSTORE region carries UEFI
variables) and one isolated swtpm TPM 2.0 state directory survive every boot.
This is the development trust domain: unsigned profile, host-trusted QEMU and
swtpm custody, no PCR measurements (the pinned EDK II payload contains no TPM
stack), no warm-reboot loops, no power-cut or snapshot operations.

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

## Findings recorded during qualification

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
- **One-time payload menu stall (open):** in one run the EDK II payload sat at
  its interactive boot menu ("ENTER to boot directly") from a pristine
  variable store and never auto-continued; the 1800 s per-boot timeout fails
  the gate closed in that case. Not reproduced in subsequent boots; if it
  recurs, the payload's menu condition needs investigation.
- QEMU provides no persistent CMOS backend; no CMOS state is carried.

## Limits

- swtpm state is host-readable state; a host administrator can snapshot or
  replace it (QEMU threat model: host trusted).
- Identity continuity is asserted at boot boundaries (digests before/after),
  not continuously during a boot.
- One host, one profile, KVM; TCG cold-start equality is a separate profile
  (PLAN 1.16).
