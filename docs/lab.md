# Q35 research laboratory runbook

This is the first Phase 1 regression fixture, **not the final installed GPT
appliance**. It reproduces direct signed-UKI/full-verity boot before the mkosi,
systemd-boot, encrypted-data and update implementation.

## Preconditions

- Linux x86-64, Python 3.11+, Git; `just` optional.
- Exact compatibility-pinned QEMU/QEMU-img; debugfs and veritysetup for root
  mutations, swtpm for optional TPM attachment. `just doctor` reports them.
- Approximately 1.4 GiB for the curated import, plus space for evidence and
  negative-test copies. Original full archive verification reads about 2.3 GiB.
- Workspace path without commas/control characters; Unix socket paths must fit
  Linux limits. Do not run with sudo, host block devices or host TPM passthrough.

No command here downloads software, mounts host images, installs host packages,
changes firmware on the host or reads signing/recovery credentials.

## Verify and import once

```sh
just check
just research-verify /home/rifat/projects/project_firearc
just baseline-import /home/rifat/projects/project_firearc
```

Only the five allowlisted public archives are visited, and only manifest-listed
regular files are read. Pins, duplicate/traversing paths, symlinks and private PEM
material are checked. Import uses a fresh staging directory and publishes a new
import only after copy/readback verification. An interrupted import remains for
inspection; there is no automatic recursive cleanup or `--force` bypass.

The original checkout is used only for verification/import. Later runs use local
imported artifacts and reverify them before/after every boot. They do not execute
its launchers or depend on its old private-key directory.

## Persistent device, fresh cold boots

```sh
just baseline-new baseline-a
just baseline-run baseline-a --label good-a
just baseline-run baseline-a --label good-b
```

`baseline-new` is the only operation that creates device flash/disks. It fails if
that ID exists. `baseline-run` fails if state is absent/incomplete/ambiguous and
never creates a replacement. It locks the device against concurrent runs.

Normal run behavior:

1. Verify the input set, tool pins, overlay parents and non-variable flash region.
2. Reuse `pflash.raw`, `root.qcow2`, `hash.qcow2` from `run/devices/<id>/`.
3. Launch pinned Q35/TCG headlessly with no NIC and a private local QMP socket.
4. Capture only the automated locked-root self-test; require the full acceptance
   report, exact db/cmdline/live verity geometry and clean guest poweroff.
5. Reap owned subprocesses, compare guest root/hash contents with their inputs,
   verify firmware changes are confined to SMMSTORE and reverify the import.
6. Write exclusive evidence/results and SHA256SUMS under `boots/<label>/`.

A second cold boot must produce a different kernel boot ID without replacing the
device's flash/disks. This demonstrates harness persistence, not encrypted-data
provisioning, CMOS-vboot state handling or complete authenticated-variable policy.

## Negative controls

Use fresh labels. These deliberately test rejection, not final automatic fallback:

```sh
just baseline-run baseline-a --label executable-a --scenario data-executable
just baseline-run baseline-a --label unused-a --scenario data-unused
just baseline-run baseline-a --label tree-a --scenario hash-tree
just baseline-run baseline-a --label pair-a --scenario replacement-pair
just baseline-run baseline-a --label unsigned-a --scenario unsigned
just baseline-run baseline-a --label wrong-a --scenario wrong
just baseline-run baseline-a --label tampered-a --scenario tampered
```

Root mutations use per-run copies. The coherent replacement pair is verified
against its own new digest on the host, then must fail against the unchanged
signed-in authority in the guest. Executable/unused-block/tree mutations must
fail full scanning **before mapping or normal readiness**.

Firmware negatives must show Secure Boot denial before any Linux/root marker.
The harness then quits QEMU and records `host_stopped_after_denial=true`.
**That is not guest automatic rollback.** The historical fixture lacks fallback;
Phase 7 must implement and prove it rather than reclassify this result.

## Optional persistent swtpm attachment

```sh
just baseline-new tpm-smoke-a --tpm
just baseline-run tpm-smoke-a --label first-a
just baseline-run tpm-smoke-a --label second-a
```

Each device gets its own ignored `tpm/` directory, one foreground swtpm process,
0600 state/socket settings and QEMU's TIS frontend. The harness does not clear,
re-enroll or copy the TPM during ordinary boots. No host `/dev/tpm*` is opened.

Explicit creation initializes the software TPM once. Ordinary boot requires its
existing nonempty, owned 0600 persistent-state file and refuses missing/empty or
symlinked state **before launching QEMU**, rather than manufacturing a new TPM.

Attaching/persisting swtpm is **not evidence of EK/AK enrollment, measured-log
correctness, TPM-sealed LUKS unlock or remote quotes**. Those require Phases 5/8.
Do not inspect/archive raw TPM state as public evidence.

The inherited firmware currently produces an additional ACPI TPM probe for the
same `0xfed40000` resource, which fails with `-EBUSY` after the first TPM 2.0
probe succeeds. Preserve that warning (R18); fix/qualify table ownership in the
source-built firmware before accepting measured-boot or data-unlock policy.

## Live control and failures

While a run is active, from another terminal:

```sh
just baseline-control baseline-a status
just baseline-control baseline-a reboot
just baseline-control baseline-a stop
just baseline-control baseline-a powercut
```

Commands address the device's validated local QMP socket, not a stored PID.
`stop` requests ACPI shutdown; `powercut` quits QEMU abruptly. Host-issued control
is journaled as a requested action before it is sent (not proof it succeeded),
but is not automatic recovery or a complete
physical-storage power-loss model. An interrupted acceptance run may correctly
finish FAIL; do not relabel it PASS.

Ctrl-C/SIGTERM stops and reaps only subprocesses owned by that invocation. Evidence
and device state remain. If the harness is killed ungracefully, an `active.json`
may remain; subsequent runs refuse it. Inspect the referenced processes/socket
and resolve only that stale record after confirming the device is stopped. Do
not delete/reset the disk, flash, TPM tree or reference project to hide failure.

No snapshot/restore/reset workflow or final installed-device profile is qualified
by this milestone. Add those with explicit authorization and tests in later work.
