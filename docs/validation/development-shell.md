# Disposable verified Debian root shell

## Command

```sh
sudo systemctl start docker   # only if the local daemon is stopped
just shell
```

Run from a graphical desktop (`DISPLAY` or `WAYLAND_DISPLAY`). The command
opens a GTK QEMU window with a standard VGA adapter and the Q35 PS/2 keyboard;
it does not require stdin/stdout TTYs. Existing pinned inputs and development
signing keys are prerequisites, as for the normal image build.
Dependency downloads remain explicit (`just bootstrap`, or firmware acquisition
when needed); the shell command is offline. It does not generate trust anchors
or enroll any saved device.

The first invocation builds the separate `shell-uki`, `shell-pcr-sign`,
`shell-sign`, `shell-device` and `shell-enroll` stages through the existing
verified builders. These stages are not dependencies of the normal image or
published output aliases. The shell has its own exact-image Secure Boot variable
store, not the normal artifact's digest allowlist.

## Guest contract

- Only the explicit shell UKI replaces the development smoke terminal with
  a root-shell unit. Normal UKIs keep the smoke terminal and disabled emergency
  shells. The shell unit and verity authority are inside the PCR-policy-signed,
  Secure-Boot-signed UKI.
- The unit requires and follows both verified `sysroot.mount` and the existing
  `firearc-data-mount.service` gate. A root/data failure cannot open a shell.
- `RootDirectory=/sysroot` executes Debian's `/bin/bash`, as UID 0, with API
  filesystems plus the guest `/dev` and `/run`. Bash uses `/dev/tty1` with
  `TERM=linux`: input and output belong to the VGA window, not the host terminal.
  The root remains verity-backed and read-only; `/tmp` is a private writable
  tmpfs. History is not saved.
- The shell UKI keeps `console=ttyS0,115200` for serial kernel diagnostics and
  adds `console=tty0 loglevel=7 systemd.show_status=yes`. VGA becomes the primary
  console for Linux, initrd status and root/data-gate output. Normal image command
  lines remain serial-only. Early coreboot debug output remains intentionally
  quiet; this does not enable firmware debugging or emergency shells.
- The VT is not reset/cleared when Bash starts. Immediately before the banner,
  the unit sends PID 1 its documented `RTMIN+21` signal to stop status updates.
  Otherwise the intentionally pending oneshot job's spinner would overwrite
  the interactive prompt. The UKI section check and device manifest both use
  the selected normal/shell command line.
- This is a fresh factory data partition and fresh swtpm, **not** an enrolled
  saved device. `/data` is not provisioned or mounted; its absence is permitted
  only by the existing factory-volume gate. No recovery credential is copied.
- PID 1 remains the initrd service manager. This is a development chroot
  console, not full switch-root appliance/service integration.
- `exit` requests poweroff through the guest initrd manager. The unit remains
  blocking until shutdown stops it, avoiding a switch-root/shutdown race.
  `SYSTEMD_IGNORE_CHROOT=1` explicitly permits this systemctl request; without
  it systemctl silently ignores poweroff from a chroot.

Click the VGA window to type. `exit` powers off; closing the QEMU window quits
the VM. Press Enter in that window if the known firmware-menu issue stalls boot.
Serial diagnostics go to the temporary session's log; the host terminal is not
connected to the guest keyboard. Normal boot gates remain headless/serial.
The pinned firmware initializes VGA natively, so the adapter's option ROM is
disabled rather than loading an additional host-supplied BIOS.
Networking is disabled. `-snapshot` overlays disk **and pflash**; a temporary
0700 directory holds the fresh TPM state and is removed on normal exit or a
handled exception. The project lock is held throughout, preventing concurrent
build/prune/clean from replacing backing files. The existing QMP/swtpm lifecycle
is reused; QEMU startup failures now explicitly stop the child before cleanup.

## Proof

Offline tests cover normal-vs-shell cpio separation, root/data dependencies,
variant signing/enrollment stages, existing-key requirements, VGA/keyboard and
serial routing, snapshot flags, missing-display refusal, non-TTY desktop launches,
startup cleanup and session cleanup. Both X11 and Wayland environment selection
are covered offline; this does not itself prove a live Wayland session.

### VGA boot-log change: validation pending a new session

293 offline tests pass, including separate normal/shell console policies,
primary-console order, unchanged fail-closed flags, no VT reset, spinner
suppression and matching variant selection for UKI/device builders. An offscreen
live test was attempted but correctly refused because the owner's existing
shell VM held the project lock. That VM was not interrupted. The updated signed
image and live VGA boot-log display have not yet been requalified; exit the
existing VM and rerun `just shell` to rebuild with the new embedded command line.

### Earlier VGA window smoke test (before boot-log routing)

A standard offline `just shell` invocation completed the pinned Docker-backed
build/sign/enroll workflow and opened the GTK VGA window on Q35/KVM with swtpm.
The kernel and manager reached the gated development-shell unit. The owner
closed the window before automated keyboard/TTY assertions or a framebuffer
capture; those live VGA assertions are not claimed here. Native Wayland remains
unqualified (the window smoke test selected GTK's X11 backend).

QEMU exited cleanly after 43 seconds. No QEMU/swtpm processes or `.shell-*`
TPM/scratch directory remained. Both tested artifact receipts were reverified
successfully after exit:

- `shell-device-ce80c7a3908a`
- `shell-enroll-7724b5b7fb51`

An actual no-display CLI invocation refused before building, with exit status 1
and empty stdout. All 292 offline tests pass. The display change does not
constitute new full boot-chain or appliance qualification.

### Earlier serial-console proof

Before the VGA change, live Q35/KVM tests with swtpm reached:

```text
FIREARC_SHELL_UID=0
FIREARC_SHELL_DEBIAN=13.7
FIREARC_SHELL_ROOT=/dev/mapper/firearc-root ext4 ro,relatime,norecovery
FIREARC_SHELL_PROOF_OK
```

The test also checked the serial device, `/proc`, access to the initrd manager,
writable `/tmp`, refusal to create a file under `/etc`, and clean poweroff after
`exit`. All artifact digests still matched after the snapshot-backed boot.

Negative control: corrupt a root block on a disposable disk copy. Verity refused
it, the guest powered off, **no shell banner or prompt appeared**, and the disk
was byte-identical to its corrupted pre-boot state afterward.

### Earlier serial-proof environment limitation

During the earlier serial-console proof, the host Docker daemon was stopped and could not be started noninteractively
because sudo requires the owner's password. Consequently the complete
`just shell` Docker-build invocation could not be exercised here. For live guest
proof, the same UKI/PCR/sign/device/enrollment builder functions used the retained,
digest-verified exported tools filesystem in an unprivileged, network-isolated
namespace, with verified retained root payloads. All normal double-build,
section, policy, signature and artifact checks ran. The resulting artifacts
then booted through the actual shell runtime and QEMU snapshot path.

That test-only runner is not a product fallback or an acquisition path. Start
Docker before using `just shell`; normal build verification still uses the
existing pinned Docker workflow. No production or complete-appliance
qualification is claimed.
