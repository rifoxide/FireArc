# Disposable verified Debian root shell

## Command

```sh
sudo systemctl start docker   # only if the local daemon is stopped
just shell
```

Use a real terminal; stdin and stdout must both be TTYs. Existing pinned inputs
and development signing keys are prerequisites, as for the normal image build.
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
  filesystems plus the guest `/dev` and `/run`. The root remains verity-backed
  and read-only; `/tmp` is a private writable tmpfs. History is not saved.
- This is a fresh factory data partition and fresh swtpm, **not** an enrolled
  saved device. `/data` is not provisioned or mounted; its absence is permitted
  only by the existing factory-volume gate. No recovery credential is copied.
- PID 1 remains the initrd service manager. This is a development chroot
  console, not full switch-root appliance/service integration.
- `exit` requests poweroff through the guest initrd manager. The unit remains
  blocking until shutdown stops it, avoiding a switch-root/shutdown race.
  `SYSTEMD_IGNORE_CHROOT=1` explicitly permits this systemctl request; without
  it systemctl silently ignores poweroff from a chroot.

QEMU's serial console is inherited directly, with **Ctrl+A, then X** as its
quit sequence. Press Enter if the known firmware-menu issue stalls boot.
Networking is disabled. `-snapshot` overlays disk **and pflash**; a temporary
0700 directory holds the fresh TPM state and is removed on normal exit or a
handled exception. The project lock is held throughout, preventing concurrent
build/prune/clean from replacing backing files. The existing QMP/swtpm lifecycle
is reused; QEMU startup failures now explicitly stop the child before cleanup.

## Proof

Offline tests cover normal-vs-shell cpio separation, root/data dependencies,
variant signing/enrollment stages, existing-key requirements, console descriptor
inheritance, snapshot flags, non-TTY refusal, startup cleanup and session cleanup.

Live Q35/KVM tests with swtpm reached:

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

### Test environment limitation

The host Docker daemon was stopped and could not be started noninteractively
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
