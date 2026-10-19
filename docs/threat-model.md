# Threat model

**Scope:** secured boot and atomic updates on Q35 first, with separate physical
hardware qualification. The development host, hypervisor, build user and Docker
daemon are trusted. This is not a hostile-host sandbox or hardware certification.

## Assets and adversaries

Protect firmware/OS authorization, executable root integrity, device identity,
encrypted persistent data, update/rollback state and recovery authorization.
Consider offline disk replacement/modification, ESP tampering, unsigned/wrong-key
images, rollback to old valid releases, interrupted updates, stolen devices and
unauthorized recovery. Physical SPI/fuse/ME/TPM attacks require hardware evidence.

## Build trust

- Git source/configuration/locks are reviewed inputs. Generated artifacts and
  mutable caches are not upstream authority.
- The pinned Debian OCI digest is the keyring bootstrap trust anchor. No OCI
  publisher-signature verification or complete CVE approval is claimed.
- Debian InRelease signatures authenticate Release/index records; project pins
  fix snapshot contents. Package sizes/hashes and complete closure fingerprints
  prevent dependency drift. Historical metadata expiry does not waive signatures.
- Containers/namespaces prevent accidental host-device/key access; they do not
  defend against a malicious host, daemon, kernel or authorized build user.

## Runtime trust contract

Firmware must enforce the approved UEFI policy, then signed systemd-boot and a
signed UKI must authenticate the kernel, initramfs and root authority. The initrd
must fully verify the protected root before a read-only dm-verity mapping/mount.
Slot/disk/boot-ESP selection must reject ambiguity, and no raw-root fallback or
unauthenticated shell may bypass that gate.

Hashing detects modifications, not confidentiality loss. Persistent data needs
TPM-bound LUKS2 plus an explicit signed PCR policy, enrollment/rotation handling
and unique escrow credentials. Signed old images require separate rollback and
revocation policy. Data schema migrations must preserve authorized rollback.

Recovery/reset/break-glass must be restricted, signed and operation-bound. HSM
custody, two-person approval and hardware-root/flash protections are independent
gates, never implied by a successful QEMU or offline build check.

## Evidence and private state

Build output/download/log trees are ignored and privately owned. No private
signing key or populated device/TPM identity belongs in Git or generic images.
Future device provisioning/reset must be explicit; ordinary boot must never
silently recreate identity state. Credential-pattern screening is useful but
not proof that arbitrary secrets are absent.

Actual acceptance limits are maintained in [progress](progress.md),
[risks](risks.md) and [validation](validation/README.md).
