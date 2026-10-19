# Implementation progress

**Updated:** 2026-10-19. **Stage:** Phase 0 / Phase 1 foundation, in progress.

## Implemented

- Recorded PDF SHA-256, stable requirements, scope, threat assumptions, accepted
  user decisions, initial owned-role risks and research reuse inventory.
- Added ignore rules, repository-only credential screening and offline tests.
- Recorded the nine inherited source pins, five historical archive-manifest pins,
  firmware SDK digest and local QEMU/swtpm/mutation-tool compatibility hashes.
- Added a read-only verifier and curated public import without executing old
  scripts or reading external private signing keys.
- Added explicit research-device creation, persistent flash/root/hash state,
  optional isolated swtpm, exclusive locks, headless runs and local QMP control.
- Added full acceptance/rejection checks, copied per-run tooling, hashes/commands,
  retained failure evidence and post-run input/flash/disk/process checks.
- Added signed Debian snapshot metadata import, exact APT tools planning,
  size/SHA-256 checked acquisition, offline Docker tools build and public-only
  tools export with filesystem inventory and interrupted-export recovery.
- Added a rootless, network-isolated mkosi smoke recipe and tar-content checks.
  See [builder runbook](builder.md); this output is nonbootable and unsigned.

## Verified so far

- Supplied PDF matches its recorded hash.
- Five historical public manifests and 582 listed files match their pins.
- All nine source checkouts match exact HEADs and have no tracked changes.
- The curated import contains only 13 explicit public files plus manifests/report.
- `just check` passes 66 offline tests, the lock/specification check and known
  credential-pattern screening.
- Two non-TPM cold boots, all seven UKI/root negative controls and a final good
  boot after the negatives passed in the independent persistent-state harness.
- Two cold boots with the same isolated swtpm-backed research device passed the
  existing Secure Boot/verified-root acceptance checks. Linux detects TPM 2.0,
  but also reports a duplicate ACPI TPM resource/probe warning (R18). This is an
  attachment/persistence smoke result, not measured-boot/data-policy qualification.
- Missing software-TPM state is refused before a VM starts, without reading or
  recreating that state. Initialization happens only in explicit device creation.
- A swtpm/QEMU normal-shutdown race was retained as a failed run and corrected;
  two new-label cold-boot retests passed on the same unreset device. Guest TPM
  detection, live QMP status/journaling and process/state checks passed.
- Evidence and manifest pins: [EXP-001](experiments/EXP-001-foundation.md).
- Both Debian InRelease signatures and package-index authorization passed;
  231 planned packages (81,766,752 bytes) were acquired and verified. The tools
  image built with no network or privileged mode. mkosi 25.3 built a Debian
  systemd 257.13 nonbootable root tar inside unprivileged namespaces.
- Two fresh smoke builds produced identical tar/manifest hashes after removing
  volatile build caches/logs. Selected tar safety checks passed. Same-host/day
  scope and retained failures: [EXP-002](experiments/EXP-002-builder-smoke.md).

## Gates not closed

G0 remains pending owner/security review and unavailable external inputs. G1 is
partial: a portable builder/package closure, fresh source rebuild, installed GPT
device profile and complete snapshot/control fault coverage are still required.
Git commit signing is temporarily deferred by the owner under ADR 0004, not a
current implementation blocker. The regression fixture is not the final appliance.
The reproduced negative matrix uses persistent flash rather than recreating it
for every run; the original fresh-flash-per-negative variant remains unrerun.

Still unimplemented: bootable appliance mkosi build, final kernel/initramfs, systemd-boot, A/B slot
assessment, TPM data policy/LUKS2/escrow, RAUC integration, health/rollback,
attestation, restricted recovery, firmware verification/updates/rotation,
production custody, release CI/SBOM/hardening and hardware qualification.

## Next implementation slice

1. Extend the pinned isolated mkosi/Debian smoke builder to the bootable appliance
   and its separate package closure. Complete portable host-tool and trust/CVE
   review; do not silently install host packages or replace inherited dependencies.
2. Rebuild the root/initramfs/verity payload and install signed systemd-boot in the
   actual boot path, before claiming the Phase 4 gate.
3. Resolve R18 in fresh source-built firmware before qualifying measured boot,
   TPM data policy or remote attestation.

No implementation commits/releases have been made by this milestone. The initial
documentation commit was pushed earlier. The owner has explicitly deferred Git
commit signing for now; no key generation or global Git changes are authorized
or needed. This does not waive any boot/update/release-artifact signature.
