# EXP-002 — authenticated Debian tools and rootless mkosi smoke

**Date:** 2026-10-19. **Result:** PASS for the bounded development-builder tests
below. G1/G3/G11 remain open; this is not an appliance or release result.

## Inputs and execution

- Debian trixie amd64 snapshot `20261018T000000Z`, explicit main/security indexes;
  keyring/metadata/OCI/tool pins in `locks/debian-build.json`.
- Both InRelease signatures verified; authenticated Release bytes match pins;
  both raw Packages indexes match signed Release SHA-256/size entries.
- Empty-status APT planning selected 231 packages, 81,766,752 bytes. Every package
  matched signed index authority and passed size/SHA-256 checks.
- Offline, nonprivileged Docker tools build:
  `sha256:f70715d52f26ad15d11b262dd987cbb971a8153b2f8a0bb8718e559dd27ab2ac`.
- Public-only tools export: 7,694 inventoried entries. No signing keys or host
  device/TPM access. Original research project remains unchanged.
- mkosi 25.3-7 under recorded host Python, exported Debian tools, unprivileged
  user/mount/PID/network namespaces. No host package installation or sudo.

## Retained attempts and corrections

| Evidence | Result / interpretation |
| --- | --- |
| `artifacts/builder/tools-a/` | Planning failed on valid APT URI lines without MD5. Parser corrected to use signed SHA-256 authority, never require/trust MD5. |
| `artifacts/builder/tools-b/` | Plan, acquisition and offline tools build passed. |
| `tools-b/export-3d8a7107cd4d/` | Copies/removal completed, initial inventory refused literal backslash in a systemd unit name. Completed the recorded export with explicit resume; strict imported path handling unchanged. |
| `artifacts/images/summary-a/` | mkosi recipe summary passed. |
| `artifacts/images/smoke-a/` | Build failed: traditional APT list supplied as a Deb822 `.sources` file. Corrected format. |
| `artifacts/images/smoke-b/` | Build failed: local mirror intentionally lacks translations. Disabled translation acquisition. |
| `artifacts/images/smoke-c/` | Build failed: Debian bootstrap opens local `file:` paths outside mkosi's sandbox. Used local-only `copy:` transport so packages enter the translated APT cache. |
| `artifacts/images/smoke-d/`, `smoke-e/` | Builds passed; identical manifests but different tars. Member comparison isolated loader auxiliary cache and alternatives log. Not reproducible results. |
| `artifacts/images/smoke-f/`, `smoke-g/` | Builds passed; removal list was mistakenly space-separated, so volatile files remained. Corrected to repeated `RemoveFiles=` entries; no reproducibility claim for these attempts. |
| `artifacts/images/smoke-h/`, `smoke-i/` | Fresh builds passed, selected tar invariants passed, tar and manifest hashes identical. |

The passing tar has 3,895 members, a locked root account, unprovisioned
`etc/machine-id`, installed systemd `257.13-1~deb13u1`, and no repository source
files, SSH host keys, or the two identified volatile files. These selected checks
are not complete hardening or arbitrary-secret detection.

## Evidence pins

Both `smoke-h` and `smoke-i`:

| Artifact | SHA-256 |
| --- | --- |
| `firearc-root-smoke.tar` | `d5a073cf53cda8b15eda7304ea40efd80f05a8a07420d04413695d5106397a51` |
| `firearc-root-smoke.manifest` | `83ea38a61b7ab163c172eff6cf0e4bfd3e9b64524ba02163faef8b4b51f9e3f4` |

The local `artifacts/builder/exp-002-evidence.json` pins input locks, recipe,
metadata result, tools plan/build/export/inventory, both image input/result/
inspection records, exact build commands/logs and output files. Its SHA-256 is
`51216d2f21c0dad6bdfd70b24c5e76c43867d926a98c8c81444b0a166ae87620`.
Tools inventory and output hashes were reverified when publishing that record.

## Limitations and next gate

- Same-host, same-day repeatability only. Host Python/kernel/namespace helpers
  and Docker are still trusted environmental dependencies. Shadow account dates
  and cross-host/date behavior need explicit normalization/qualification.
- No OCI publisher-signature verification, independent keyring trust review or
  CVE/license approval is claimed. Fixed historical metadata expiry exception
  does not waive signature/hash authentication.
- Nonbootable unsigned tar: no kernel, initramfs, verity tree, installed GPT
  layout, systemd-boot path, TPM policy, RAUC or hardware qualification.
- Next: separate appliance package closure and bootable root/initramfs/verity
  build, with aligned systemd artifacts and dedicated signing custody decisions.

See [builder runbook](../builder.md) for commands and trust boundaries.
