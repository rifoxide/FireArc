# Read-only research reuse inventory

**Reference:** `/home/rifat/projects/project_firearc`. **Recorded:** 2026-10-19.
Primary map: `docs/boot-chain-file-map.md` in that checkout (EXP-029, not EXP-028).
The old checkout and external private-key custody remain untouched.

## Inputs and decisions

| Input | Original location | Treatment |
| --- | --- | --- |
| Nine source pins | `configs/q35-sources.tsv`, `configs/q35-extra-sources.tsv` | Recorded in `locks/firmware-sources.json`; check exact HEAD and tracked cleanliness |
| Original source Git checkouts | `run/q35/sources/`, `run/q35/extra-sources/` | Read-only inventory, no recursive submodule init or patching |
| Expanded firmware config, ROM, payload/patch/build metadata | `artifacts/exp-029/firmware-a/` | Verify whole pinned manifest; import only public ROM/config/patch/pins/SDK metadata |
| Verified-root build | `artifacts/exp-029/build-root-h/` | Verify whole pinned manifest; import only final `output/root.ext4` |
| Signed-in verity authority/tree | `artifacts/exp-029/prepare-e/` | Verify whole pinned manifest; import `root.verity` and `verity.json` |
| Public trust records | `artifacts/exp-029/keys-a/` | Verify public archive only; import `public/db.der`; no external key tree access |
| Signed/negative UKI media | `artifacts/exp-029/sign-e/` | Verify whole pinned manifest; import good/unsigned/wrong-key/tampered FAT images |
| Prior validation and boot reports | `artifacts/exp-029/validation-a/`, `boot-*/`, experiment report | Historical evidence, not silently counted as a new run |
| Old scripts and initramfs recipe | `scripts/debian-verity.py`, `scripts/verity_lab.py`, `configs/debian-verity/` | Read as reference for independent regression implementation; never execute them from this repo |
| SDK | Digest in `firmware-a/sdk.json` and plan | Recorded compatibility anchor; Docker storage not copied or rebuilt yet |
| Debian package plan/cache | `plan-root-a/packages.json`, `acquire-root-a/`, `plan-tools-b/` | Historical binary-package provenance; new mkosi package closure still needed |
| External private signing keys | Outside research checkout | Not read, hashed, copied or needed by this milestone |

## Verification performed

The new read-only verifier checks five pinned SHA256SUMS files and **582 listed
files**, and all nine source HEADs/absence of tracked modifications. These
upstream publisher signatures are **not verified**. Untracked files and unused
archive contents are not approved source/build inputs merely because the tracked
tree is clean.

The new import copies 13 explicit files plus the original manifests and its own
provenance report. It is intentionally **not a full archive clone**. Unlike the
old launcher, the new runner validates this curated set independently and does
not need unrelated EXP-028 archives, old private keys or original absolute paths.
The absolute `root_image` string inside historical `verity.json` is metadata only;
the runner always uses its own verified imported `root.ext4`.

Public certificate SHA-256 fingerprints (DER, historical lab trust only):

| Role | Fingerprint |
| --- | --- |
| PK | `b864e8dbfa8691bc8bd7a1294018759ff5fab1eade6abb39f0587cb57c90e3f0` |
| KEK | `c45f1b566920bacd4375e6fbcf6bbbeae9dcb9ba506655133ab12111be22dd29` |
| db | `bee9f57262b7ebc2b4755cb965236941ce311b51939bdb3967613d755637c909` |

These certificates identify the EXP-029 disposable lab roles; validity is
2026-10-19 through 2026-11-18. Do not confuse certificate expiration with
firmware-enforced revocation. The expected EDK II db signature-list hash is
`60256f95d0b86648c4095321533c6e34664b2760443c816252e0857fdf3822e7`.

## Known research limitations preserved, not adopted as release policy

- Direct UKI boot, no systemd-boot; no A/B/RAUC, encrypted data or quotes.
- vboot disabled despite available vboot library and measured-boot build options.
- Original successful launch had no attached TPM.
- Original fresh-flash self-test powers off; it is not a persistent appliance.
- Lab patch removes inherited dbx and supplies disposable 30-day test trust.
  Keep that patch as evidence only, not the final revocation design.
- systemd 262 host stub versus systemd 257 root; new versions need alignment.
- Old images are binary-package builds and do not establish reproducible release
  images or a whole-Debian source rebuild.
- No forwarding result follows from reaching `FIREARC_ROOT_READY` with no NIC.

## Hidden/local dependencies

The old `.gitignore` excludes `run/` and `artifacts/`. Its Git clone alone does
not supply sources, archives, root images, UKIs, ROMs, package caches, patched
workspaces or local Docker images. Some source progress was uncommitted when the
map was written. Never overwrite local files or bypass a verification failure to
make a transplant work. New local runtime outputs also remain ignored/private.
