# Variable-store enrollment qualification

**Scope:** offline qualification of the `enroll` stage (chain step 3c). This
page documents how the constructed variable store was validated against the
pinned firmware's own format and behavior — **no enforcement claim is made
here**; boot-time enforcement and rejection proofs are tracked separately
(step 3d, plan items 13 of Phase 2 and 4).

## Format ground truth (pinned EDK II sources)

Every structure the stage writes was read from the exact sources the
firmware was built from (`build/firmware/firmware-source-*/sources/edk2`,
the pinned commit the build configuration binds to):

| Structure | Source file | Facts used |
| --- | --- | --- |
| `VARIABLE_STORE_HEADER` | `MdeModulePkg/Include/Guid/VariableFormat.h` | 28 bytes (`Signature`/`Size`/`Format`/`State`/reserved); `FORMATTED 0x5a`, `HEALTHY 0xfe` |
| `AUTHENTICATED_VARIABLE_HEADER` | same | 60 bytes packed; `StartId 0x55AA`, state `VAR_ADDED 0x3f`; name null-terminated UTF-16LE |
| entry advance | `VariableParsing.c` (`GetNextVariablePtr`, `GetStartPointer`) | first entry at FV header + 28; `ALIGNMENT 1` means no name/data padding, entries 4-byte aligned |
| store size | `UefiPayloadPkg.dsc` `PcdVariableStoreSize\|0x10000` | variable store spans 64 KiB (`Size = 0xFFB8`) inside the 256 KiB SMMSTORE region |
| enforcement gate | `DxeImageVerificationLib.c` (~line 1752) | image verification is skipped when `SecureBoot` is absent or 0 — and nothing in this payload ever writes it |
| `certdb` scope | `AuthServiceInternal.h` | tracks signers only for variables other than PK/KEK/db/dbx — enrollment needs no entries |

## Behavioral ground truth (real boot evidence)

Parsing the SMMSTORE region of post-boot flash copies with the stage's own
parser (`enroll.parse_store`):

- A **pristine-start boot auto-enrolls the payload's default hierarchy**:
  `PK` (1055 B), `KEK` (3066 B), `db` (6133 B), `dbx` (19996 B), plus UI
  variables (`SecureBootEnable`, `CustomMode`, `VendorKeysNv` …). Observed
  identically in every `check-boot` post-run copy and in the `dev2`
  persistent profile.
- **`SecureBoot` and `SetupMode` are never created by the payload** — even
  with the default PK present. This is why enforcement never ran and why
  development-signed artifacts (our certificate is not in the default db)
  kept booting: the gate variable did not exist.
- The payload-initialized store matches the constructed format field for
  field (same FV header values, same 64 KiB store span, same header style,
  same empty 4-byte `certdb`).

## In-stage verification (all required, all fail-closed)

The `enroll` stage (`just enroll`) refuses to produce an image unless all
of the following hold — the 2026-10-21 run satisfied each:

1. **Pristine region erased:** the firmware-build ROM's SMMSTORE region is
   100% `0xFF` before construction (existing variables are never patched).
2. **Byte-deterministic construction:** the store is built twice and must
   be identical (timestamps derive from the generated `.auth` payloads, so
   regenerating keys changes enrollment — by design; the payloads are stage
   inputs).
3. **Re-parse round trip:** the constructed store must parse back to
   exactly the intended variables — `certdb`, `PK`, `KEK` (global GUID),
   `db` (`gEfiImageSecurityDatabaseGuid`), `SecureBoot=1`, `SetupMode=0` —
   with correct attributes (`NV|BS|RT|TIME_BASED_AUTH` for the trust
   variables, `NV|BS|RT` for the mode flags).
4. **Confinement:** every byte outside the SMMSTORE region, the flash map
   and the image length are unchanged from the verified firmware-build ROM
   (the firmware-build manifest digest is checked before the ROM is used).

## Open items (honest)

- **Boot-time enforcement is not proven here.** Whether the payload accepts
  the constructed store, keeps our hierarchy (rather than re-enrolling its
  defaults), and actually verifies images is the subject of the step-3d
  proofs: `SecureBoot=1` on the serial console, signed-chain boot, and
  unsigned/wrong-key rejection.
- **dbx policy is not set** (plan Phase 2 item 12 remains partially open):
  the constructed store carries no revocations.
- The offline-written entries carry `PubKeyIndex 0` and `.auth`-derived
  timestamps; future *guest-side* authenticated variable updates must sign
  with later timestamps (replay protection compares against stored stamps).
- Single-host evidence; cross-host enrollment reproducibility follows the
  firmware build's open cross-host qualification item.
