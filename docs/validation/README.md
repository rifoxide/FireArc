# Component validation

| Component | Acceptance record |
| --- | --- |
| Public dependency acquisition and clean builds | [Build system](build-system.md) |
| Root, initramfs and integrity payloads | [Root and initramfs](appliance-root.md) |
| Development device assembly and QEMU boot gate | [Device boot](device-boot.md) |
| Firmware flash layout and boot write confinement | [Firmware layout](firmware-layout.md) |
| Persistent installed-device profile with swtpm | [Device profile](device-profile.md) |

The preliminary CycloneDX inventory (`just sbom`) is generated deterministically
from the locked root closure; its scope limits are stated in the document
metadata and it is not a license/vulnerability-reviewed release SBOM.

`just firmware-sources --online` acquires the fifteen pinned upstream repositories
at their exact commits into ignored `build/firmware/`, records each commit/tree
identity and refuses offline reuse without explicit acquisition. The fourteen
submodule repositories are materialized inside their parent checkouts at the
paths recorded by the lock; the lock's gitlink census must match each pinned
parent tree exactly, so every other upstream submodule is explicitly declined
rather than fetched, and offline re-verification fails if any unlisted
repository appears below a parent. Every EDK II gitlink is closed for the
offline payload build; coreboot's stay declined until a reviewed configuration
requires them. Source pins do not verify publisher signatures, review the
code, or establish trust.

`just firmware-build` compiles the pinned closure into the monolithic 8 MiB
QEMU Q35 coreboot ROM inside the pinned SDK container with networking
disabled, pre-seeding the EDK II payload workspace from the verified sources
so nothing is fetched during the build. It records the exact input commits,
the SDK image digest, toolchain digests and the CBFS inventory, and
`just check-boot` boots the ROM (single writable pflash carrying the SMMSTORE
variable region) instead of any host firmware. `just firmware-layout`
additionally archives the FMAP region inventory with role classification
([firmware layout](firmware-layout.md)), and the boot gate requires every
flash byte outside SMMSTORE to survive each run unchanged. Firmware security
review, byte reproducibility and trust qualification remain open gates; see
[Device boot](device-boot.md).

`just device-provision` / `just device-boot` maintain a persistent
installed-device profile — OS disk, writable firmware copy and one isolated
swtpm TPM 2.0 state directory — and cold-start it with fail-closed identity
continuity: SMMSTORE and TPM state may change only inside guest execution,
every boot must re-bind the TPM through ACPI/TIS, and provisioning never
silently resets a device ([device profile](device-profile.md)). Operator
operations — `device-reboot` (warm-reset loop in one powered session),
`device-stop` (QMP power-down with honest ACPI evidence), `device-powercut`
(hard kill after a verified boot), `device-snapshot`/`device-restore`
(explicit, immutable, digest-verified state copies) — are recorded in the
profile's operations history. Every session runs under a local-only QMP
control socket. It is a development harness, not measured boot or
provisioning.

Record actual results and limitations against each component's acceptance
contract. Build IDs identify immutable logs/outputs, not separate implementations
or user-facing commands. Do not count a static check as a successful boot.

Generated evidence remains under ignored `build/`; public summaries contain no
private credentials or device state. Current status: [progress](../progress.md).
