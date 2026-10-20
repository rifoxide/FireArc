# Component validation

| Component | Acceptance record |
| --- | --- |
| Public dependency acquisition and clean builds | [Build system](build-system.md) |
| Root, initramfs and integrity payloads | [Root and initramfs](appliance-root.md) |
| Development device assembly and QEMU boot gate | [Device boot](device-boot.md) |

The preliminary CycloneDX inventory (`just sbom`) is generated deterministically
from the locked root closure; its scope limits are stated in the document
metadata and it is not a license/vulnerability-reviewed release SBOM.

`just firmware-sources --online` acquires the nine pinned upstream repositories
at their exact commits into ignored `build/firmware/`, records each commit/tree
identity and refuses offline reuse without explicit acquisition. The seven
submodule repositories are materialized inside their parent checkouts at the
paths recorded by the lock; the lock's gitlink census must match each pinned
parent tree exactly, so every other upstream submodule is explicitly declined
rather than fetched, and offline re-verification fails if any unlisted
repository appears below a parent. Source pins do not verify publisher
signatures, review the code, or build anything: firmware compilation and trust
qualification are separate open gates.

Record actual results and limitations against each component's acceptance
contract. Build IDs identify immutable logs/outputs, not separate implementations
or user-facing commands. Do not count a static check as a successful boot.

Generated evidence remains under ignored `build/`; public summaries contain no
private credentials or device state. Current status: [progress](../progress.md).
