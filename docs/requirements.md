# Requirements baseline

**Recorded:** 2026-10-19. **Scope:** Workstreams B/C, with only the platform and
test interfaces required by A/H. No physical reference hardware is available.

Authority: [FireArc R&D Plan — Technical Team](../FireArc_R-D_Plan—Technical_Team.pdf),
dated 2026-10-17, 13 pages.

```text
SHA-256 bab9389d81b9c5bd85b023551fb466ad1d41c7ee0bdb5c9996feefbe56346c49
```

`locks/research-baseline.json` pins the PDF. `just verify-inputs` fails if it is
changed without an explicit baseline review. The complete phase/step contract is
in [PLAN.md](../PLAN.md); IDs here remain stable across implementation changes.

| ID | Required outcome | PDF | Evidence/gate |
| --- | --- | --- | --- |
| GOV-01 | Independent development; public inputs; isolated lab | pp. 1–3 | Threat model, reuse inventory, reviewed clean-room/legal boundaries; G0/G1 |
| GOV-02 | Signed commits, reproducible CI and artifact storage | p. 3 | Approved signing identity, reviewed CI and release provenance; G1/G11 |
| B-01 | Record physical Boot Guard/root ownership | p. 5 | Hardware sample report; G13, not QEMU |
| B-02 | Self-built coreboot/UEFI boot and recovery | p. 5 | Fresh build and recovery evidence; G2/G10/G13 |
| B-03 | ME/CSME status and supported disable policy | p. 5 | Model-specific measurements/recovery; G13 |
| B-04 | FireArc PK/KEK/db; remove unrelated trust; reject unsigned/modified UKIs | p. 5 | Signed-chain, authenticated-variable and revocation tests; G2/G4/G10 |
| B-05 | Explain PCR measurements and independently verify TPM quotes | p. 5 | Phase-specific event-log replay and verifier tests; G5/G8 |
| B-06 | Signed firmware delivery with failed-update recovery | p. 6 | Firmware update/interrupt campaign at declared trust boundary; G10/G13 |
| B-07 | UART/SPI/USB tamper assessment and mitigation | p. 6 | Firmware policy now, physical protection later; G2/G13 |
| B-08 | Offline root, HSM signer, two-person release, reproducible firmware CI | p. 6 | Ceremony and independent builds; G11/G13 |
| C-01 | Minimal pinned Debian stable built reproducibly | p. 6 | mkosi selected; two clean-runner identical payload hashes; G3/G11 |
| C-02 | Maintained kernel with reduced documented configuration and lockdown | p. 6 | Source/config/module inventory, negative tests and board boots; G3/G13 |
| C-03 | Signed UKI **and systemd-boot** | p. 6 | Observed complete boot path; G4 |
| C-04 | Read-only dm-verity root; tamper refusal and authenticated fallback | p. 6 | Full preverification plus runtime verity and fallback tests; G3/G4/G7 |
| C-05 | A/B update, health acceptance and unattended rollback | p. 6 | RAUC/custom systemd-boot backend, crash consistency, broken signed update; G6/G7 |
| C-06 | LUKS2 persistent data sealed with systemd-cryptenroll | p. 6 | Allowed A/B unlock, fresh-TPM disk transplant denial, audited escrow recovery; G5 |
| C-07 | AppArmor, parser seccomp, non-login service accounts, auditd, recorded CIS assessment | p. 6 | Per-service enforcement tests and exceptions; G11 |
| C-08 | Factory reset, serial recovery, TPM-bound one-time break-glass | p. 6 | Authorized and unauthorized/replay recovery tests; G9/G13 |
| C-09 | CycloneDX SBOM, license scan and GPL source offer | p. 6 | Release-linked SBOM/source/license deliverables; G11 |
| PERF-01 | Forwarding within 60 seconds of power-on | p. 7 | Actual forwarded-packet timing, not a readiness marker; G12/G13 |
| PERF-02 | Healthy-update downtime under 120 seconds | p. 7 | Packet outage measured independently from staging and failure recovery; G12/G13 |
| TEST-01 | Versioned, reproducible evidence | pp. 11–13 | Commands, hashes, device/profile, mutation and actual outcome per test |
| EXIT-01 | Reviewed outputs; unmet requirements become owned risks | p. 13 | Risk register and gate review, not implied completion of other workstreams |

## Confirmed choices

See [ADRs](decisions/README.md): mkosi with pinned Debian stable; unencrypted
read-only verity A/B roots; LUKS2 persistent **data only**; unique per-device
escrow recovery under two-person access; RAUC; coreboot/EDK II and systemd-boot.

## Interpretation and external dependencies

1. A source pin, a checksum or a successful signed-UKI boot does not prove a
   hardware-protected firmware root. An unfused but writable platform is not a
   completed physical-root design.
2. PCR comparison requires the same measurement phase and explained event logs.
   Do not assume every PCR 0–7 changes for every boot-chain modification.
3. Preserve the research fixture's full protected-root scan before readiness;
   switching to on-demand-only verification needs a reviewed decision.
4. Independent deterministic release payloads are separate from randomized device
   provisioning and potentially time-bearing signature envelopes.
5. PDF p. 2 forbids proprietary firmware dumping while p. 5 requests a private
   recovery backup. Owner/counsel must resolve this before physical acquisition;
   it does not block open-source QEMU work. Never redistribute vendor images.
6. Firewalla source/assets are not inputs to this implementation. Build from
   reviewed behavior specifications/public standards only.
7. The referenced Technology & Business Design document is not supplied; its
   requirements cannot be invented. Hardware, legal sign-off and production HSM
   operations remain explicit external dependencies.

**Review state:** recorded for owner/security review. This file does not claim
independent review, legal approval or G0 completion.
