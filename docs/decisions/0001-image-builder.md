# ADR 0001 — mkosi with pinned Debian stable

**Status:** Accepted by owner during planning; recorded 2026-10-19.

## Decision

Use mkosi as the new top-level OS builder, with a minimal Debian stable package
closure pinned to authenticated snapshot metadata and exact package hashes.
The project build interface uses mkosi and pinned Debian packages throughout.

## Consequences

The previous package inventory and verity checks are reusable compatibility
evidence. mkosi, systemd/ukify, initramfs and RAUC dependencies need a new portable
lock/build environment. Security refreshes change the lock through review, not
unpinned network updates. Two independent clean builds must match the documented
release-payload hashes. Device-specific secrets/randomness are provisioned later.

References: C-01; `PLAN.md` Phases 1, 3 and 11. No mkosi image is claimed built by
the initial foundation milestone.
