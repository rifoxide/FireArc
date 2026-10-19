# Development workflow

Implement dependency-ready features from [PLAN.md](../PLAN.md) in the maintained
source/configuration directories, with automated tests and component acceptance
records. Architecture decisions belong in `docs/decisions/`.

1. Change code in `src/firearc/`, image policies in `images/`, container policies
   in `containers/`, and exact upstream inputs in `locks/`.
2. Add offline tests under `tests/`; run `just check`.
3. Run `just build` and applicable component checks. Commands select dependencies
   and allocate build IDs themselves; do not put manual retry names into APIs.
4. Update [progress](progress.md) and [validation](validation/README.md) with
   actual outcomes and limitations. A passing static check is not a boot gate.
5. Before a release, run a clean reconstruction and reproducibility comparison.

Only source, configuration, locks and documentation are committed. Downloads,
binaries, logs and successful-stage pointers live under ignored `build/`.
No signing key or software-TPM/private device state belongs in Git or a build
context. Signing/provisioning are separate, explicitly authorized operations.

Do not silently install host packages, enable host services, reset device state,
weaken authentication, or replace a failed result with an assumed success.
