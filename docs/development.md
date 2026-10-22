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

## Command-script ownership

- `scripts/firearc.py` stays a thin checkout launcher; it contains no build or
  provisioning logic.
- `cli.create_parser()` defines flags/defaults without acquiring locks or doing
  work. `cli.execute()` dispatches parsed arguments and returns operation results.
- The CLI's key and saved-device helpers hold the project lock across the entire
  operation. Key roles remain separate; pipeline and reproduction commands keep
  their existing internal lock ownership.
- `cli.main()` alone renders result JSON and operational errors/exit codes. The
  interactive shell keeps control of the terminal and emits no result JSON.
- `Pipeline.produce()` uses the same verified builders for normal and shell
  images, with distinct dependency namespaces. Do not cross-wire shell artifacts
  into normal published outputs.

`tests/test_cli.py` fixes dispatch arguments, default flags, dependency order,
lock lifetimes, JSON formatting and failure/interrupt behavior. Variant-builder
coverage in `tests/test_shell.py` checks both dependency isolation and unchanged
exception propagation. Guest security scripts are not duplicated in the CLI.

Only source, configuration, locks and documentation are committed. Downloads,
binaries, logs and successful-stage pointers live under ignored `build/`.
No signing key or software-TPM/private device state belongs in Git or a build
context. Signing/provisioning are separate, explicitly authorized operations.

Do not silently install host packages, enable host services, reset device state,
weaken authentication, or replace a failed result with an assumed success.
