set positional-arguments

# Default is read-only: list the available workflows.
default:
    @just --list

# Read-only host/tool diagnostics; missing future build tools are reported.
doctor:
    python3 -B scripts/firearc.py doctor

# Check the specification, locks and repository files without a VM or network.
verify-inputs:
    python3 -B scripts/firearc.py verify-inputs

# Inspect tracked and non-ignored repository files, never the private run tree.
secrets:
    python3 -B scripts/firearc.py secrets

test:
    python3 -B -m unittest discover -s tests -v

check: verify-inputs secrets test

# Verify complete pinned historical manifests; the reference remains read-only.
research-verify reference:
    python3 -B scripts/firearc.py research-verify --reference "$1"

# Explicit public-artifact import; refuses to replace an existing import.
baseline-import reference:
    python3 -B scripts/firearc.py baseline-import --reference "$1"

# Explicit new research device, NOT an installer or encrypted-data provisioner.
baseline-new device *options:
    python3 -B scripts/firearc.py baseline-new "$@"

# Reuse existing device flash/disks/TPM; never creates or resets a missing device.
baseline-run device *options:
    python3 -B scripts/firearc.py baseline-run "$@"

# Control only this device's local QMP socket, never a PID from an old file.
baseline-control device operation:
    python3 -B scripts/firearc.py baseline-control "$1" "$2"

# Public Debian metadata only; verify archive signatures and index hashes.
builder-import-metadata reference:
    python3 -B scripts/firearc.py builder-import-metadata --reference "$1"

# Exact APT plan from signed, fixed indexes; optional pinned OCI base acquisition.
builder-plan label *options:
    python3 -B scripts/firearc.py builder-plan --label "$@"

# Explicit network acquisition of only planned SHA-256/size-authorized packages.
builder-fetch label *options:
    python3 -B scripts/firearc.py builder-fetch --label "$@"

# Offline Docker tools build; never privileged and never mounts host disks/keys.
builder-build label:
    python3 -B scripts/firearc.py builder-build --label "$1"

# Export only public /usr, alternatives and CA certificates, not private state.
builder-export label *options:
    python3 -B scripts/firearc.py builder-export --label "$@"

# Validate the explicit recipe with pinned mkosi; does not build or boot an image.
image-summary tools label:
    python3 -B scripts/firearc.py image-summary --tools "$1" --label "$2"

# Offline, rootless, nonbootable root tar. No signing, provisioning or device IO.
image-smoke tools label:
    python3 -B scripts/firearc.py image-smoke --tools "$1" --label "$2"
