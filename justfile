set positional-arguments

default:
    @just --list

# Inspect host prerequisites and pinned tool versions.
doctor:
    python3 -B scripts/firearc.py doctor

# Offline input verification, secret scan and complete unit suite.
check:
    python3 -B scripts/firearc.py verify-inputs
    python3 -B scripts/firearc.py secrets
    python3 -B -m unittest discover -s tests -v

# Explicit network acquisition of pinned Debian dependencies.
bootstrap:
    python3 -B scripts/firearc.py bootstrap

# Explicit network acquisition of pinned firmware sources.
firmware-sources *options:
    python3 -B scripts/firearc.py firmware-sources "$@"

# Generate/reuse the development EFI hierarchy; never silently regenerate.
keys:
    python3 -B scripts/firearc.py keys

# Separate firmware-signing identity.
vboot-keys:
    python3 -B scripts/firearc.py vboot-keys

# Separate PCR-policy-signing identity.
pcr-keys:
    python3 -B scripts/firearc.py pcr-keys

# Build the normal signed OS payloads offline; dependencies resolve automatically.
build:
    python3 -B scripts/firearc.py build

# Maintainer entry point for one intermediate build stage or component audit.
stage name:
    python3 -B scripts/firearc.py stage "$1"

# Disposable signed development image: Bash in the verified read-only Debian root.
shell:
    python3 -B scripts/firearc.py shell

# Verify build receipts, embedded initrd units and filesystem corruption controls.
verify-build:
    python3 -B scripts/firearc.py verify-build

# Boot gates retain independent positive and negative controls.
check-boot:
    python3 -B scripts/firearc.py check-boot

check-secure-boot:
    python3 -B scripts/firearc.py check-secure-boot

check-firmware-vboot:
    python3 -B scripts/firearc.py check-firmware-vboot

# Explicit provisioning; --replace is required to discard existing device state.
device-provision *options:
    python3 -B scripts/firearc.py device-provision "$@"

# Enroll TPM2 data unlock once; recovery custody remains a separate decision.
data-enroll *options:
    python3 -B scripts/firearc.py data-enroll "$@"

# Persistent device lifecycle and destructive test operations stay explicit.
device-boot *options:
    python3 -B scripts/firearc.py device-boot "$@"

device-reboot *options:
    python3 -B scripts/firearc.py device-reboot "$@"

device-stop *options:
    python3 -B scripts/firearc.py device-stop "$@"

device-powercut *options:
    python3 -B scripts/firearc.py device-powercut "$@"

device-snapshot *options:
    python3 -B scripts/firearc.py device-snapshot "$@"

device-restore *options:
    python3 -B scripts/firearc.py device-restore "$@"

status:
    python3 -B scripts/firearc.py status

# Remove superseded stages and successful boot-test scratch disks, not devices.
prune *options:
    python3 -B scripts/firearc.py prune "$@"

# Destructive operations require --yes; neither ever removes signing keys.
clean *options:
    python3 -B scripts/firearc.py clean "$@"

reproduce *options:
    python3 -B scripts/firearc.py reproduce "$@"
