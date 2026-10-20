set positional-arguments

default:
    @just --list

doctor:
    python3 -B scripts/firearc.py doctor

verify-inputs:
    python3 -B scripts/firearc.py verify-inputs

secrets:
    python3 -B scripts/firearc.py secrets

test:
    python3 -B -m unittest discover -s tests -v

check: verify-inputs secrets test

# Download pinned public dependencies. Explicit network acquisition.
bootstrap:
    python3 -B scripts/firearc.py bootstrap

# All stages resolve successful dependencies automatically; no labels required.
build-tools *options:
    python3 -B scripts/firearc.py build-tools "$@"

build-root *options:
    python3 -B scripts/firearc.py build-root "$@"

build-rootfs *options:
    python3 -B scripts/firearc.py build-rootfs "$@"

# Preliminary CycloneDX inventory of the locked root package closure.
sbom *options:
    python3 -B scripts/firearc.py sbom "$@"

# Exact-commit acquisition of pinned upstream firmware sources. Network required.
firmware-sources *options:
    python3 -B scripts/firearc.py firmware-sources "$@"

# Compile the pinned sources into the QEMU Q35 ROM offline in the pinned SDK.
firmware-build *options:
    python3 -B scripts/firearc.py firmware-build "$@"

# Offline flash-map inspection: region roles, gaps, vboot capacity, archival.
firmware-layout *options:
    python3 -B scripts/firearc.py firmware-layout "$@"

# Explicitly create (or --replace) a persistent device profile: disk, firmware
# flash copy and one isolated swtpm TPM state directory. Never resets silently.
device-provision *options:
    python3 -B scripts/firearc.py device-provision "$@"

# Cold-start a persistent profile repeatedly; asserts boot markers, TPM TIS/ACPI
# binding, write confinement and flash/TPM identity continuity across boots.
device-boot *options:
    python3 -B scripts/firearc.py device-boot "$@"

# Warm-reset a running machine in place (one QEMU+swtpm session, flash and TPM
# stay powered through every reset); ends on a full verified boot.
device-reboot *options:
    python3 -B scripts/firearc.py device-reboot "$@"

# Boot to the marker, then stop the machine through the QMP powerdown request.
device-stop *options:
    python3 -B scripts/firearc.py device-stop "$@"

# Cut power hard after a verified boot: QEMU and swtpm die without cleanup.
device-powercut *options:
    python3 -B scripts/firearc.py device-powercut "$@"

# Copy the whole persistent device state into a named immutable snapshot.
device-snapshot *options:
    python3 -B scripts/firearc.py device-snapshot "$@"

# Explicitly restore persistent device state from a named snapshot.
device-restore *options:
    python3 -B scripts/firearc.py device-restore "$@"

# Delete superseded stage evidence; keeps each stage's current + previous dir
# (runs automatically after every successful stage build, too).
prune *options:
    python3 -B scripts/firearc.py prune "$@"

# Assemble the unsigned development installed-device disk (ESP + slot A).
device *options:
    python3 -B scripts/firearc.py device "$@"

# Boot the development disk in QEMU Q35 and assert the integrity gate outcome.
check-boot *options:
    python3 -B scripts/firearc.py check-boot "$@"

build *options:
    python3 -B scripts/firearc.py build "$@"

check-initrd *options:
    python3 -B scripts/firearc.py check-initrd "$@"

check-rootfs *options:
    python3 -B scripts/firearc.py check-rootfs "$@"

verify-build *options:
    python3 -B scripts/firearc.py verify-build "$@"

status:
    python3 -B scripts/firearc.py status

# Explicit confirmation is required. Neither command touches other directories.
clean *options:
    python3 -B scripts/firearc.py clean "$@"

reproduce *options:
    python3 -B scripts/firearc.py reproduce "$@"
