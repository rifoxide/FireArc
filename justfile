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
