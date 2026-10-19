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
