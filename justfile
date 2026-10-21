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

# Generate (once) the development signing hierarchy under gitignored secrets/.
keys:
    python3 -B scripts/firearc.py keys

# Generate (once) the development vboot keyset under gitignored secrets/vboot/.
vboot-keys:
    python3 -B scripts/firearc.py vboot-keys

# Build the pinned vboot futility signing tool from the firmware sources.
futility *options:
    python3 -B scripts/firearc.py futility "$@"

# Sign the vboot RW section of the built firmware with the dev vboot keyset.
firmware-sign:
    python3 -B scripts/firearc.py firmware-sign

# Build the unsigned slot-A UKI from the frozen payloads (pinned ukify).
uki *options:
    python3 -B scripts/firearc.py uki "$@"

# Sign the UKI and systemd-boot loader with the development sb key
# (requires `just keys`; the signing container sees only sb.key/sb.crt).
sign *options:
    python3 -B scripts/firearc.py sign "$@"

# Enroll the development PK/KEK/db into the firmware variable store and
# set SecureBoot=1/SetupMode=0, producing the enrolled flash image
# (requires `just keys`; pure offline surgery, no boot).
enroll *options:
    python3 -B scripts/firearc.py enroll "$@"

# Assemble the development installed-device disk (ESP + slot A) from the
# frozen payloads and signed boot artifacts.
device *options:
    python3 -B scripts/firearc.py device "$@"

# Boot the development disk in QEMU Q35 and assert the integrity gate outcome.
check-boot *options:
    python3 -B scripts/firearc.py check-boot "$@"

# Prove vboot protected-RW verification: signed RW executes, tampered and
# attacker-keyed RW are refused before payload execution.
check-firmware-vboot *options:
    python3 -B scripts/firearc.py check-firmware-vboot "$@"

# Prove Secure Boot enforcement on the enrolled firmware: signed chain boots,
# tampered / modified / loader-tampered variants are refused, the store survives.
check-secure-boot *options:
    python3 -B scripts/firearc.py check-secure-boot "$@"

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
