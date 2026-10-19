# Pinned Debian / mkosi development builder

This is an **unsigned, nonbootable root-tar smoke test**, not the appliance or a
release. No host packages are installed, no keys are generated, and no device,
host TPM, Docker socket or old signing-key tree is mounted into a build.

## Inputs and acquisition

`locks/debian-build.json` fixes Debian trixie amd64 at snapshot
`20261018T000000Z`, mkosi 25.3-7 and systemd 257.13. The systemd tools, EFI
stub/boot manager and cryptsetup integration are installed from the same
version family. This does not yet replace the historical QEMU fixture's stub.

```sh
just builder-import-metadata /home/rifat/projects/project_firearc
just builder-plan tools-b --allow-network
just builder-fetch tools-b --allow-network
just builder-build tools-b
just builder-export tools-b
just image-summary tools-b summary-a
just image-smoke tools-b smoke-a
```

These labels illustrate the workflow; **use fresh labels** if they exist.
The first command imports only seven pinned public metadata files. It checks
the archive-keyring hash, verifies both InRelease signatures with `gpgv`, compares
the authenticated Release bytes, and verifies raw Packages hashes/sizes against
the signed Release. APT planning runs without network, with an empty dpkg status
and explicit main/security repositories. Each selected package must match a
signed index row; SHA-256 and size are checked on download and before building.
APT's optional MD5 output is not trusted as package authority.

Only explicit `--allow-network` acquisition can pull the digest-pinned OCI base
or fetch planned packages. The tools-image build itself has `--network=none`.
Historical metadata expiry is waived **only for this locked development
snapshot**; signature/hash checks remain mandatory. Snapshot age/CVE approval
and independent keyring trust review remain release gates. The OCI base digest
was obtained from Docker Hub; no publisher signature has been verified for it.

## Execution boundaries

Docker builds an APT tools filesystem from a public-only staging context. The
daemon remains trusted host infrastructure; this is not a hostile-host sandbox.
The export uses a never-started container and copies `/usr`, `/etc/alternatives`
and public CA certificates only. It records regular-file hashes, modes and
symlink text without following directory symlinks. Literal backslashes in Linux
systemd unit filenames are accepted only by this filesystem inventory, not by
imported path/URL checks.

mkosi runs using its exported Debian Python package under the recorded **host
Python**, with the exported tools tree supplying build tools. Host Python,
kernel, user-namespace helpers and Docker are not yet a portable pinned closure.
The actual root build uses an unprivileged user namespace with subordinate
UID/GID mappings, private mount/PID namespaces and a network namespace with no
external connectivity. It does not use sudo or privileged Docker. An explicit
Deb822 `mkosi.sources` replaces mkosi's generated sources so its default security
mirror cannot escape the snapshot. Local `copy:` URIs place packages in APT's
cache, avoiding sandbox-only `file:` paths during mkosi's Debian bootstrap.
Translation downloads are disabled; only
the authenticated binary indexes and planned packages are mirrored locally.

`image/smoke/mkosi.conf` disables bootability, Secure Boot output, SSH and
autologin; the root password is locked. This tar must never be provisioned as a
FireArc device. Separate image builds, signature/verity construction and boot
tests are still required.

## Evidence and interrupted exports

Logs, exact commands, package plans, image identity and tools inventory are in
ignored `artifacts/builder/<label>/`; image inputs/logs/results are in ignored
`artifacts/images/<label>/`. Failures remain for diagnosis. No broad cleanup,
overwrite or implicit retry occurs.

If all recorded export copies and owned-container removal completed, but the
inventory step failed, resume that exact recorded export without rebuilding:

```sh
just builder-export tools-b --resume-export export-3d8a7107cd4d
```

Resume checks the recorded container identity, commands, successful copy exits,
staging destination and root links. It is not a bypass for incomplete copies.
The local host and evidence files are trusted; these records are not cryptographic
attestations of a hostile Docker daemon or filesystem.
