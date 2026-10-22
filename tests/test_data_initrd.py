"""Execute the real initrd mount gate against isolated command/device fixtures."""
import os
from pathlib import Path
import subprocess
import unittest

from support import temporary

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "images/initrd/99firearc-root/firearc-data-mount"


class DataEnrollmentGateTests(unittest.TestCase):
    def run_enroll(self, *, filesystem="", probe_rc=2, authorize=False, mkfs_rc=0):
        with temporary() as work:
            console = work / "console"
            calls = work / "calls"
            tpm = work / "tpm"
            tpm.touch()
            extra = work / "extra"
            extra.mkdir()
            for name in ("tpm2-pcr-signature.json", "tpm2-pcr-public-key.pem"):
                (extra / name).touch()
            transport = work / "transport"
            magic = b"FIREARC-ENROLL-KEY-V1\n".ljust(32, b"\0")
            grant = b"FIREARC-FORMAT-ONCE-V1\n" if authorize else b""
            transport.write_bytes(magic + b"R" * 32 + grant.ljust(32, b"\0"))
            text = (ROOT / "images/initrd/99firearc-root/firearc-data-enroll").read_text()
            for old, new in (("/dev/disk/by-id/ata-QEMU_HARDDISK_FIREARC_ENROLL_V1", str(transport)),
                             ("/dev/console", str(console)), ("/dev/tpmrm0", str(tpm)),
                             ("/.extra", str(extra)), ("/run/", str(work) + "/")):
                text = text.replace(old, new)
            script = work / "enroll"
            script.write_text(text)
            bins = work / "bin"
            bins.mkdir()
            for name, body in {
                "udevadm": "exit 0",
                "cryptsetup": "echo '{}'",
                "systemd-cryptsetup": "exit 0",
                "systemd-cryptenroll": f"echo enroll >> '{calls}'",
                "blkid": f"echo '{filesystem}'; exit {probe_rc}",
                "mkfs.ext4": f"echo mkfs >> '{calls}'; exit {mkfs_rc}",
            }.items():
                exe = bins / name
                exe.write_text("#!/bin/sh\n" + body + "\n")
                exe.chmod(0o755)
            result = subprocess.run(["/bin/sh", str(script)], capture_output=True,
                                    env={**os.environ, "PATH": f"{bins}:/usr/bin:/bin"})
            self.assertFalse((work / "firearc-recovery.key").exists())
            return result.returncode, calls.read_text() if calls.exists() else ""

    def test_only_initial_grant_allows_filesystem_creation(self):
        self.assertEqual(self.run_enroll(authorize=True), (0, "mkfs\nenroll\n"))
        rc, calls = self.run_enroll(authorize=False)
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, "")

    def test_retry_preserves_existing_ext4(self):
        self.assertEqual(self.run_enroll(filesystem="ext4", probe_rc=0), (0, "enroll\n"))

    def test_foreign_signature_and_probe_error_never_format(self):
        for options in ({"filesystem": "xfs", "probe_rc": 0}, {"probe_rc": 4}):
            with self.subTest(options=options):
                rc, calls = self.run_enroll(authorize=True, **options)
                self.assertNotEqual(rc, 0)
                self.assertEqual(calls, "")

    def test_failed_format_never_enrolls(self):
        rc, calls = self.run_enroll(authorize=True, mkfs_rc=1)
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, "mkfs\n")


class DataMountGateTests(unittest.TestCase):
    def run_gate(self, *, kind="crypto_LUKS", probe_rc=0, header_rc=0,
                 token=True, mount_rc=0, mounts=None, blank=True):
        with temporary() as work:
            volume = work / "volume"
            volume.touch()
            console = work / "console"
            console.touch()
            calls = work / "calls"
            proc = work / "mounts"
            proc.write_text(mounts if mounts is not None else (
                "/dev/mapper/firearc-data /sysroot/data ext4 rw,nosuid,nodev,noexec 0 0\n"))
            # Substitute only host resource locations. All policy branches
            # and shell commands come directly from the shipped script.
            text = SCRIPT.read_text().replace(
                "/dev/disk/by-partlabel/FIREARC_DATA", str(volume)).replace(
                "/dev/console", str(console)).replace(
                "/run/firearc-data-header.json", str(work / "header.json")).replace(
                "/proc/mounts", str(proc)).replace('-b "$volume"', '-f "$volume"')
            script = work / "gate"
            script.write_text(text)
            bins = work / "bin"
            bins.mkdir()
            stubs = {
                "blkid": f"echo '{kind}'; exit {probe_rc}",
                "cryptsetup": f"echo '{'systemd-tpm2' if token else '{}'}'; exit {header_rc}",
                "systemctl": f"echo systemctl >> '{calls}'; exit {mount_rc}",
                "blockdev": "echo 4096",
                "cmp": f"exit {0 if blank else 1}",
            }
            # The gate may never format or directly attach a volume.
            for name in ("mkfs.ext4", "systemd-cryptsetup", "mount", "mkdir"):
                stubs[name] = f"echo FORBIDDEN:{name} >> '{calls}'; exit 99"
            for name, body in stubs.items():
                exe = bins / name
                exe.write_text("#!/bin/sh\n" + body + "\n")
                exe.chmod(0o755)
            result = subprocess.run(["/bin/sh", str(script)], capture_output=True,
                                    text=True, env={**os.environ,
                                                   "PATH": f"{bins}:/usr/bin:/bin"})
            return result.returncode, console.read_text(), (
                calls.read_text() if calls.exists() else "")

    def test_unenrolled_volume_never_starts_unlock_or_mount(self):
        for options in ({"token": False}, {"kind": "", "probe_rc": 2},
                        {"kind": "", "probe_rc": 0}):
            with self.subTest(options=options):
                rc, console, calls = self.run_gate(**options)
                self.assertEqual(rc, 0)
                self.assertIn("FIREARC_DATA_TOKEN_ABSENT", console)
                self.assertEqual(calls, "")

    def test_unreadable_or_foreign_header_is_not_token_absent(self):
        for options in ({"header_rc": 1}, {"kind": "ext4"}, {"probe_rc": 4},
                        {"kind": "", "probe_rc": 0, "blank": False},
                        {"kind": "", "probe_rc": 2, "blank": False}):
            with self.subTest(options=options):
                rc, console, calls = self.run_gate(**options)
                self.assertNotEqual(rc, 0)
                self.assertIn("FIREARC_DATA_UNLOCK_REFUSED", console)
                self.assertNotIn("TOKEN_ABSENT", console)
                self.assertEqual(calls, "")

    def test_refused_unlock_never_falls_back_or_formats(self):
        rc, console, calls = self.run_gate(mount_rc=1)
        self.assertNotEqual(rc, 0)
        self.assertIn("FIREARC_DATA_UNLOCK_REFUSED", console)
        self.assertEqual(calls, "systemctl\n")

    def test_mount_source_type_and_every_restriction_are_required(self):
        for entry in ("", "tmpfs /sysroot/data tmpfs rw,nosuid,nodev,noexec 0 0\n",
                      "/dev/mapper/wrong /sysroot/data ext4 rw,nosuid,nodev,noexec 0 0\n",
                      *[f"/dev/mapper/firearc-data /sysroot/data ext4 {','.join(o for o in ('rw', 'nosuid', 'nodev', 'noexec') if o != missing)} 0 0\n"
                        for missing in ("rw", "nosuid", "nodev", "noexec")]):
            with self.subTest(entry=entry):
                rc, console, calls = self.run_gate(mounts=entry)
                self.assertNotEqual(rc, 0)
                self.assertIn("FIREARC_DATA_MOUNT_MISSING", console)
                self.assertEqual(calls, "systemctl\n")

    def test_correct_mount_passes(self):
        rc, console, calls = self.run_gate()
        self.assertEqual(rc, 0)
        self.assertIn("FIREARC_DATA_MOUNT_OK", console)
        self.assertEqual(calls, "systemctl\n")
