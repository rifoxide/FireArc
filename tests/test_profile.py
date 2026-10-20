"""Offline tests for the persistent installed-device profile and its invariants."""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from firearc import device, profile
from firearc.integrity import SafetyError, read_json, sha256, write_json
from support import temporary
from test_firmware_layout import layout_of, synthetic_image

DEVICE_LABEL = "device-l"
FIRMWARE_LABEL = "firmware-build-l"


def fabricate(root):
    """A fake successful device and firmware-build evidence tree."""
    build = root / "build"
    build.mkdir(mode=0o700)
    images = build / "images"
    images.mkdir(mode=0o700)
    dev = images / DEVICE_LABEL
    dev.mkdir(mode=0o700)
    output = dev / "output"
    output.mkdir(mode=0o700)
    (output / "device.raw").write_bytes(b"D" * 8192)
    write_json(dev / "result.json",
               {"passed": True, "artifacts": {"device.raw": sha256(output / "device.raw")}})
    write_json(dev / "device.json", {"kernel_cmdline": device.KERNEL_CMDLINE})
    firmware = build / "firmware-build"
    firmware.mkdir(mode=0o700)
    stage = firmware / FIRMWARE_LABEL
    stage.mkdir(mode=0o700)
    rom_output = stage / "output"
    rom_output.mkdir(mode=0o700)
    (rom_output / "coreboot.rom").write_bytes(b"F" * device.FIRMWARE_BYTES)
    write_json(rom_output / "manifest.json",
               {"coreboot.rom": {"sha256": sha256(rom_output / "coreboot.rom"),
                                 "bytes": device.FIRMWARE_BYTES}})
    write_json(stage / "result.json",
               {"passed": True, "artifacts": {"coreboot.rom": sha256(rom_output / "coreboot.rom"),
                                              "manifest.json": sha256(rom_output / "manifest.json")}})


class NameTests(unittest.TestCase):
    def test_device_names_are_restricted(self):
        self.assertEqual(profile.validate_name("dev1"), "dev1")
        self.assertEqual(profile.validate_name("a" * 32), "a" * 32)
        for bad in ("", None, "Dev", "-x", "x y", "a" * 33, "../esc", "tpm_1", "dev.1"):
            with self.subTest(name=bad), self.assertRaises(SafetyError):
                profile.validate_name(bad)


class ProvisionTests(unittest.TestCase):
    def test_provision_creates_persistent_state(self):
        with temporary() as root:
            fabricate(root)
            result = profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
            self.assertTrue(result["passed"])
            target = root / "build/devices/dev1"
            self.assertEqual((target / "disk.raw").read_bytes(), b"D" * 8192)
            self.assertEqual((target / "flash.rom").stat().st_size, device.FIRMWARE_BYTES)
            for name in ("tpm", "runs"):
                self.assertTrue((target / name).is_dir())
            stored = read_json(target / "profile.json")
            self.assertEqual(stored["name"], "dev1")
            self.assertEqual(stored["boots"], 0)
            self.assertEqual(stored["provenance"]["device_label"], DEVICE_LABEL)
            self.assertEqual(stored["provenance"]["firmware_label"], FIRMWARE_LABEL)
            self.assertEqual(stored["provenance"]["kernel_cmdline"], device.KERNEL_CMDLINE)
            self.assertNotIn("state_after_last_boot", stored)

    def test_provision_never_silently_replaces(self):
        with temporary() as root:
            fabricate(root)
            profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
            with self.assertRaises(SafetyError) as raised:
                profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
            self.assertIn("explicitly", str(raised.exception))
            result = profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL, replace=True)
            self.assertTrue(result["passed"])
            self.assertEqual(read_json(root / "build/devices/dev1/profile.json")["boots"], 0)

    def test_provision_verifies_stage_vouching(self):
        with temporary() as root:
            fabricate(root)
            (root / "build/images" / DEVICE_LABEL / "output/device.raw").write_bytes(b"X" * 8192)
            with self.assertRaises(SafetyError):
                profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)


class LoadTests(unittest.TestCase):
    def test_load_validates_profile_contract(self):
        with temporary() as root:
            fabricate(root)
            profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
            target, stored = profile.load(root, "dev1")
            self.assertEqual(target.name, "dev1")
            self.assertEqual(stored["provenance"]["disk_bytes"], 8192)
            with (target / "flash.rom").open("r+b") as flash:
                flash.truncate(1024)
            with self.assertRaises(SafetyError):
                profile.load(root, "dev1")

    def test_load_rejects_foreign_harness_cmdline(self):
        with temporary() as root:
            fabricate(root)
            profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
            target = root / "build/devices/dev1"
            stored = read_json(target / "profile.json")
            stored["provenance"]["kernel_cmdline"] = "root=/dev/other"
            profile.save_json(target / "profile.json", stored)
            with self.assertRaises(SafetyError):
                profile.load(root, "dev1")

    def test_load_rejects_missing_profile(self):
        with temporary() as root:
            fabricate(root)
            with self.assertRaises(SafetyError):
                profile.load(root, "ghost")


class IdentityTests(unittest.TestCase):
    def test_tpm_digests_inventory(self):
        with temporary() as work:
            self.assertEqual(profile.tpm_digests(work), {})
            (work / "tpm2-00.permall").write_bytes(b"state")
            (work / "tpm2-00.volatilize").write_bytes(b"volatile")
            digests = profile.tpm_digests(work)
            self.assertEqual(list(digests), ["tpm2-00.permall", "tpm2-00.volatilize"])
            self.assertEqual(digests["tpm2-00.permall"], sha256(work / "tpm2-00.permall"))

    def test_identity_must_not_move_outside_boots(self):
        current = {"a": "1"}
        profile.assert_identity_unchanged({"a": "1"}, current, "TPM state")
        with self.assertRaises(SafetyError) as raised:
            profile.assert_identity_unchanged({"a": "2"}, current, "TPM state")
        self.assertIn("outside guest execution", str(raised.exception))

    def test_area_digest_reads_the_declared_region(self):
        image = synthetic_image()
        layout = layout_of(image)
        import hashlib
        expected = hashlib.sha256(image[0:0x8000]).hexdigest()
        self.assertEqual(profile.area_digest(image, layout, "SMMSTORE"), expected)
        with self.assertRaises(SafetyError):
            profile.area_digest(image, layout, "GBB")


class BootValidationTests(unittest.TestCase):
    def test_boot_count_is_bounded(self):
        with temporary() as root:
            for count in (0, -1, profile.MAX_BOOT_RUNS + 1):
                with self.subTest(count=count), self.assertRaises(SafetyError):
                    profile.boot(root, "dev1", count=count)

    def test_boot_requires_an_existing_profile(self):
        with temporary() as root:
            fabricate(root)
            with self.assertRaises(SafetyError):
                profile.boot(root, "ghost", count=1)

    def test_reboot_reset_count_is_bounded(self):
        with temporary() as root:
            for resets in (0, -1, profile.MAX_RESETS + 1):
                with self.subTest(resets=resets), self.assertRaises(SafetyError):
                    profile.reboot(root, "dev1", resets=resets)


class RunNumberingTests(unittest.TestCase):
    def test_next_run_is_monotonic(self):
        with temporary() as work:
            self.assertEqual(profile.next_run(work).name, "0001")
            (work / "0001").mkdir()
            (work / "0007").mkdir()
            (work / "not-a-run").mkdir()
            self.assertEqual(profile.next_run(work).name, "0008")


class SnapshotTests(unittest.TestCase):
    def prepared(self, root):
        fabricate(root)
        profile._provision(root, "dev1", DEVICE_LABEL, FIRMWARE_LABEL)
        target = root / "build/devices/dev1"
        (target / "tpm/tpm2-00.permall").write_bytes(b"tpm-state")
        stored = read_json(target / "profile.json")
        stored["boots"] = 3
        stored["state_after_last_boot"] = {
            "smmstore_sha256": "aa",
            "tpm_sha256": {"tpm2-00.permall": sha256(target / "tpm/tpm2-00.permall")}}
        profile.save_json(target / "profile.json", stored)
        return target

    def test_snapshot_then_restore_is_an_explicit_round_trip(self):
        with temporary() as root:
            target = self.prepared(root)
            result = profile.snapshot(root, "dev1", "pre-chaos")
            self.assertTrue(result["passed"])
            snap = target / "snapshots/pre-chaos"
            self.assertEqual(read_json(snap / "manifest.json")["boots"], 3)
            # Diverge the live state after the snapshot.
            (target / "tpm/tpm2-00.permall").write_bytes(b"changed-by-later-boot")
            (target / "flash.rom").write_bytes(b"Z" * device.FIRMWARE_BYTES)
            restored = profile.restore(root, "dev1", "pre-chaos")
            self.assertEqual(restored["restored_boots"], 3)
            self.assertEqual((target / "tpm/tpm2-00.permall").read_bytes(), b"tpm-state")
            stored = read_json(target / "profile.json")
            self.assertEqual(stored["boots"], 3)
            self.assertEqual(stored["state_after_last_boot"]["smmstore_sha256"], "aa")
            self.assertEqual([entry["op"] for entry in stored["operations"]],
                             ["provision", "snapshot", "restore"])
            self.assertIn("pre-chaos", stored["snapshots"])

    def test_snapshots_are_immutable_and_labels_validated(self):
        with temporary() as root:
            target = self.prepared(root)
            profile.snapshot(root, "dev1", "one")
            with self.assertRaises(SafetyError) as raised:
                profile.snapshot(root, "dev1", "one")
            self.assertIn("immutable", str(raised.exception))
            for bad in ("../esc", "Two", ""):
                with self.subTest(label=bad), self.assertRaises(SafetyError):
                    profile.snapshot(root, "dev1", bad)

    def test_restore_rejects_unknown_or_corrupt_snapshots(self):
        with temporary() as root:
            target = self.prepared(root)
            with self.assertRaises(SafetyError):
                profile.restore(root, "dev1", "ghost")
            profile.snapshot(root, "dev1", "good")
            (target / "tpm/tpm2-00.permall").write_bytes(b"diverged")
            (target / "snapshots/good/tpm/tpm2-00.permall").write_bytes(b"corrupted")
            with self.assertRaises(SafetyError) as raised:
                profile.restore(root, "dev1", "good")
            self.assertIn("corrupted", str(raised.exception))
            # The live state must be untouched by the refused restore.
            self.assertEqual((target / "tpm/tpm2-00.permall").read_bytes(), b"diverged")


class HarnessWiringTests(unittest.TestCase):
    def test_qemu_command_attaches_exactly_one_tis_tpm(self):
        command = device.qemu_command("/f", "/d", "/s", kvm=True, tpm="/run/swtpm.sock")
        joined = " ".join(command)
        self.assertIn("-chardev socket,id=chrtpm,path=/run/swtpm.sock", joined)
        self.assertIn("-tpmdev emulator,id=tpm0,chardev=chrtpm", joined)
        self.assertIn("-device tpm-tis,tpmdev=tpm0", joined)
        self.assertEqual(command.count("-tpmdev"), 1)
        self.assertNotIn("tpm-tis", " ".join(device.qemu_command("/f", "/d", "/s", kvm=True)))

    def test_qemu_command_exposes_local_qmp_and_reboot_control(self):
        command = device.qemu_command("/f", "/d", "/s", kvm=True,
                                      qmp_socket=Path("/run/qmp.sock"))
        joined = " ".join(command)
        self.assertIn("-qmp unix:/run/qmp.sock,server,nowait", joined)
        self.assertNotIn("tcp", joined)
        self.assertIn("-no-reboot", joined)
        rebootable = device.qemu_command("/f", "/d", "/s", kvm=True,
                                         qmp_socket=Path("/run/qmp.sock"), rebootable=True)
        self.assertNotIn("-no-reboot", rebootable)

    def test_accelerator_profiles_are_distinct(self):
        self.assertIn("kvm", device.qemu_command("/f", "/d", "/s", kvm=True))
        self.assertIn("tcg", device.qemu_command("/f", "/d", "/s", kvm=False))
        self.assertNotIn("kvm", " ".join(device.qemu_command("/f", "/d", "/s", kvm=False)))

    def test_dev_unit_graces_before_poweroff(self):
        self.assertIn(f"sleep {device.GRACE_SECONDS}", device.DEV_UNIT)
        self.assertIn("poweroff -f", device.DEV_UNIT)

    def test_dev_unit_reports_tis_acpi_binding(self):
        self.assertIn("FIREARC_TPM_TIS_OK", device.DEV_UNIT)
        self.assertIn("FIREARC_TPM_TIS_MISSING", device.DEV_UNIT)
        self.assertIn("/sys/class/tpm/tpm0", device.DEV_UNIT)
        self.assertNotIn("/sys/class/tpm0", device.DEV_UNIT)
        self.assertIn("tpm_version_major", device.DEV_UNIT)
        self.assertIn("/dev/tpm0", device.DEV_UNIT)
        self.assertEqual(device.TPM_TIS_MARKER, "FIREARC_TPM_TIS_OK")
        self.assertEqual(device.TPM_TIS_MISSING_MARKER, "FIREARC_TPM_TIS_MISSING")

    def test_profile_state_updates_use_replacement(self):
        with temporary() as work:
            path = work / "state.json"
            write_json(path, {"boots": 0})
            profile.save_json(path, {"boots": 1})
            profile.save_json(path, {"boots": 2})
            self.assertEqual(json.loads(path.read_text())["boots"], 2)


if __name__ == "__main__":
    unittest.main()
