"""Offline tests for the persistent installed-device profile and its invariants."""

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from firearc import device, luks, profile
from firearc.integrity import SafetyError, read_json, sha256, write_json
from support import temporary
from test_device import AUTHORITY
from test_firmware_layout import layout_of, synthetic_image

DEVICE_LABEL = "device-l"
FIRMWARE_LABEL = "firmware-sign-l"
TOOLS_LABEL = "tools-l"
DATA_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


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
    # The disk is big enough to carry the (blank) data partition region.
    disk_size = luks.DATA_OFFSET + luks.DATA_BYTES
    with (output / "device.raw").open("wb") as handle:
        handle.write(b"D" * 8192)
        handle.truncate(disk_size)
    write_json(dev / "result.json",
               {"passed": True, "artifacts": {"device.raw": sha256(output / "device.raw")}})
    write_json(dev / "device.json", {"kernel_cmdline": device.KERNEL_CMDLINE})
    stage = build / "images" / FIRMWARE_LABEL
    stage.mkdir(mode=0o700)
    rom_output = stage / "output"
    rom_output.mkdir(mode=0o700)
    (rom_output / "signed-firmware.rom").write_bytes(b"F" * device.FIRMWARE_BYTES)
    write_json(stage / "result.json",
               {"passed": True, "changed_regions": ["GBB", "VBLOCK_A"],
                "artifacts": {"signed-firmware.rom":
                              sha256(rom_output / "signed-firmware.rom")},
                "signed": {"rom_sha256": sha256(rom_output / "signed-firmware.rom")},
                "input": {"firmware_label": "fb-l", "rom_sha256": "0" * 64}})


def fake_data_provision(root, target, tools_label):
    """Synthetic per-device LUKS2 evidence without docker/cryptsetup."""
    target = Path(target)
    evidence = target / "provision"
    evidence.mkdir(mode=0o700)
    secrets = target / "secrets"
    secrets.mkdir(mode=0o700)
    credential = b"R" * luks.RECOVERY_BYTES
    path = secrets / "recovery.key"
    path.write_bytes(credential)
    path.chmod(0o600)
    document = {
        "schema": 1, "volume": "luks2", "label": luks.LUKS_LABEL,
        "uuid": DATA_UUID, "keyslots": ["0"],
        "recovery_credential": {"bits": 256, "path": "secrets/recovery.key",
                                "sha256": hashlib.sha256(credential).hexdigest(),
                                "escrow": "pending (Phase 5 item 7)",
                                "transport": "file only"},
        "data_region_sha256": luks.region_digest(target / "disk.raw", luks.DATA_OFFSET),
    }
    write_json(evidence / "data.json", document)
    return document


def provision(root, name="dev1", *, replace=False):
    """_provision with the LUKS formatting step stubbed to synthetic evidence."""
    with patch.object(profile.luks, "provision_data", fake_data_provision):
        return profile._provision(root, name, DEVICE_LABEL, FIRMWARE_LABEL,
                                  TOOLS_LABEL, replace=replace)


# Shrink the data-partition geometry for this suite only: the real offset
# (~4.7 GiB) would make every whole-disk digest and profile copy in these
# offline tests gigabytes large. The geometry contract itself is pinned in
# tests/test_luks.py against the real constants.
_PATCHERS = []


def setUpModule():
    _PATCHERS.append(patch.object(luks, "DATA_OFFSET", 1024 * 1024))
    _PATCHERS.append(patch.object(luks, "DATA_BYTES", 8 * 1024 * 1024))
    for patcher in _PATCHERS:
        patcher.start()


def tearDownModule():
    for patcher in _PATCHERS:
        patcher.stop()


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
            result = provision(root)
            self.assertTrue(result["passed"])
            target = root / "build/devices/dev1"
            with (target / "disk.raw").open("rb") as disk:
                self.assertEqual(disk.read(8192), b"D" * 8192)
                self.assertEqual(disk.seek(0, 2), luks.DATA_OFFSET + luks.DATA_BYTES)
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
            provision(root)
            with self.assertRaises(SafetyError) as raised:
                provision(root)
            self.assertIn("explicitly", str(raised.exception))
            result = provision(root, replace=True)
            self.assertTrue(result["passed"])
            self.assertEqual(read_json(root / "build/devices/dev1/profile.json")["boots"], 0)

    def test_provision_verifies_stage_vouching(self):
        with temporary() as root:
            fabricate(root)
            (root / "build/images" / DEVICE_LABEL / "output/device.raw").write_bytes(b"X" * 8192)
            with self.assertRaises(SafetyError):
                provision(root)


class LoadTests(unittest.TestCase):
    def test_load_validates_profile_contract(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            target, stored = profile.load(root, "dev1")
            self.assertEqual(target.name, "dev1")
            self.assertEqual(stored["provenance"]["disk_bytes"],
                             luks.DATA_OFFSET + luks.DATA_BYTES)
            self.assertEqual(stored["data"]["uuid"], DATA_UUID)
            self.assertEqual(stored["data"]["keyslots"], ["0"])
            self.assertEqual(stored["operations"][0]["data_volume_uuid"], DATA_UUID)
            with (target / "flash.rom").open("r+b") as flash:
                flash.truncate(1024)
            with self.assertRaises(SafetyError):
                profile.load(root, "dev1")

    def test_load_rejects_foreign_harness_cmdline(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
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

    def test_provision_creates_per_device_luks2_evidence(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            target = root / "build/devices/dev1"
            evidence = read_json(target / "provision/data.json")
            self.assertEqual(evidence["uuid"], DATA_UUID)
            credential = target / "secrets/recovery.key"
            self.assertTrue(credential.is_file())
            import stat
            self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o600)
            stored = read_json(target / "profile.json")
            self.assertEqual(stored["data"]["region_sha256"],
                             evidence["data_region_sha256"])
            self.assertEqual(stored["data"]["recovery_credential"]["escrow"],
                             "pending (Phase 5 item 7)")

    def test_load_rejects_data_region_drift(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            disk = root / "build/devices/dev1/disk.raw"
            with disk.open("r+b") as handle:
                handle.seek(luks.DATA_OFFSET + 4096)
                handle.write(b"X")
            with self.assertRaises(SafetyError) as raised:
                profile.load(root, "dev1")
            self.assertIn("LUKS2 data volume identity", str(raised.exception))

    def test_load_rejects_credential_tampering(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            credential = root / "build/devices/dev1/secrets/recovery.key"
            original = credential.read_bytes()
            for damage in (lambda: credential.chmod(0o644),
                           lambda: credential.write_bytes(b"0" * 32)):
                with self.subTest(damage=damage), self.assertRaises(SafetyError):
                    damage()
                    profile.load(root, "dev1")
                credential.chmod(0o600)
                credential.write_bytes(original)

    def test_load_rejects_foreign_data_contract(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            target = root / "build/devices/dev1"
            original = read_json(target / "profile.json")
            for damage in (lambda d: d.update({"keyslots": ["0", "1", "2"]}),
                           lambda d: d.update({"volume": "luks1"})):
                with self.subTest(damage=damage):
                    stored = json.loads(json.dumps(original))
                    damage(stored["data"])
                    profile.save_json(target / "profile.json", stored)
                    with self.assertRaises(SafetyError) as raised:
                        profile.load(root, "dev1")
                    self.assertIn("provisioning contract", str(raised.exception))
                    profile.save_json(target / "profile.json", original)

    def test_load_accepts_the_enrolled_contract(self):
        with temporary() as root:
            fabricate(root)
            provision(root)
            target = root / "build/devices/dev1"
            stored = read_json(target / "profile.json")
            stored["data"]["keyslots"] = ["0", "1"]
            stored["data"]["token"] = {"type": "systemd-tpm2", "pcrs": ["7", "11"]}
            profile.save_json(target / "profile.json", stored)
            # load() re-digests the region against the (unchanged) evidence.
            _, loaded = profile.load(root, "dev1")
            self.assertEqual(loaded["data"]["keyslots"], ["0", "1"])
            stored["data"].pop("token")
            profile.save_json(target / "profile.json", stored)
            with self.assertRaises(SafetyError) as raised:
                profile.load(root, "dev1")
            self.assertIn("token record", str(raised.exception))


class DataUnlockContractTests(unittest.TestCase):
    """The boot verdict depends on the volume's enrollment state (items 9+10)."""

    def _text(self, *markers, root_ok=True):
        body = "\n".join(markers)
        if root_ok:
            body = ("tpm tis\n" + device.TPM_TIS_MARKER + "\n" + body)
        return body

    def test_enrolled_boot_requires_unlock_and_mount(self):
        base = self._text(device.REQUIRED_MARKER)
        # Unlock alone is not enough: the mount must happen too.
        for partial in ([device.DATA_UNLOCK_OK_MARKER],
                        [device.DATA_MOUNT_OK_MARKER],
                        [device.DATA_UNLOCK_REFUSED_MARKER],
                        [device.DATA_MOUNT_MISSING_MARKER],
                        [device.DATA_TOKEN_ABSENT_MARKER]):
            with self.subTest(markers=partial):
                with self.assertRaises(SafetyError):
                    profile._assert_boot_markers(
                        self._text(device.REQUIRED_MARKER, *partial), "boot",
                        enrolled=True)
        good = profile._assert_boot_markers(
            self._text(device.REQUIRED_MARKER, device.DATA_UNLOCK_OK_MARKER,
                       device.DATA_MOUNT_OK_MARKER), "boot", enrolled=True)
        self.assertTrue(good[0][device.REQUIRED_MARKER])

    def test_unenrolled_boot_requires_token_absent(self):
        # A factory/pre-enrollment disk passes only without unlock claims.
        for bad in ([device.DATA_UNLOCK_OK_MARKER],
                    [device.DATA_UNLOCK_REFUSED_MARKER],
                    [device.DATA_MOUNT_MISSING_MARKER], []):
            with self.subTest(markers=bad):
                with self.assertRaises(SafetyError):
                    profile._assert_boot_markers(
                        self._text(device.REQUIRED_MARKER, *bad), "boot",
                        enrolled=False)
        profile._assert_boot_markers(
            self._text(device.REQUIRED_MARKER, device.DATA_TOKEN_ABSENT_MARKER),
            "boot", enrolled=False)
        profile._assert_boot_markers(
            self._text(device.REQUIRED_MARKER, device.DATA_PROBE_NO_DISK_MARKER),
            "boot", enrolled=False)

    def test_unlock_marker_alone_cannot_end_the_session(self):
        self.assertFalse(profile._data_verdict_ready(device.DATA_UNLOCK_OK_MARKER))
        self.assertTrue(profile._data_verdict_ready(
            device.DATA_UNLOCK_OK_MARKER + "\n" + device.DATA_MOUNT_OK_MARKER))
        self.assertTrue(profile._data_verdict_ready(device.DATA_UNLOCK_REFUSED_MARKER))
        self.assertTrue(profile._data_verdict_ready(device.DATA_MOUNT_MISSING_MARKER))

    def test_enrollment_state_survives_operation_history_rotation(self):
        self.assertFalse(profile._data_enrolled({"operations": []}))
        self.assertFalse(profile._data_enrolled({"data": {"keyslots": ["0"]}}))
        self.assertTrue(profile._data_enrolled(
            {"data": {"keyslots": ["0", "1"]}, "operations": []}))


class EnrolledIdentityScopeTests(unittest.TestCase):
    """Items 9+10: after enrollment the header is identity; payload is data."""

    def _enrolled_profile(self, root):
        fabricate(root)
        provision(root)
        target = root / "build/devices/dev1"
        stored = read_json(target / "profile.json")
        stored["data"]["keyslots"] = ["0", "1"]
        stored["data"]["token"] = {"type": "systemd-tpm2", "pcrs_plain": ["7"],
                                   "pcrs_signed": ["11"]}
        stored["data"].pop("enroll_pending", None)
        disk = target / "disk.raw"
        header = bytearray(luks.HEADER_READ_BYTES)
        header[:6] = luks.LUKS2_MAGIC
        header[6:8] = (2).to_bytes(2, "big")
        header[8:16] = (16384).to_bytes(8, "big")
        metadata = json.dumps({"segments": {"0": {
            "type": "crypt", "offset": str(2 * luks.MIB)}}}).encode()
        header[luks.HEADER_JSON_OFFSET:luks.HEADER_JSON_OFFSET + len(metadata)] = metadata
        with disk.open("r+b") as handle:
            handle.seek(luks.DATA_OFFSET)
            handle.write(header)
        stored["data"]["header_sha256"] = luks.header_digest(disk)
        profile.save_json(target / "profile.json", stored)
        return target, disk

    def test_payload_writes_are_data_not_tampering(self):
        with temporary() as root:
            target, disk = self._enrolled_profile(root)
            # An unlocked-and-mounted ext4 legitimately writes into the
            # payload area (superblock/journal), past metadata AND keyslots.
            with open(disk, "r+b") as handle:
                handle.seek(luks.DATA_OFFSET + 2 * luks.MIB + 4096)
                handle.write(b"mounted filesystem writes here")
            profile.load(root, "dev1")  # must not raise

    def test_header_change_is_tampering(self):
        with temporary() as root:
            target, disk = self._enrolled_profile(root)
            with open(disk, "r+b") as handle:
                # Keyslot material beyond the first MiB must be protected too.
                handle.seek(luks.DATA_OFFSET + luks.MIB + 512)
                handle.write(b"X")
            with self.assertRaises(SafetyError) as raised:
                profile.load(root, "dev1")
            self.assertIn("identity diverged", str(raised.exception))


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
        expected = hashlib.sha256(image[0x30000:0x70000]).hexdigest()
        self.assertEqual(profile.area_digest(image, layout, "SMMSTORE"), expected)
        self.assertEqual(profile.area_digest(image, layout, "GBB"),
                         hashlib.sha256(image[0x81800:0x83800]).hexdigest())
        with self.assertRaises(SafetyError):
            profile.area_digest(image, layout, "NOT_AN_AREA")


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
        provision(root)
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

    def test_qemu_command_attaches_the_enroll_transport_optionally(self):
        plain = " ".join(device.qemu_command("/f", "/d", "/s", kvm=True))
        self.assertEqual(plain.count("ide-hd,"), 1)
        self.assertNotIn("enroll0", plain)
        command = device.qemu_command("/f", "/d", "/s", kvm=True,
                                      enroll_disk="/run/enroll-key.img")
        joined = " ".join(command)
        self.assertIn("-drive if=none,id=enroll0,file=/run/enroll-key.img,format=raw", joined)
        self.assertIn("-device ide-hd,drive=enroll0,bus=ahci0.1,serial=FIREARC_ENROLL_V1", joined)
        self.assertEqual(joined.count("ide-hd,"), 2)

    def test_data_units_are_ordered_and_probe_is_required(self):
        payload = device.dev_cpio(AUTHORITY)
        for unit in (device.DATA_PROBE_UNIT, device.DATA_ENROLL_UNIT,
                     device.DATA_MOUNT_UNIT):
            self.assertIn("After=systemd-pcrphase-initrd.service", unit)
            self.assertIn("sysroot.mount", unit)
            self.assertIn("Before=initrd.target", unit)
        for name in ("firearc-data-probe.service", "firearc-data-enroll.service",
                     "firearc-data-mount.service"):
            self.assertIn(name.encode(), payload)
            self.assertIn(("initrd.target.requires/" + name).encode(), payload)
        # Unlock configuration is crypttab, consumed by the pinned generator
        # into a unit only the mount gate starts (noauto, headless, nofail).
        self.assertIn(b"firearc-data /dev/disk/by-partlabel/FIREARC_DATA - "
                      b"noauto,nofail,tpm2-device=auto,headless", payload)
        self.assertIn(b"systemd-cryptsetup@firearc", payload)
        self.assertIn("Requires=sysroot.mount systemd-cryptsetup@firearc",
                      device.DATA_FILESYSTEM_MOUNT)
        # The probe is observation-only: it never attaches by itself.
        self.assertNotIn("systemd-cryptsetup attach", device.DATA_PROBE_UNIT)
        self.assertIn("/proc/mounts", device.DATA_PROBE_UNIT)
        # The mount gate owns the real unlock: mapper wait, fatal refusal,
        # noexec/nodev/nosuid ext4 mount on the pre-baked sysroot mountpoint.
        self.assertIn("/dev/mapper/firearc-data", device.DATA_FILESYSTEM_MOUNT)
        self.assertIn("Options=rw,noexec,nodev,nosuid", device.DATA_FILESYSTEM_MOUNT)
        self.assertIn("OnFailure=firearc-boot-failure.service", device.DATA_MOUNT_UNIT)
        # The enrollment command binds PCR 7 plus the signed PCR 11 policy,
        # unlocks only via the file-handle credential, and births the ext4
        # filesystem before sealing (failed mkfs leaves the volume
        # retryable: still unenrolled).
        script = (ROOT / "images/initrd/99firearc-root/firearc-data-enroll").read_text()
        self.assertIn("mkfs.ext4 -q -L FIREARC_DATA", script)
        self.assertNotIn("mkfs.ext4 -F", script)
        self.assertIn('0:ext4) : ;;', script)
        self.assertIn("--tpm2-pcrs=7", script)
        self.assertIn("--tpm2-public-key-pcrs=11", script)
        self.assertIn('--unlock-key-file="$key"', script)

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

    def test_dev_unit_holds_initrd_for_runtime_verity_read(self):
        self.assertIn(f"sleep {device.RUNTIME_READ_SETTLE_SECONDS}", device.DEV_UNIT)
        # The known systemd ExecStart pitfall: backslash escapes break quoting.
        self.assertNotIn("\\", device.DEV_UNIT)
        self.assertIn("Before=initrd.target", device.DEV_UNIT)
        self.assertIn(device.RUNTIME_EIO_MARKER, device.DEV_UNIT)
        self.assertIn(device.RUNTIME_CLEAN_MARKER, device.DEV_UNIT)
        # Sessions are ended by the harness; the unit carries no poweroff.
        self.assertNotIn("poweroff", device.DEV_UNIT)

    def test_dev_cpio_blocks_switch_root_behind_the_dev_unit(self):
        from test_device import AUTHORITY, parse_cpio
        entries = parse_cpio(device.dev_cpio(AUTHORITY))
        self.assertIn("etc/systemd/system/initrd.target.requires", entries)
        link = entries["etc/systemd/system/initrd.target.requires/firearc-dev-done.service"]
        self.assertEqual(link, (0o120777, b"../firearc-dev-done.service"))
        self.assertNotIn("etc/systemd/system/initrd.target.wants/firearc-dev-done.service",
                         entries)

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
