"""Offline tests for the development installed-device profile and boot check."""

from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, rootfs
from firearc.integrity import SafetyError, read_json, write_json
from support import temporary

AUTHORITY = {"schema": 1, "format": 1, "algorithm": "sha256", "data_bytes": 4 * 1024**3,
             "hash_bytes": 128 * 1024**2, "data_blocks": 1048576, "data_block_size": 4096,
             "hash_block_size": 4096, "hash_offset": 0,
             "salt": "ab" * 32, "root_hash": "cd" * 32}


def parse_cpio(payload):
    """Minimal structural reader mirroring the kernel's newc consumption."""
    entries, offset = {}, 0
    while offset + 110 <= len(payload):
        if payload[offset:offset + 6] != b"070701":
            raise AssertionError("bad newc magic")
        fields = [int(payload[offset + 6 + 8 * index:offset + 14 + 8 * index], 16) for index in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        name_start = offset + 110
        name = payload[name_start:name_start + namesize - 1].decode()
        data_start = name_start + namesize + (-(110 + namesize) % 4)
        entries[name] = (mode, payload[data_start:data_start + size])
        if name == "TRAILER!!!":
            return entries
        offset = data_start + size + (-size % 4)
    raise AssertionError("missing cpio trailer")


class DeviceTests(unittest.TestCase):
    def test_dev_cpio_is_deterministic_and_kernel_shaped(self):
        first = device.dev_cpio(AUTHORITY)
        second = device.dev_cpio(dict(AUTHORITY))
        self.assertEqual(first, second)
        self.assertEqual(len(first) % 4, 0)
        # The kernel only recognizes cpio segments at 4-byte-aligned offsets of
        # the concatenated initramfs; any compressed base size must be padded.
        for base_size in (43, 44, 45, 46, 43_404_697):
            padding = -base_size % 4
            self.assertIn(padding, (0, 1, 2, 3))
            self.assertEqual((base_size + padding) % 4, 0)
        entries = parse_cpio(first)
        self.assertIn("TRAILER!!!", entries)
        authority = entries["etc/firearc/verity.authority"]
        self.assertEqual(authority[0], 0o100644)
        self.assertEqual(authority[1].decode(), rootfs.render_initrd_authority(AUTHORITY, "A"))
        unit = entries["etc/systemd/system/firearc-dev-done.service"][1].decode()
        self.assertIn("Requires=sysroot.mount", unit)
        self.assertIn("--force poweroff", unit)
        self.assertNotIn("\nEnvironment=", unit)
        link = entries["etc/systemd/system/initrd.target.wants/firearc-dev-done.service"]
        self.assertEqual(link[0], 0o120777)
        self.assertEqual(link[1], b"../firearc-dev-done.service")
        self.assertEqual(entries["etc"][0], 0o40755)

    def test_dev_cpio_authority_matches_the_gate_parser_contract(self):
        text = parse_cpio(device.dev_cpio(AUTHORITY))["etc/firearc/verity.authority"][1].decode()
        expected = {"schema", "layout_version", "slot", "root_hash", "salt", "format", "algorithm",
                    "data_bytes", "data_blocks", "data_block_size", "hash_bytes", "hash_block_size", "hash_offset"}
        pairs = dict(line.split("=") for line in text.splitlines())
        self.assertEqual(set(pairs), expected)
        self.assertEqual(pairs["slot"], "A")
        self.assertFalse(re.search(r"[^a-zA-Z0-9_=\n]", text))
        wrong = dict(AUTHORITY, salt="AB" * 32)
        with self.assertRaises(SafetyError):
            device.dev_cpio(wrong)

    def test_cpio_archive_rejects_unsafe_paths_and_modes(self):
        for name in ("/absolute", "../escape", "name\0x"):
            with self.subTest(name=name), self.assertRaises(SafetyError):
                device.cpio_archive([(name, 0o100644, b"data")])
        with self.assertRaises(SafetyError):
            device.cpio_archive([("ok", 0o100777, b"data")])

    def test_partition_layout_is_aligned_complete_and_scriptable(self):
        script = device.sfdisk_script()
        self.assertEqual(script, device.sfdisk_script())
        self.assertTrue(script.startswith("label: gpt\n"))
        rows = [line for line in script.splitlines() if line.startswith("start=")]
        self.assertEqual(len(rows), 3)
        self.assertIn('name="FIREARC_ESP", attrs=RequiredPartition', rows[0])
        self.assertIn('name="FIREARC_ROOT_A"', rows[1])
        self.assertIn('name="FIREARC_HASH_A"', rows[2])
        parsed = []
        for row in rows:
            fields = dict(re.findall(r"(\w+)=(\"[^\"]+\"|[^,]+)", row))
            parsed.append((fields["start"], fields["size"], fields["name"].strip('"')))
        self.assertEqual([row[0] for row in parsed], ["2048", str(2048 + 512 * 1024**2 // 512),
                                                      str(2048 + (512 * 1024**2 + 4 * 1024**3) // 512)])
        covered = sum(int(row[1]) for row in parsed)
        self.assertEqual(device.DISK_MIB * 1024 * 2, 2048 + covered + 2048)
        self.assertEqual(device.ROOT_OFFSET, (1 + 512) * 1024 * 1024)
        self.assertEqual(device.HASH_OFFSET, device.ROOT_OFFSET + 4 * 1024**3)
        self.assertEqual(len({row[4] for row in device.PARTITIONS}), 3)

    def test_boot_entry_and_loader_configuration(self):
        self.assertIn("rauc.slot=A", device.KERNEL_CMDLINE)
        self.assertIn("rd.emergency=poweroff", device.KERNEL_CMDLINE)
        for forbidden in ("rd.shell=1", "rw", "init=", "rd.break", "systemd.unit="):
            self.assertNotIn(forbidden + " ", device.KERNEL_CMDLINE + " ")
        self.assertIn("console=ttyS0,115200", device.KERNEL_CMDLINE)
        self.assertIn("options " + device.KERNEL_CMDLINE + "\n", device.BOOT_ENTRY)
        self.assertIn("initrd  /firearc/initrd.img", device.BOOT_ENTRY)
        self.assertEqual(device.LOADER_CONF, "timeout 0\ndefault firearc-a\neditor no\n")

    def test_qemu_command_shape(self):
        command = device.qemu_command("/fw/CODE.fd", "/run/vars.fd", "/disks/dev.raw", "/run/s.log", kvm=False)
        joined = " ".join(command)
        self.assertEqual(command[0], "qemu-system-x86_64")
        self.assertIn("-machine q35", joined)
        self.assertIn("-accel tcg", joined)
        self.assertIn("accel kvm", " ".join(device.qemu_command(
            "/c", "/v", "/d", "/s", kvm=True)))
        for required in ("-no-reboot", "-display none", "-net none", "-nodefaults",
                         "if=pflash,format=raw,readonly=on,file=/fw/CODE.fd",
                         "if=pflash,format=raw,file=/run/vars.fd",
                         "file=/disks/dev.raw,format=raw,if=virtio",
                         "-serial file:/run/s.log"):
            self.assertIn(required, joined)

    def test_boot_verdict_requires_distinct_success_and_denial_evidence(self):
        good = "\n".join(device.POSITIVE_MARKERS) + "\n"
        markers, denial = device.boot_verdict(good)
        self.assertTrue(all(markers.values()))
        self.assertFalse(denial["denial"])
        # The self-verifying terminal marker alone is authoritative evidence;
        # forwarded gate status lines may be dropped without failing the boot.
        markers, denial = device.boot_verdict("FIREARC_DEV_BOOT_OK\n")
        self.assertTrue(markers[device.REQUIRED_MARKER])
        self.assertFalse(denial["denial"])
        partial = "\n".join(marker for marker in device.POSITIVE_MARKERS
                            if marker != device.REQUIRED_MARKER)
        markers, denial = device.boot_verdict(partial)
        self.assertFalse(markers[device.REQUIRED_MARKER])
        markers, denial = device.boot_verdict("Verification failed at position 42.\npoweroff\n")
        self.assertFalse(any(markers.values()))
        self.assertTrue(denial["denial"])
        for broken in ("", None):
            with self.subTest(broken=broken), self.assertRaises(SafetyError):
                device.boot_verdict(broken)
        with self.assertRaises(SafetyError):
            device.boot_verdict("x" * (8 * 1024 * 1024 + 1))

    def test_ovmf_pins_verify_against_host_files(self):
        result = device.ovmf_pins(ROOT)
        self.assertEqual(set(result), {"code", "vars"})
        self.assertEqual(result["code"].name, "OVMF_CODE.4m.fd")
        wrong = {"ovmf": {"code": {"path": "/usr/share/OVMF/x64/OVMF_CODE.4m.fd", "sha256": "0" * 64}}}
        with patch.object(device, "load_lock", return_value={"ovmf": wrong["ovmf"] | {
                "vars": {"path": str(result["vars"]), "sha256": "1" * 64}}}):
            with self.assertRaises(SafetyError):
                device.ovmf_pins(ROOT)
        with patch.object(device, "load_lock", return_value={"ovmf": {"code": wrong["ovmf"]["code"]}}):
            with self.assertRaises(SafetyError):
                device.ovmf_pins(ROOT)


if __name__ == "__main__":
    unittest.main()
