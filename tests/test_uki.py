"""Offline tests for the unsigned Unified Kernel Image construction."""

from pathlib import Path
import hashlib
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, uki
from firearc.integrity import SafetyError


def synthetic_pe(sections, *, machine=0x8664, timestamp=0x69DD461D):
    """Minimal amd64 PE carrying (name, content) sections at 512-byte stride."""
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)  # e_lfanew
    pe = bytearray(b"PE\0\0")
    pe += struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, 0, 0)  # 20-byte COFF header, no optional header
    table = bytearray()
    body = bytearray()
    pointer = 0x40 + 4 + 20 + 40 * len(sections)
    for name, content in sections:
        padded = pointer + (-pointer % 512)
        body += b"\0" * (padded - pointer)
        pointer = padded
        entry = bytearray(40)
        entry[:8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIII", entry, 8, 0, 0, len(content), pointer)
        table += entry
        body += content
        pointer += len(content)
    return bytes(header + pe + table + body)


class UkiTests(unittest.TestCase):
    def test_segment_padding_aligns_cpio_segments(self):
        for size, expected in ((0, 0), (43, 1), (44, 0), (45, 3), (46, 2), (47, 1), (48, 0)):
            self.assertEqual(uki.segment_padding(size), expected)
            self.assertEqual((size + uki.segment_padding(size)) % 4, 0)

    def test_pe_sections_reads_names_sizes_and_digests(self):
        binary = synthetic_pe([(".osrel", b"ID=firearc\n"), (".linux", b"KERNELDATA")])
        sections, timestamp = uki.pe_sections(binary)
        self.assertEqual(timestamp, 0x69DD461D)
        by_name = {section["name"]: section for section in sections}
        self.assertEqual(by_name[".osrel"]["bytes"], len(b"ID=firearc\n"))
        self.assertEqual(by_name[".linux"]["bytes"], len(b"KERNELDATA"))
        self.assertEqual(by_name[".linux"]["sha256"], hashlib.sha256(b"KERNELDATA").hexdigest())
        raw = binary[by_name[".linux"]["offset"]:by_name[".linux"]["offset"] + by_name[".linux"]["bytes"]]
        self.assertEqual(raw, b"KERNELDATA")

    def test_pe_sections_rejects_broken_images(self):
        with self.assertRaises(SafetyError):
            uki.pe_sections(b"ELF...\x00\x00")  # not MZ
        truncated = synthetic_pe([(".linux", b"X" * 8)])[:0x50]
        with self.assertRaises(SafetyError):
            uki.pe_sections(truncated)  # section table cut off
        arm = synthetic_pe([(".linux", b"X")], machine=0xAA64)
        with self.assertRaises(SafetyError):
            uki.pe_sections(arm)  # not amd64
        bad_signature = bytearray(synthetic_pe([(".linux", b"X")]))
        bad_signature[0x40:0x44] = b"PE\x00\x01"
        with self.assertRaises(SafetyError):
            uki.pe_sections(bytes(bad_signature))

    def test_section_carries_matches_content_with_zero_padding_only(self):
        section = {"offset": 0, "bytes": 16}
        self.assertTrue(uki.section_carries(b"KERNELDATA\0\0\0\0\0\0\0", section, b"KERNELDATA"))
        self.assertTrue(uki.section_carries(b"KERNELDATA", section, b"KERNELDATA"))
        self.assertFalse(uki.section_carries(b"KERNELDATA\x01", section, b"KERNELDATA"))
        self.assertFalse(uki.section_carries(b"OTHERDATA\0\0\0\0\0\0\0", section, b"KERNELDATA"))

    def test_required_sections_and_artifact_names_agree_with_device(self):
        self.assertEqual(uki.REQUIRED_SECTIONS, (".osrel", ".cmdline", ".uname", ".linux", ".initrd"))
        # The UKI artifact the stage produces is exactly the file the device
        # ESP installs, and the ESP boot path is a systemd-boot type-2 path.
        self.assertEqual(device.UKI_ARTIFACT, "firearc-uki-a.efi")
        self.assertEqual(device.ESP_UKI_PATH, "EFI/Linux/firearc-a.efi")
        self.assertEqual(Path(device.ESP_UKI_PATH).parent.as_posix(), "EFI/Linux")
        self.assertNotEqual(device.UKI_ARTIFACT, Path(device.ESP_UKI_PATH).name)
        # The slot identity is embedded in the kernel command line the UKI
        # carries, not in a loader entry file.
        self.assertIn("rauc.slot=A", device.KERNEL_CMDLINE)

    def test_required_sections_all_parse_in_a_probe_shaped_pe(self):
        binary = synthetic_pe([(name, name.encode().upper() + b"!")
                               for name in uki.REQUIRED_SECTIONS])
        sections, _ = uki.pe_sections(binary)
        names = {section["name"] for section in sections}
        self.assertTrue(set(uki.REQUIRED_SECTIONS) <= names)
        for name in uki.REQUIRED_SECTIONS:
            content = name.encode().upper() + b"!"
            section = next(s for s in sections if s["name"] == name)
            self.assertTrue(uki.section_carries(binary, section, content))


if __name__ == "__main__":
    unittest.main()
