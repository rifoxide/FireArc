"""Offline tests for the Secure Boot enforcement-proof stage."""

from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, pipeline, secureboot, uki
from firearc.integrity import SafetyError


class VariantTests(unittest.TestCase):
    def test_install_replaces_the_uki_at_the_esp_partition_offset(self):
        command = secureboot.install_command("tampered", "/payload/tampered.efi")
        self.assertEqual(command[0], "mcopy")
        self.assertIn(f"/disk/device-tampered.raw@@{secureboot.ESP_BYTES}",
                      command)
        self.assertIn(f"::{device.ESP_UKI_PATH}", command)
        self.assertEqual(secureboot.ESP_BYTES, 1024 * 1024)

    def test_install_loader_replaces_both_esp_loader_paths(self):
        command = " ".join(secureboot.install_loader_command(
            "tampered-loader", "/payload/tampered-loader.efi"))
        self.assertIn("EFI/BOOT/BOOTX64.EFI", command)
        self.assertIn("EFI/systemd/systemd-bootx64.efi", command)
        self.assertIn(f"device-tampered-loader.raw@@{secureboot.ESP_BYTES}", command)

    def test_variants_cover_content_tamper_modified_and_loader(self):
        self.assertEqual(secureboot.VARIANTS,
                         ("good", "tampered", "modified", "tampered-loader"))

    def test_tamper_flips_one_linux_section_byte(self):
        binary = _synthetic_uki()
        tampered, offset = secureboot.tamper_uki(binary)
        self.assertEqual(len(tampered), len(binary))
        differences = [index for index, (a, b) in enumerate(zip(binary, tampered))
                       if a != b]
        self.assertEqual(differences, [offset])
        self.assertEqual(binary[offset] ^ tampered[offset], 0x01)
        # The flipped byte is inside the .linux section payload.
        section = next(item for item in uki.pe_sections(binary)[0]
                       if item["name"] == ".linux")
        self.assertTrue(section["offset"] <= offset <
                        section["offset"] + section["bytes"])

    def test_kernel_execution_detection(self):
        self.assertTrue(secureboot.kernel_executed(
            "[    0.000000] Linux version 6.12"))
        self.assertTrue(secureboot.kernel_executed("EFI stub: Loaded initrd"))
        self.assertTrue(secureboot.kernel_executed(device.REQUIRED_MARKER))
        self.assertFalse(secureboot.kernel_executed("Security Violation"))
        self.assertFalse(secureboot.kernel_executed(""))

    def test_refusal_verdict_fails_closed(self):
        refused = secureboot.refusal_verdict("FireArc\nSecurity Violation", False)
        self.assertTrue(refused["refused"])
        self.assertEqual(refused["refusal_evidence"], "security-violation")
        silent = secureboot.refusal_verdict("", True)
        self.assertTrue(silent["refused"])
        self.assertEqual(silent["refusal_evidence"], "bounded-timeout")
        executed = secureboot.refusal_verdict("Linux version 6.12", False)
        self.assertFalse(executed["refused"])
        self.assertTrue(executed["kernel_executed"])

    def test_violation_phrases_survive_console_line_wrap(self):
        # Firmware consoles wrap at VGA width mid-word: the observed denial
        # arrived as "Acc\r\ness denied" and must still match.
        wrapped = ("[1m[31m[40m../src/boot/boot.c:2576@image_start: Error "
                   "loading \\EFI\\Linux\\firearc-a.efi: Acc\r\ness denied\r\n")
        self.assertTrue(secureboot.violation_seen(wrapped))
        self.assertTrue(secureboot.refusal_verdict(wrapped, False)["refused"])
        self.assertEqual(secureboot.refusal_verdict(wrapped, False)
                         ["refusal_evidence"], "security-violation")
        self.assertFalse(secureboot.violation_seen("FIREARC_DEV_BOOT_OK\n"))

    def test_stage_wiring(self):
        self.assertEqual(pipeline.DEPENDENCIES["check-secure-boot"],
                         ("tools", "pcr-sign", "sign", "device", "enroll"))
        self.assertNotIn("check-secure-boot", pipeline.Pipeline.STAGE_INPUTS)


def _synthetic_uki():
    """A minimal amd64 PE image with the required UKI sections."""
    header = bytearray(0x200)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x200)  # PE signature follows the header
    pe = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 5, 0, 0, 0, 0xF0, 0)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    payloads = [(name, bytes([0x11]) * size)
                for name, size in ((".osrel", 0x20), (".cmdline", 0x20),
                                   (".uname", 0x20), (".initrd", 0x20),
                                   (".linux", 0x4000))]
    table_offset = len(header) + len(pe) + len(optional)
    body_offset = table_offset + 40 * len(payloads)
    table, body, pointer = bytearray(), bytearray(), body_offset
    for name, data in payloads:
        entry = bytearray(40)
        entry[0:len(name)] = name.encode()
        struct.pack_into("<IIII", entry, 8, len(data), 0, len(data), pointer)
        table += entry
        body += data
        pointer += len(data)
    return bytes(header + pe + optional + table + body)


if __name__ == "__main__":
    unittest.main()
