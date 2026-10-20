"""Offline tests for the isolated signing step."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, pipeline, sign


class SignTests(unittest.TestCase):
    def test_command_pair_is_isolated_and_verifiable(self):
        for name in (device.UKI_ARTIFACT, sign.LOADER_ARTIFACT):
            signing, verify = sign.commands(name)
            # Only the sb key pair enters the signing command.
            self.assertIn("--key /keys/sb.key", " ".join(signing))
            self.assertIn("--cert /keys/sb.crt", " ".join(signing))
            self.assertNotIn("pk.key", " ".join(signing))
            self.assertNotIn("kek.key", " ".join(signing))
            # The artifact is verified against the certificate, not the key.
            self.assertIn(f"sbverify --cert /keys/sb.crt /work/{name}", " ".join(verify))

    def _synthetic_pair(self, certificate=b"CERTIFICATE", *, tamper=None,
                        rva=None, size=None):
        """(unsigned, signed) pair shaped like sbsign output."""
        header = bytearray(0x100)
        header[0:2] = b"MZ"
        import struct
        struct.pack_into("<I", header, 0x3C, 0x40)
        pe = bytearray(b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0x80, 0))
        # 0x80-byte optional header with 16 zero data directories
        optional = bytearray(0x80)
        struct.pack_into("<H", optional, 0, 0x20B)
        unsigned = bytes(header + pe + optional) + b"CONTENT\0" * 4
        directory = 0x40 + 4 + 20 + 112 + 32
        signed = bytearray(unsigned + certificate)
        struct.pack_into("<I", signed, 0x40 + 4 + 20 + 64, 0xDEADBEEF)  # checksum
        struct.pack_into("<II", signed, directory,
                         len(unsigned) if rva is None else rva,
                         len(certificate) if size is None else size)
        if tamper is not None:
            signed[tamper] ^= 0xFF
        return unsigned, bytes(signed)

    def test_covers_content_accepts_only_exact_signature_appends(self):
        unsigned, signed = self._synthetic_pair()
        self.assertTrue(sign.covers_content(unsigned, signed))
        # A changed content byte outside checksum/certificate-directory fields
        # means the signature covers something else.
        _, tampered = self._synthetic_pair(tamper=0x123)
        self.assertFalse(sign.covers_content(unsigned, tampered))
        # The certificate must be appended exactly at the original length.
        _, moved = self._synthetic_pair(rva=0x120)
        self.assertFalse(sign.covers_content(unsigned, moved))
        _, sized = self._synthetic_pair(size=4)
        self.assertFalse(sign.covers_content(unsigned, sized))
        self.assertFalse(sign.covers_content(signed, signed))
        self.assertFalse(sign.covers_content(b"ELF", signed))

    def test_stage_wiring_puts_signing_between_uki_and_device(self):
        self.assertEqual(pipeline.DEPENDENCIES["sign"], ("tools", "root", "uki"))
        self.assertEqual(pipeline.DEPENDENCIES["device"], ("tools", "rootfs", "sign"))
        # Regenerating the custody manifest restages signatures; unrelated
        # source churn alone does not.
        self.assertEqual(pipeline.Pipeline.STAGE_INPUTS["sign"],
                         ["secrets/manifest.json", "src/firearc/sign.py"])

    def test_loader_member_is_the_root_archive_loader(self):
        self.assertEqual(sign.LOADER_ARTIFACT, "systemd-bootx64.efi")
        self.assertEqual(sign.LOADER_MEMBER,
                         "./usr/lib/systemd/boot/efi/systemd-bootx64.efi")


if __name__ == "__main__":
    unittest.main()
