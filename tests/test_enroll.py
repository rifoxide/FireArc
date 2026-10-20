"""Offline tests for offline variable-store enrollment."""

from pathlib import Path
import struct
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import enroll, keys, pipeline
from firearc.integrity import SafetyError

# EFI_TIME: Year, Month, Day, Hour, Minute, Second, Pad1, Nanosecond,
# TimeZone, Daylight, Pad2 — exactly 16 bytes.
VALID_TIME = struct.pack("<HBBBBBBIhBB", 2026, 10, 20, 12, 0, 0, 0, 0, 0, 0, 0)


class HeaderTests(unittest.TestCase):
    def test_fv_header_mirrors_the_payload_format_and_checksums_to_zero(self):
        header = enroll.fv_header(0x40000)
        self.assertEqual(len(header), 0x48)
        self.assertEqual(header[40:44], b"_FVH")
        self.assertEqual(struct.unpack_from("<I", header, 44)[0], enroll.FV_ATTRIBUTES)
        self.assertEqual(uuid.UUID(bytes_le=header[16:32]), enroll.SYSTEM_FV_GUID)
        self.assertEqual(struct.unpack_from("<Q", header, 32)[0], 0x40000)
        self.assertEqual(header[55], 2)  # firmware-volume revision
        self.assertEqual(struct.unpack_from("<H", header, 48)[0], 0x48)
        self.assertEqual(struct.unpack_from("<II", header, 56), (4, 0x10000))
        words = struct.unpack("<36H", header)
        self.assertEqual(sum(words) & 0xFFFF, 0)
        # Rejects regions that are not whole 64 KiB multiples.
        self.assertRaises(SafetyError, enroll.fv_header, 0x40001)

    def test_varstore_header_is_authenticated_and_healthy(self):
        header = enroll.varstore_header(0x40000)
        self.assertEqual(len(header), 28)
        self.assertEqual(uuid.UUID(bytes_le=header[:16]), enroll.AUTH_VARSTORE_GUID)
        # The payload's PcdVariableStoreSize is 64 KiB: Size covers the store
        # inside the larger region, exactly as the payload initializes it.
        self.assertEqual(struct.unpack_from("<I", header, 16)[0],
                         enroll.VARSTORE_SIZE - 0x48)
        self.assertEqual(header[20], enroll.STORE_FORMATTED)
        self.assertEqual(header[21], enroll.STORE_HEALTHY)
        self.assertRaises(SafetyError, enroll.varstore_header, 0x8000)

    def test_entry_layout_matches_the_pinned_variable_format(self):
        record = enroll.entry("PK", enroll.GLOBAL_VARIABLE_GUID, 0x27, b"payload")
        self.assertEqual(len(record), 60 + 2 * 2 + 2 + 7)  # header + "PK\0" + data
        self.assertEqual(struct.unpack_from("<H", record, 0)[0], 0x55AA)
        self.assertEqual(record[2], enroll.VAR_ADDED)
        self.assertEqual(struct.unpack_from("<I", record, 4)[0], 0x27)
        self.assertEqual(struct.unpack_from("<III", record, 32), (0, 6, 7))
        self.assertEqual(uuid.UUID(bytes_le=record[44:60]), enroll.GLOBAL_VARIABLE_GUID)
        self.assertEqual(record[60:66], "PK".encode("utf-16-le") + b"\x00\x00")
        self.assertEqual(record[66:], b"payload")


class DigestTests(unittest.TestCase):
    def _signed_pe(self, digest=b"\x11" * 32):
        """A minimal PE whose certificate table embeds a PKCS#7 digest."""
        cert_body = (bytes.fromhex("0609608648016503040201") + b"\x05\x00"
                     + b"\x04\x20" + digest)
        header = bytearray(0x400)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x200)
        optional = 0x218
        struct.pack_into("<II", header, optional + 144, 0x400, 8 + len(cert_body))
        return bytes(header) + struct.pack("<IHH", 8 + len(cert_body), 0x200, 2) + cert_body

    def test_signed_digest_extracts_the_signature_digest(self):
        digest = bytes(range(32))
        self.assertEqual(enroll.signed_digest(self._signed_pe(digest)), digest)
        # The NULL-parameters form is optional.
        body = (bytes.fromhex("0609608648016503040201") + b"\x04\x20"
                + bytes(range(32)))
        header = bytearray(0x400)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x200)
        struct.pack_into("<II", header, 0x218 + 144, 0x400, 8 + len(body))
        pe = bytes(header) + struct.pack("<IHH", 8 + len(body), 0x200, 2) + body
        self.assertEqual(enroll.signed_digest(pe), bytes(range(32)))

    def _alg_free_pe(self):
        """A signed PE whose certificate lacks the sha256 digest algorithm."""
        body = b"\x30\x0c\x30\x0a\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05"
        header = bytearray(0x400)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x200)
        struct.pack_into("<II", header, 0x218 + 144, 0x400, 8 + len(body))
        return bytes(header) + struct.pack("<IHH", 8 + len(body), 0x200, 2) + body

    def test_signed_digest_fails_closed(self):
        # No certificate table: the directory entry is zero.
        blank = bytearray(0x400)
        blank[0:2] = b"MZ"
        self.assertRaises(SafetyError, enroll.signed_digest, bytes(blank))
        # A certificate that is not PKCS signed data.
        weird = bytearray(0x400)
        weird[0:2] = b"MZ"
        struct.pack_into("<II", weird, 0x218 + 144, 0x200, 16)
        pe = bytes(weird[:0x200]) + struct.pack("<IHH", 16, 0x200, 9) + b"\x00" * 8
        self.assertRaises(SafetyError, enroll.signed_digest, pe)
        # No sha256 digest algorithm anywhere in the certificate.
        self.assertRaises(SafetyError, enroll.signed_digest,
                          self._signed_pe()[:0] + self._alg_free_pe())

    def test_hash_entry_layout(self):
        digest = bytes(range(32))
        entry = enroll.hash_entry(digest, "fa1ec0de-05ec-4a41-8a41-0000000000a1")
        self.assertEqual(entry[:16], enroll.CERT_SHA256_GUID.bytes_le)
        self.assertEqual(struct.unpack_from("<III", entry, 16),
                         (28 + 16 + 32, 0, 16 + 32))
        self.assertEqual(entry[28:44], uuid.UUID(
            "fa1ec0de-05ec-4a41-8a41-0000000000a1").bytes_le)
        self.assertEqual(entry[44:], digest)


class StoreTests(unittest.TestCase):
    def variables(self):
        return [
            {"name": "certdb", "guid": str(enroll.CERT_DB_GUID),
             "attributes": enroll.ATTR_NV_BS_RT_AT, "data": struct.pack("<I", 4)},
            {"name": "PK", "guid": str(enroll.GLOBAL_VARIABLE_GUID),
             "attributes": enroll.ATTR_NV_BS_RT_AT, "data": b"\x11" * 16,
             "timestamp": VALID_TIME},
            # A name whose data end is unaligned, to prove 4-byte entry alignment.
            {"name": "AB", "guid": str(enroll.GLOBAL_VARIABLE_GUID),
             "attributes": enroll.ATTR_NV_BS_RT, "data": b"\x01"},
        ]

    def test_construct_and_parse_round_trip(self):
        region = enroll.construct_region(0x10000, self.variables())
        self.assertEqual(len(region), 0x10000)
        parsed = enroll.parse_store(region)
        self.assertEqual([v["name"] for v in parsed], ["certdb", "PK", "AB"])
        self.assertEqual(parsed[1]["data"], b"\x11" * 16)
        self.assertEqual(parsed[2]["data"], b"\x01")
        # The erased tail after the last entry is intact.
        self.assertEqual(region[-1], 0xFF)
        # Entries are aligned: certdb ends unaligned, PK and AB headers start
        # on 4-byte boundaries after padding.
        certdb_len = 60 + 14 + 4                    # header + "certdb\0" + 4 data
        pk_start = (0x64 + certdb_len + 3) & ~3     # 180
        pk_len = 60 + 6 + 16                        # header + "PK\0" + 16 data
        ab_start = (pk_start + pk_len + 3) & ~3     # 264
        self.assertEqual(struct.unpack_from("<H", region, pk_start)[0], 0x55AA)
        self.assertEqual(struct.unpack_from("<H", region, ab_start)[0], 0x55AA)
        self.assertEqual(region[pk_start + 2], enroll.VAR_ADDED)

    def test_parse_fails_closed_on_garbage_after_entries(self):
        region = bytearray(enroll.construct_region(0x10000, self.variables()))
        region[-1] = 0x00
        self.assertRaises(SafetyError, enroll.parse_store, bytes(region))

    def test_parse_stops_at_erased_tail(self):
        region = enroll.construct_region(0x10000, [])
        self.assertEqual(enroll.parse_store(region), [])

        # A timestamp that is not a 16-byte EFI_TIME fails closed (a byte
        # shift here would silently corrupt every following entry).
        self.assertRaises(SafetyError, enroll.entry, "PK", enroll.GLOBAL_VARIABLE_GUID,
                          0x27, b"x", b"\x00" * 17)

    def test_enrollment_that_does_not_fit_fails(self):
        big = [{"name": "PK", "guid": str(enroll.GLOBAL_VARIABLE_GUID),
                "attributes": 7, "data": b"\x00" * 0x10000}]
        self.assertRaises(SafetyError, enroll.construct_region, 0x10000, big)


class ContentTests(unittest.TestCase):
    def secrets(self, root):
        directory = root / "secrets"
        directory.mkdir(mode=0o700)
        for name in keys.ALL_OUTPUTS:
            if name == "manifest.json":
                continue
            if name.endswith(".esl"):
                (directory / name).write_bytes(f"esl-{name}".encode())
            elif name.endswith(".auth"):
                (directory / name).write_bytes(VALID_TIME + f"pkcs7-{name}".encode())
            else:
                (directory / name).write_bytes(b"fixture")
        (directory / "manifest.json").write_text(
            '{"schema":1,"certificates":{"pk":{"sha256_fingerprint":"' + "0" * 64 + '"}}}')

    def test_variables_derive_from_the_generated_hierarchy(self):
        from support import temporary
        with temporary() as root:
            self.secrets(root)
            prepared = enroll.variables(root)
            by_name = {v["name"]: v for v in prepared}
            self.assertEqual([v["name"] for v in prepared],
                             ["certdb", "PK", "KEK", "db", "SecureBootEnable",
                              "SecureBoot", "SetupMode"])
            # PK/KEK live in the global-variable GUID; db is a security database.
            self.assertEqual(by_name["PK"]["guid"], str(enroll.GLOBAL_VARIABLE_GUID))
            self.assertEqual(by_name["KEK"]["guid"], str(enroll.GLOBAL_VARIABLE_GUID))
            self.assertEqual(by_name["db"]["guid"], str(enroll.SECURITY_DATABASE_GUID))
            # Stored payloads are the ESLs; timestamps come from the .auth files.
            self.assertEqual(by_name["PK"]["data"], b"esl-pk.esl")
            self.assertEqual(by_name["db"]["data"], b"esl-db.esl")
            self.assertEqual(by_name["PK"]["timestamp"], VALID_TIME)
            # Mode flags are plain one-byte values; the derivation variable
            # carries NV|BS exactly as the firmware's init writes it, while
            # the runtime-managed flags are BS|RT (an NV attribute there
            # breaks the boot-time rewrite).
            self.assertEqual(by_name["SecureBoot"]["data"], b"\x01")
            self.assertEqual(by_name["SetupMode"]["data"], b"\x00")
            self.assertEqual(by_name["SecureBoot"]["attributes"], 0x6)
            self.assertEqual(by_name["SecureBootEnable"]["data"], b"\x01")
            self.assertEqual(by_name["SecureBootEnable"]["guid"],
                             str(enroll.SECURE_BOOT_ENABLE_GUID))
            self.assertEqual(by_name["SecureBootEnable"]["attributes"], 0x3)
            # certdb mirrors the payload's empty certificate database.
            self.assertEqual(by_name["certdb"]["data"], struct.pack("<I", 4))

    def test_implausible_timestamps_are_refused(self):
        from support import temporary
        with temporary() as root:
            self.secrets(root)
            (root / "secrets/pk.auth").write_bytes(
                struct.pack("<HBBBBBBIhBB", 1999, 13, 32, 25, 0, 0, 0, 0, 0, 0, 0))
            self.assertRaises(SafetyError, enroll.variables, root)

    def test_stage_wiring(self):
        self.assertEqual(pipeline.DEPENDENCIES["enroll"], ("firmware-build", "sign"))
        inputs = pipeline.Pipeline.STAGE_INPUTS["enroll"]
        for name in ("secrets/manifest.json", "secrets/pk.esl", "secrets/kek.esl",
                     "secrets/db.esl", "secrets/pk.auth", "secrets/kek.auth",
                     "secrets/db.auth", "src/firearc/enroll.py"):
            self.assertIn(name, inputs)


if __name__ == "__main__":
    unittest.main()
