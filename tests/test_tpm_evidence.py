"""Offline tests for the Phase 5 TCG event-log extraction, parsing and replay."""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import tpm_evidence
from firearc.integrity import SafetyError

SHA1, SHA256 = b"\x11" * 20, b"\x22" * 32


def spec_id_event():
    """Spec ID event with SHA-1 and SHA-256 active banks."""
    algorithms = struct.pack("<HH", 0x0004, 20) + struct.pack("<HH", 0x000B, 32)
    body = (b"Spec ID Event03\x00" + struct.pack("<I", 0)  # platform class
            + bytes([2, 0, 0, 2])                            # version, errata, uintn
            + struct.pack("<I", 2) + algorithms
            + bytes([0]))                                    # vendor info size
    return (struct.pack("<II", 0, 0x00000003) + b"\x00" * 20
            + struct.pack("<I", len(body)) + body)


def agile_event(pcr, event_type, event, sha1=SHA1, sha256=SHA256):
    digests = (struct.pack("<I", 2) + struct.pack("<H", 0x0004) + sha1
               + struct.pack("<H", 0x000B) + sha256)
    return (struct.pack("<II", pcr, event_type) + digests
            + struct.pack("<I", len(event)) + event)


def synthetic_log():
    return (spec_id_event()
            + agile_event(0, 0x00000008, b"separator")
            + agile_event(7, 0x80000001, b"SecureBoot-variable")
            + agile_event(11, 0x80000007, b"Calling EFI Application from Boot Option"))


def serial_with(hex_payload, noise=True):
    lines = ["early boot noise", tpm_evidence.DUMP_BEGIN]
    for index in range(0, len(hex_payload), 32):
        chunk = hex_payload[index:index + 32]
        if noise and index == 32:
            lines.append("[  OK  ] Finished initrd-parse-etc.service — interleaved")
        lines.append(" ".join(chunk[index2:index2 + 2] for index2 in range(0, len(chunk), 2)))
    lines.extend([tpm_evidence.DUMP_END, "later boot noise"])
    return "\r\n".join(lines) + "\r\n"


class HexExtractionTests(unittest.TestCase):
    def test_roundtrip_with_interleaved_console_lines(self):
        payload = synthetic_log()
        text = serial_with(payload.hex())
        self.assertEqual(tpm_evidence.hex_from_serial(text), payload)

    def test_missing_brackets_fail_closed(self):
        with self.assertRaises(SafetyError):
            tpm_evidence.hex_from_serial("no dump here")
        with self.assertRaises(SafetyError):
            tpm_evidence.hex_from_serial(f"{tpm_evidence.DUMP_BEGIN}\r\nff ff\r\n")

    def test_implausible_small_payload_fails(self):
        with self.assertRaises(SafetyError):
            tpm_evidence.hex_from_serial(
                f"{tpm_evidence.DUMP_BEGIN}\r\nab cd\r\n{tpm_evidence.DUMP_END}")

    def test_odd_length_hex_line_is_skipped_as_noise(self):
        with self.assertRaises(SafetyError):
            tpm_evidence.hex_from_serial(f"{tpm_evidence.DUMP_BEGIN}\r\nabc\r\n"
                                         f"{tpm_evidence.DUMP_END}")


class ParseTests(unittest.TestCase):
    def test_event_count_fields_and_digests(self):
        events = tpm_evidence.parse_tcg2_log(synthetic_log())
        self.assertEqual([event.pcr for event in events], [0, 0, 7, 11])
        self.assertEqual([event.event_type for event in events],
                         [0x00000003, 0x00000008, 0x80000001, 0x80000007])
        for event in events[1:]:
            self.assertEqual(event.digests["sha1"], SHA1)
            self.assertEqual(event.digests["sha256"], SHA256)

    def test_spec_id_signature_required(self):
        broken = synthetic_log()
        broken = b"XXXXXXXXXXXXXXX\x00" + broken[15:]
        with self.assertRaises(SafetyError):
            tpm_evidence.parse_tcg2_log(broken)

    def test_truncated_log_fails(self):
        with self.assertRaises(SafetyError):
            tpm_evidence.parse_tcg2_log(synthetic_log()[:-5])

    def test_unknown_digest_algorithm_fails(self):
        bad = (spec_id_event()
               + struct.pack("<II", 0, 0x00000008) + struct.pack("<I", 1)
               + struct.pack("<H", 0xDEAD) + SHA1)
        with self.assertRaises(SafetyError):
            tpm_evidence.parse_tcg2_log(bad)


class ReplayTests(unittest.TestCase):
    def test_extend_semantics_sha256(self):
        events = tpm_evidence.parse_tcg2_log(synthetic_log())
        values = tpm_evidence.replay(events, "sha256")
        expected = hashlib.sha256(bytes(32) + SHA256).hexdigest()
        self.assertEqual(values[0], expected)  # one extend on PCR 0
        self.assertEqual(values[1], "0" * 64)  # untouched PCR stays zero

    def test_extend_semantics_sha1(self):
        events = tpm_evidence.parse_tcg2_log(synthetic_log())
        values = tpm_evidence.replay(events, "sha1")
        self.assertEqual(values[7], hashlib.sha1(bytes(20) + SHA1).hexdigest())

    def test_bank_isolation_and_ordering(self):
        first = b"\xaa" * 32
        second = b"\xbb" * 32
        log = (spec_id_event()
               + agile_event(4, 0x00000006, b"one", sha256=first)
               + agile_event(4, 0x00000006, b"two", sha256=second))
        values = tpm_evidence.replay(tpm_evidence.parse_tcg2_log(log), "sha256")
        chained = hashlib.sha256(hashlib.sha256(bytes(32) + first).digest() + second).hexdigest()
        self.assertEqual(values[4], chained)

    def test_unsupported_bank_rejected(self):
        with self.assertRaises(SafetyError):
            tpm_evidence.replay([], "sha512")

    def test_out_of_range_pcr_rejected(self):
        log = spec_id_event() + agile_event(24, 0x00000006, b"beyond")
        with self.assertRaises(SafetyError):
            tpm_evidence.replay(tpm_evidence.parse_tcg2_log(log), "sha256")


class ProducerMapTests(unittest.TestCase):
    def test_summary_counts_extends_and_dedupes(self):
        events = tpm_evidence.parse_tcg2_log(synthetic_log())
        summary = tpm_evidence.summarize(events)
        self.assertEqual(summary[7]["extends"], 1)
        self.assertIn("EV_EFI_VARIABLE_BOOT", summary[7]["producers"])

    def test_action_string_decoding(self):
        events = tpm_evidence.parse_tcg2_log(synthetic_log())
        self.assertIn("EDK II boot manager launching the next boot option",
                      events[-1].describe())


if __name__ == "__main__":
    unittest.main()
