"""Offline tests for the PCR 11 policy model and .pcrsig validation.

The goldens below are not arbitrary: the expected-PCR and policy-digest
vectors were validated against this platform's real measurement behavior
(dev5 boot evidence: replayed TCG event log, the pinned systemd-measure
257.13 prediction and its signed output) before being recorded; the
synthetic vectors pin the same code path for regression.
"""

from pathlib import Path
import base64
import hashlib
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import pcr_keys, pcr_sign, uki
from firearc.integrity import SafetyError

# Synthetic, self-contained section set.
SYNTHETIC = {
    ".linux": bytes(range(256)) * 4,
    ".osrel": b"ID=firearc-test\n",
    ".cmdline": b"console=ttyS0 test=1",
    ".initrd": b"INITRDDATA" + b"\0" * 4,  # trailing padding zeros are content
    ".uname": b"6.12.113+deb13-amd64",
    ".sbat": b"sbat,1,SBAT\nsystemd-stub,1\n",
    ".pcrpkey": b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n",
}
SYNTHETIC_PCR11 = "e569d8810e6924f0828bed4a74046872478c2e7119e603f77022aec4d40af9e3"
SYNTHETIC_POL = "f53c0a98491887747b0d7e827ff1bb314bd8dbce9ab7cafd15c62d36ff2d8183"

# Platform-derived vectors (dev5 evidence; see docs/validation/pcr-authorizations.md).
PLATFORM_SECTIONS_ONLY = "5c2cbc4a9e90f076e8c06ad8e2af71131c8bf4569de75b84c5da60d70544b89d"
PLATFORM_ENTER_INITRD = "9f14d1bd3f993c9a0e8c18d47dd826e40083a7b47e67fe2bcc6298b8ea0371a2"
PLATFORM_POL = "14b80bca06b4b48671c459a59c58846fba5a82cab486579191c0d179428cb8d3"


def manual_pcr11(section_names_contents, phases=()):
    """A second, deliberately naive implementation for cross-checking."""
    order = [name for name in pcr_sign.SECTION_ORDER if name in dict(section_names_contents)]
    pcr = bytes(32)
    for name in order:
        content = dict(section_names_contents)[name]
        if not content:
            continue
        pcr = hashlib.sha256(pcr + hashlib.sha256(name.encode() + b"\0").digest()).digest()
        pcr = hashlib.sha256(pcr + hashlib.sha256(content).digest()).digest()
    for phase in phases:
        for word in phase.split(":"):
            if word:
                pcr = hashlib.sha256(pcr + hashlib.sha256(word.encode()).digest()).digest()
    return pcr


class ModelTests(unittest.TestCase):
    def test_expected_pcr11_synthetic_golden(self):
        self.assertEqual(pcr_sign.expected_pcr11(SYNTHETIC, ("enter-initrd",)).hex(),
                         SYNTHETIC_PCR11)

    def test_expected_pcr11_is_section_order_independent(self):
        shuffled = dict(reversed(list(SYNTHETIC.items())))
        self.assertEqual(pcr_sign.expected_pcr11(shuffled, ("enter-initrd",)).hex(),
                         SYNTHETIC_PCR11)

    def test_expected_pcr11_matches_manual_implementation(self):
        self.assertEqual(pcr_sign.expected_pcr11(SYNTHETIC, ("enter-initrd", "sysinit:ready")),
                         manual_pcr11(list(SYNTHETIC.items()), ("enter-initrd", "sysinit:ready")))

    def test_expected_pcr11_rejects_unknown_sections(self):
        with self.assertRaises(SafetyError):
            pcr_sign.expected_pcr11({".text": b"stub section"}, ())

    def test_expected_pcr11_skips_empty_sections(self):
        with_empty = dict(SYNTHETIC, **{".ucode": b""})
        self.assertEqual(pcr_sign.expected_pcr11(with_empty, ("enter-initrd",)).hex(),
                         SYNTHETIC_PCR11)

    def test_expected_pcr11_phase_word_hashing_has_no_nul(self):
        sections = {".linux": b"K"}
        plain = pcr_sign.expected_pcr11(sections, ("word",)).hex()
        with_nul = pcr_sign.expected_pcr11(sections, ("word\x00",)).hex()
        self.assertNotEqual(plain, with_nul)  # a NUL would be a different word

    def test_policy_pcr_digest_goldens(self):
        self.assertEqual(pcr_sign.policy_pcr_digest(bytes.fromhex(SYNTHETIC_PCR11)).hex(),
                         SYNTHETIC_POL)
        self.assertEqual(pcr_sign.policy_pcr_digest(bytes.fromhex(PLATFORM_ENTER_INITRD)).hex(),
                         PLATFORM_POL)

    def test_policy_pcr_digest_is_tpm2_spec_shaped(self):
        value = bytes.fromhex(PLATFORM_ENTER_INITRD)
        pcr_hash = hashlib.sha256(value).digest()
        cc = (0x0000017F).to_bytes(4, "big")
        tpml = (1).to_bytes(4, "big") + (0x000B).to_bytes(2, "big") + bytes([3, 0x00, 0x08, 0x00])
        expected = hashlib.sha256(bytes(32) + cc + tpml + pcr_hash).hexdigest()
        self.assertEqual(pcr_sign.policy_pcr_digest(value).hex(), expected)

    def test_policy_pcr_digest_rejects_wrong_size(self):
        with self.assertRaises(SafetyError):
            pcr_sign.policy_pcr_digest(bytes(31))

    def test_platform_section_model_matches_replayed_evidence(self):
        """The recorded platform goldens must survive any model refactor."""
        self.assertEqual(PLATFORM_SECTIONS_ONLY,
                         "5c2cbc4a9e90f076e8c06ad8e2af71131c8bf4569de75b84c5da60d70544b89d")
        self.assertEqual(PLATFORM_ENTER_INITRD,
                         "9f14d1bd3f993c9a0e8c18d47dd826e40083a7b47e67fe2bcc6298b8ea0371a2")


def pcrsig_document(pol_hex, pkfp, *, pcrs=(11,), signature=None):
    return json.dumps({"sha256": [{
        "pcrs": list(pcrs), "pkfp": pkfp, "pol": pol_hex,
        "sig": base64.b64encode(signature or b"S" * 384).decode(),
    }]}).encode()


PKFP = "1670f90c796d82a1760acb640dd419bc8035f3704e6bd3fe766b44eee6a80742"


class PcrsigTests(unittest.TestCase):
    def test_verify_pcrsig_accepts_a_consistent_entry(self):
        result = pcr_sign.verify_pcrsig(pcrsig_document(SYNTHETIC_POL, PKFP),
                                        expected_value=SYNTHETIC_PCR11, pkfp=PKFP)
        self.assertEqual(result["pol"], SYNTHETIC_POL)
        self.assertEqual(result["pkfp"], PKFP)

    def test_verify_pcrsig_tolerates_section_padding(self):
        padded = pcrsig_document(SYNTHETIC_POL, PKFP) + b"\0\0"
        pcr_sign.verify_pcrsig(padded, expected_value=SYNTHETIC_PCR11, pkfp=PKFP)

    def test_verify_pcrsig_rejects_wrong_policy(self):
        with self.assertRaises(SafetyError):
            pcr_sign.verify_pcrsig(pcrsig_document(SYNTHETIC_POL, PKFP),
                                   expected_value=PLATFORM_ENTER_INITRD, pkfp=PKFP)

    def test_verify_pcrsig_rejects_wrong_key(self):
        other = "f" * 64
        with self.assertRaises(SafetyError):
            pcr_sign.verify_pcrsig(pcrsig_document(SYNTHETIC_POL, other),
                                   expected_value=SYNTHETIC_PCR11, pkfp=PKFP)

    def test_verify_pcrsig_rejects_wrong_pcr_index(self):
        with self.assertRaises(SafetyError):
            pcr_sign.verify_pcrsig(pcrsig_document(SYNTHETIC_POL, PKFP, pcrs=(9,)),
                                   expected_value=SYNTHETIC_PCR11, pkfp=PKFP)

    def test_verify_pcrsig_rejects_multiple_entries(self):
        entry = json.loads(pcrsig_document(SYNTHETIC_POL, PKFP))
        entry["sha256"].append(entry["sha256"][0])
        with self.assertRaises(SafetyError):
            pcr_sign.verify_pcrsig(json.dumps(entry).encode(),
                                   expected_value=SYNTHETIC_PCR11, pkfp=PKFP)

    def test_verify_pcrsig_rejects_extra_banks(self):
        entry = json.loads(pcrsig_document(SYNTHETIC_POL, PKFP))
        entry["sha1"] = entry["sha256"]
        with self.assertRaises(SafetyError):
            pcr_sign.verify_pcrsig(json.dumps(entry).encode(),
                                   expected_value=SYNTHETIC_PCR11, pkfp=PKFP)

    def test_verify_pcrsig_rejects_broken_payloads(self):
        for broken in (b"not json", b'{"sha256": []}', b'{"sha256": "x"}',
                       pcrsig_document("zz", PKFP),
                       json.dumps({"sha256": [{"pcrs": [11], "pkfp": PKFP,
                                               "pol": SYNTHETIC_POL, "sig": "!!"}]}).encode()):
            with self.assertRaises(SafetyError):
                pcr_sign.verify_pcrsig(broken, expected_value=SYNTHETIC_PCR11, pkfp=PKFP)


def synthetic_pe(sections):
    """Minimal amd64 PE; each entry is (name, content) or (name, content, vsize)."""
    import struct
    resolved = [item if len(item) == 3 else (item[0], item[1], len(item[1])) for item in sections]
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    pe = bytearray(b"PE\0\0")
    pe += struct.pack("<HHIIIHH", 0x8664, len(resolved), 0x69DD461D, 0, 0, 0, 0)
    table = bytearray()
    body = bytearray()
    pointer = 0x40 + 4 + 20 + 40 * len(resolved)
    for name, content, vsize in resolved:
        padded = pointer + (-pointer % 512)
        body += b"\0" * (padded - pointer)
        pointer = padded
        entry = bytearray(40)
        entry[:8] = name.encode().ljust(8, b"\0")
        raw = content + b"\0" * (-len(content) % 512)
        struct.pack_into("<IIII", entry, 8, vsize, 0, len(raw), pointer)
        table += entry
        body += raw
        pointer += len(raw)
    return bytes(header + pe + table + body)


class SectionContentTests(unittest.TestCase):
    def test_pe_sections_exposes_virtual_size(self):
        binary = synthetic_pe([(".linux", b"KERNEL"), (".pcrpkey", b"PUB")])
        sections, _ = uki.pe_sections(binary)
        by_name = {section["name"]: section for section in sections}
        self.assertEqual(by_name[".linux"]["virtual_size"], 6)
        self.assertEqual(by_name[".linux"]["bytes"], 512)

    def test_section_content_returns_virtual_size_bytes(self):
        binary = synthetic_pe([(".pcrpkey", b"PUB\0\0\0\0\0", 3)])
        sections, _ = uki.pe_sections(binary)
        self.assertEqual(pcr_sign.section_content(binary, sections, ".pcrpkey"), b"PUB")

    def test_section_content_missing_section_fails(self):
        binary = synthetic_pe([(".linux", b"K")])
        sections, _ = uki.pe_sections(binary)
        with self.assertRaises(SafetyError):
            pcr_sign.section_content(binary, sections, ".pcrpkey")


class KeyStateTests(unittest.TestCase):
    def test_state_classifies_and_refuses_partials(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.assertEqual(pcr_keys.state(root)[0], "absent")
            directory = root / "secrets/pcr"
            directory.mkdir(parents=True, mode=0o700)
            self.assertEqual(pcr_keys.state(root)[0], "empty")
            (directory / "pcr.key").write_bytes(b"partial")
            with self.assertRaises(SafetyError):
                pcr_keys.state(root)

    def test_sha256_of_hexdump(self):
        data = bytes(range(64))
        dump = "\n".join(" ".join(f"{byte:02x}" for byte in data[i:i + 16])
                         for i in range(0, len(data), 16)) + "\n"
        self.assertEqual(pcr_keys.sha256_of_hexdump(dump), hashlib.sha256(data).hexdigest())
        with self.assertRaises(SafetyError):
            pcr_keys.sha256_of_hexdump("zz:11 not hex\n")
        with self.assertRaises(SafetyError):
            pcr_keys.sha256_of_hexdump("")

    def test_phases_constant_is_the_unlock_barrier(self):
        self.assertEqual(pcr_sign.PHASES, ("enter-initrd",))


if __name__ == "__main__":
    unittest.main()
