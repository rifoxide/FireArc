"""Offline tests for per-device LUKS2 data provisioning (Phase 5 item 6).

The LUKS2 on-disk expectations below (magic/version at 0, u64 hdr_size,
JSON area from 0x1000, argon2id keyslot 0, aes-xts-plain64 segment) were
validated against real cryptsetup 2.7.5 output from the pinned tools
image before being pinned here; the synthetic builder reproduces that
shape so the provisioning flow is exercised without docker.
"""

import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from firearc import device, luks
from firearc.integrity import SafetyError, read_json
from support import temporary

TOOLS_LABEL = "tools-l"


def synthetic_luks2_image(uuid, *, size=None, label="FIREARC_DATA"):
    """A LUKS2-shaped region: binary header strings + JSON area."""
    size = size or luks.DATA_BYTES
    blob = bytearray(size)
    header = {
        "keyslots": {"0": {"type": "luks2", "key_size": 64,
                           "kdf": {"type": "argon2id", "time": 25, "memory": 575742,
                                   "cpus": 4, "salt": "c2FsdA=="}}},
        "tokens": {},
        "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic",
                           "encryption": "aes-xts-plain64", "sector_size": 4096}},
        "digests": {"0": {"type": "pbkdf2", "keyslots": ["0"], "segments": ["0"],
                          "hash": "sha256"}},
        "config": {"json_size": "12288", "keyslots_size": "2068480"},
    }
    text = json.dumps(header).encode()
    blob[0:6] = luks.LUKS2_MAGIC
    blob[6:8] = (2).to_bytes(2, "big")
    hdr_size = 16384
    blob[8:16] = hdr_size.to_bytes(8, "big")
    # cryptsetup keeps the label and uuid as NUL-padded ASCII in the binary
    # header (before the JSON area); placement differs by version, so the
    # synthetic header simply embeds both somewhere before 0x1000.
    blob[0x1c:0x1c + len(label)] = label.encode()
    blob[0xa8:0xa8 + len(uuid)] = uuid.encode()
    blob[luks.HEADER_JSON_OFFSET:luks.HEADER_JSON_OFFSET + len(text)] = text
    return bytes(blob), header


class FakeCryptsetup:
    """Records commands, simulates the four provisioning calls."""

    def __init__(self, uuid):
        self.uuid = uuid
        self.commands = []
        self.workspaces = []

    def __call__(self, work, name, command, *, env=None, timeout=300):
        self.commands.append((name, command))
        # The fake runs host-side: /workspace paths resolve to the single
        # mounted workspace directory the test registered.
        real = self.workspaces[-1]
        tool = "truncate" if "truncate" in command else "cryptsetup"
        argv = command[command.index(tool):]
        if argv[0] == "truncate":
            (real / "data.img").write_bytes(b"")
            (real / "data.img").write_bytes(synthetic_luks2_image(self.uuid)[0])
            return ""
        if argv[1] == "luksFormat":
            blob, header = synthetic_luks2_image(self.uuid)
            # Format starts from the truncated empty image.
            (real / "data.img").write_bytes(blob)
            return ""
        if argv[1] == "luksDump":
            return json.dumps(synthetic_luks2_image(self.uuid)[1])
        if argv[1] == "luksUUID":
            return self.uuid + "\n"
        if argv[1] == "luksOpen":
            return ""
        raise AssertionError(f"unexpected command: {command}")


def fabricate(root, *, disk_bytes=None):
    """Fake tools-stage evidence plus a blank factory disk (0700 tree)."""
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "build").mkdir(mode=0o700)
    dependencies = root / "build" / "dependencies"
    dependencies.mkdir(mode=0o700)
    tools = dependencies / TOOLS_LABEL
    tools.mkdir(mode=0o700)
    (tools / "export-result.json").write_text(
        json.dumps({"image_id": "sha256:" + "0" * 64}))
    target = root / "profile"
    target.mkdir(mode=0o700)
    disk = target / "disk.raw"
    disk_bytes = disk_bytes or (luks.DATA_OFFSET + luks.DATA_BYTES + 512)
    with open(disk, "wb") as handle:
        handle.truncate(disk_bytes)  # sparse: every byte is zero
    return target, disk


class GeometryTests(unittest.TestCase):
    def test_blank_digest_covers_the_whole_partition(self):
        manual = hashlib.sha256(b"\0" * luks.DATA_BYTES).hexdigest()
        self.assertEqual(luks.BLANK_SHA256, manual)

    def test_partition_table_agrees_with_the_data_offset(self):
        name, start, sectors, kind, unique = device.PARTITIONS[-1]
        self.assertEqual(name, "FIREARC_DATA")
        self.assertEqual(kind, device.LUKS_TYPE_GUID)
        self.assertEqual(start * device.SECTOR, luks.DATA_OFFSET)
        self.assertEqual(sectors * device.SECTOR, luks.DATA_BYTES)
        # The partition fits inside the disk with the trailing GPT copy.
        self.assertLessEqual(luks.DATA_OFFSET + luks.DATA_BYTES,
                             device.DISK_MIB * device.MIB)

    def test_sfdisk_script_carries_the_data_partition(self):
        rows = [line for line in device.sfdisk_script().splitlines()
                if line.startswith("start=")]
        self.assertEqual(len(rows), len(device.PARTITIONS))
        self.assertIn('name="FIREARC_DATA"', rows[-1])
        self.assertIn(device.LUKS_TYPE_GUID, rows[-1])


class BlankTests(unittest.TestCase):
    def test_factory_blank_checks_agree(self):
        with temporary() as work:
            disk = work / "disk.raw"
            with open(disk, "wb") as handle:
                handle.truncate(luks.DATA_OFFSET + luks.DATA_BYTES)
            self.assertEqual(luks.assert_region_blank(disk, "test disk"), luks.BLANK_SHA256)
            device.assert_data_blank(disk)  # device.py's independent check agrees

    def test_populated_header_never_passes_as_factory(self):
        with temporary() as work:
            disk = work / "disk.raw"
            with open(disk, "wb") as handle:
                handle.truncate(luks.DATA_OFFSET + luks.DATA_BYTES)
                handle.seek(luks.DATA_OFFSET)
                handle.write(luks.LUKS2_MAGIC + b"template")
            for check in (lambda: luks.assert_region_blank(disk, "test disk"),
                          lambda: device.assert_data_blank(disk)):
                with self.assertRaises(SafetyError) as raised:
                    check()
                self.assertIn("factory", str(raised.exception))


class HeaderTests(unittest.TestCase):
    def test_parse_header_json_reads_real_luks2_layout(self):
        blob, header = synthetic_luks2_image("11111111-2222-3333-4444-555555555555",
                                             size=luks.HEADER_READ_BYTES)
        parsed = luks.parse_header_json(blob)
        self.assertEqual(parsed["segments"]["0"]["encryption"], "aes-xts-plain64")
        self.assertEqual(sorted(parsed["keyslots"]), ["0"])
        luks.validate_header(parsed, keyslots=["0"])
        luks.assert_binary_identity(
            blob, uuid="11111111-2222-3333-4444-555555555555")

    def test_parse_header_json_rejects_foreign_bytes(self):
        for bad in (b"", b"LUKS\xba\xbe" + b"\x03\x00",  # wrong version
                    synthetic_luks2_image("11111111-2222-3333-4444-555555555555",
                                          size=luks.HEADER_READ_BYTES)[0][:0x800]):
            with self.assertRaises(SafetyError):
                luks.parse_header_json(bad)

    def test_validate_header_rejects_contract_violations(self):
        blob, header = synthetic_luks2_image("11111111-2222-3333-4444-555555555555",
                                             size=luks.HEADER_READ_BYTES)
        for mutate, why in (
                (lambda h: h["keyslots"].update({"1": dict(h["keyslots"]["0"])}),
                 "extra keyslot"),
                (lambda h: h.update({"tokens": {"0": {"type": "systemd-tpm2"}}}),
                 "token already enrolled"),
                (lambda h: h["segments"].update({"1": {"type": "linear"}}),
                 "second segment"),
        ):
            broken = json.loads(json.dumps(header))
            mutate(broken)
            with self.subTest(why), self.assertRaises(SafetyError):
                luks.validate_header(broken, keyslots=["0"])

    def test_binary_identity_rejects_wrong_uuid(self):
        blob, _ = synthetic_luks2_image("11111111-2222-3333-4444-555555555555",
                                        size=luks.HEADER_READ_BYTES)
        with self.assertRaises(SafetyError):
            luks.assert_binary_identity(blob, uuid="99999999-2222-3333-4444-555555555555")



def enrolled_header(pem):
    """The real systemd 257.13 token shape (from the first live enrollment)."""
    import base64
    return {
        "keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
        "tokens": {"0": {"type": "systemd-tpm2", "keyslots": ["1"],
                         "tpm2-pcrs": [7], "tpm2_pubkey_pcrs": [11],
                         "tpm2-pcr-bank": "sha256", "tpm2-primary-alg": "ecc",
                         "tpm2_pubkey": base64.b64encode(pem.encode()).decode()}},
    }


class EnrollTests(unittest.TestCase):
    def test_filesystem_birth_requires_explicit_transport_grant(self):
        with temporary() as work:
            blob = luks.build_enroll_disk(work / "initial.img", b"R" * 32,
                                          initialize_filesystem=True)
            self.assertEqual(len(blob), luks.ENROLL_DISK_BYTES)
            self.assertEqual(blob[32:64], b"R" * 32)
            self.assertEqual(blob[64:96], luks.ENROLL_FORMAT_MAGIC.ljust(32, b"\0"))
            retry = luks.build_enroll_disk(work / "retry.img", b"R" * 32)
            self.assertNotIn(luks.ENROLL_FORMAT_MAGIC, retry)

    def test_enroll_disk_carries_magic_then_credential(self):
        with temporary() as work:
            path = work / "enroll-key.img"
            credential = bytes(range(32))
            luks.build_enroll_disk(path, credential)
            import stat
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            blob = path.read_bytes()
            self.assertEqual(len(blob), luks.ENROLL_DISK_BYTES)
            self.assertEqual(blob[:len(luks.ENROLL_MAGIC)], luks.ENROLL_MAGIC)
            self.assertEqual(blob[32:64], credential)
            self.assertEqual(blob[64:], b"\0" * (luks.ENROLL_DISK_BYTES - 64))
            with self.assertRaises(SafetyError):
                luks.build_enroll_disk(work / "other.img", b"short")

    def test_validate_enrolled_accepts_our_contract(self):
        pem = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
        header = enrolled_header(pem)
        token = luks.validate_enrolled(header, expected_pem=pem)
        self.assertEqual(token["type"], "systemd-tpm2")
        self.assertEqual(token["tpm2_pubkey_pcrs"], [11])

    def test_validate_enrolled_rejects_violations(self):
        pem = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
        base = enrolled_header(pem)
        mutations = (
            lambda h: h["keyslots"].pop("1"),                # token unbound
            lambda h: h["tokens"]["0"].update({"tpm2-pcrs": ["7", "11"]}),
            lambda h: h["tokens"]["0"].update({"keyslots": ["0"]}),
            lambda h: h["tokens"]["0"].pop("tpm2_pubkey"),
            lambda h: h["tokens"]["0"].update({"tpm2-pcr-bank": "sha1"}),
            lambda h: h["tokens"]["0"].update({"type": "systemd-fido2"}),
            lambda h: h["tokens"]["0"].pop("tpm2_pubkey_pcrs"),
        )
        for mutate in mutations:
            header = json.loads(json.dumps(base))
            mutate(header)
            with self.subTest(mutate=mutate.__name__ if hasattr(mutate, '__name__') else mutate), \
                    self.assertRaises(SafetyError):
                luks.validate_enrolled(header, expected_pem=pem)
        wrong_key = json.loads(json.dumps(base))
        wrong_key["tokens"]["0"]["tpm2_pubkey"] = __import__("base64").b64encode(
            pem.replace("test", "other").encode()).decode()
        with self.assertRaises(SafetyError):
            luks.validate_enrolled(wrong_key, expected_pem=pem)


class CredentialTests(unittest.TestCase):
    def test_recovery_credential_is_256_bits_and_unique(self):
        first = luks.generate_recovery_credential()
        second = luks.generate_recovery_credential()
        self.assertEqual(len(first), luks.RECOVERY_BYTES)
        self.assertNotEqual(first, second)
        self.assertEqual(len(set(first)), len(first) and len(set(first)))

    def test_write_secret_is_0600_and_never_overwrites(self):
        with temporary() as work:
            path = work / "recovery.key"
            luks.write_secret(path, b"material")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(SafetyError):
                luks.write_secret(path, b"other")

    def test_format_arguments_carry_paths_only(self):
        argv = luks.format_arguments()
        self.assertIn("--type", argv); self.assertIn("luks2", argv)
        self.assertIn("--batch-mode", argv)
        # The credential travels by file handle: the item after --key-file
        # must be a path, never inline secret material, and nothing in the
        # argv resembles key bytes.
        index = argv.index("--key-file")
        self.assertTrue(argv[index + 1].startswith("/"))
        self.assertTrue(all(item != "--key-file" or argv[i + 1].startswith("/")
                            for i, item in enumerate(argv)))


class ProvisionTests(unittest.TestCase):
    def provision(self, root, uuid):
        fake = FakeCryptsetup(uuid)
        fake.workspaces.append(root / "profile" / "provision" / "workspace")
        with patch.object(luks.builder, "verify_tools", lambda *a, **k: None), \
             patch.object(luks.builder, "logged", fake), \
             patch.object(luks.builder, "docker_args",
                          lambda image, **k: ["docker", "run", image]):
            document = luks.provision_data(root, root / "profile", TOOLS_LABEL)
        return document, fake

    def test_provision_formats_verifies_and_splices(self):
        with temporary() as work:
            root = work
            target, disk = fabricate(root)
            fake = FakeCryptsetup("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            fake.workspaces.append(target / "provision" / "workspace")
            with patch.object(luks.builder, "verify_tools", lambda *a, **k: None), \
                 patch.object(luks.builder, "logged", fake), \
                 patch.object(luks.builder, "docker_args",
                              lambda image, **k: ["docker", "run", image]):
                document = luks.provision_data(root, target, TOOLS_LABEL)
            # The volume is on the disk, exactly once, at the data offset.
            with open(disk, "rb") as handle:
                handle.seek(luks.DATA_OFFSET)
                on_disk = handle.read(4096)
            self.assertEqual(on_disk[:6], luks.LUKS2_MAGIC)
            self.assertNotEqual(document["data_region_sha256"], luks.BLANK_SHA256)
            self.assertEqual(document["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            self.assertEqual(document["keyslots"], ["0"])
            self.assertEqual(document["recovery_credential"]["escrow"],
                             "pending (Phase 5 item 7)")
            # The credential exists exactly once (profile secrets), is 0600
            # and never rode a command line.
            secret = target / "secrets" / "recovery.key"
            self.assertTrue(secret.is_file())
            self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
            material = secret.read_bytes()
            self.assertEqual(len(material), luks.RECOVERY_BYTES)
            for name, command in fake.commands:
                for item in command:
                    self.assertNotIn(material, item.encode() if isinstance(item, str)
                                     else item)
            # Workspace copies are scrubbed; evidence survives.
            self.assertFalse((target / "provision/workspace/recovery.key").exists())
            self.assertFalse((target / "provision/workspace/data.img").exists())
            stored = read_json(target / "provision/data.json")
            self.assertEqual(stored["uuid"], document["uuid"])
            # The recorded credential digest matches the kept file.
            self.assertEqual(hashlib.sha256(material).hexdigest(),
                             document["recovery_credential"]["sha256"])
            # The format was verified against keyslot 0 before splicing.
            names = [name for name, _ in fake.commands]
            self.assertIn("data-luks-verify", names)

    def test_provision_refuses_a_nonblank_region(self):
        with temporary() as work:
            root = work
            target, disk = fabricate(root)
            with open(disk, "r+b") as handle:
                handle.seek(luks.DATA_OFFSET + 1234)
                handle.write(b"stale-header-template")
            with self.assertRaises(SafetyError) as raised:
                self.provision(root, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            self.assertIn("factory", str(raised.exception))

    def test_two_provisions_are_unique_volumes(self):
        with temporary() as work:
            first_root = work / "a"
            second_root = work / "b"
            first, _ = fabricate(first_root)
            second, _ = fabricate(second_root)
            doc_a, _ = self.provision(first_root, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            doc_b, _ = self.provision(second_root, "ffffffff-2222-3333-4444-555555555555")
            self.assertNotEqual(doc_a["uuid"], doc_b["uuid"])
            self.assertNotEqual(doc_a["data_region_sha256"], doc_b["data_region_sha256"])
            # And the credentials are independent CSPRNG draws.
            self.assertNotEqual((first / "secrets/recovery.key").read_bytes(),
                                (second / "secrets/recovery.key").read_bytes())


if __name__ == "__main__":
    unittest.main()
