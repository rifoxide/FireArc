"""Offline tests for frozen root payload authority and assembly boundaries."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import rootfs
from firearc.integrity import SafetyError
from firearc.integrity import write_json
from support import temporary


class RootPayloadTests(unittest.TestCase):
    def authority(self):
        return {"schema": 1, "format": 1, "algorithm": "sha256", "data_bytes": rootfs.ROOT_BYTES,
                "hash_bytes": rootfs.HASH_BYTES, "data_blocks": rootfs.ROOT_BYTES // rootfs.BLOCK_SIZE,
                "data_block_size": 4096, "hash_block_size": 4096, "hash_offset": 0, "salt": "a" * 64}

    def test_authority_pins_full_partition_range_and_has_no_mutable_header(self):
        arguments = rootfs.verity_args(self.authority())
        self.assertIn("--no-superblock", arguments)
        self.assertIn("--data-blocks=1048576", arguments)
        self.assertIn("--hash=sha256", arguments)
        self.assertIn("--hash-offset=0", arguments)
        self.assertNotIn("--ignore-corruption", arguments)

    def test_truncated_range_wrong_geometry_salt_and_format_are_rejected(self):
        for key, value in [("data_blocks", 1), ("data_bytes", 4096), ("hash_bytes", 4096),
                           ("data_block_size", 512), ("hash_block_size", 512), ("hash_offset", 4096),
                           ("algorithm", "sha1"), ("salt", "a" * 63), ("salt", "z" * 64),
                           ("root_hash", "bad"), ("salt", None), ("root_hash", 123),
                           ("format", True), ("format", 0), ("schema", 2)]:
            with self.subTest(key=key, value=value), self.assertRaises(SafetyError):
                rootfs.verity_args({**self.authority(), key: value})

    def test_exactly_one_explicit_root_hash_is_required(self):
        digest = "b" * 64
        self.assertEqual(rootfs.parse_root_hash("Root hash: " + digest + "\n"), digest)
        for text in ["", digest, "Root hash: " + "g" * 64,
                     "Root hash: " + digest + "\nRoot hash: " + digest + "\n"]:
            with self.subTest(text=text), self.assertRaises(SafetyError):
                rootfs.parse_root_hash(text)

    def test_rootfs_recipe_is_offline_and_not_installed_ab_layout(self):
        recipe = (ROOT / "images/rootfs/mkosi.conf").read_text()
        self.assertIn("RepartOffline=yes", recipe)
        self.assertIn("WithNetwork=no", recipe)
        self.assertIn("Bootable=no", recipe)
        self.assertNotIn("Packages=", recipe)
        partition = (ROOT / "images/rootfs/repart.d/10-root.conf").read_text()
        self.assertIn("SizeMinBytes=4G", partition)
        self.assertIn("SizeMaxBytes=4G", partition)
        self.assertNotIn("Type=esp", partition)

    def test_corruption_is_bounded_and_changes_only_one_copied_byte(self):
        with temporary() as root:
            file = root / "copy.raw"
            file.write_bytes(b"a" * 16)
            rootfs.flip_byte(file, 15)
            self.assertEqual(file.read_bytes(), b"a" * 15 + b"`")
            for offset in [-1, 16]:
                with self.subTest(offset=offset), self.assertRaises(SafetyError):
                    rootfs.flip_byte(file, offset)

    def test_negative_control_requires_integrity_error_not_any_command_failure(self):
        for status, stderr, accepted in [(2, "Verification failed at position 0.", True),
                                         (1, "Verification of root hash failed.", True),
                                         (2, "Permission denied", False), (1, "Verification failed", False)]:
            with self.subTest(status=status, stderr=stderr), temporary() as root:
                write_json(root / "denial.exit.json", {"returncode": status})
                (root / "denial.stderr").write_text(stderr)
                with patch.object(rootfs.builder, "logged", side_effect=SafetyError("command failed")):
                    if accepted:
                        rootfs.expect_integrity_denial(root, "denial", ["synthetic"])
                    else:
                        with self.assertRaises(SafetyError):
                            rootfs.expect_integrity_denial(root, "denial", ["synthetic"])

    def test_negative_control_refuses_unexpected_success(self):
        with temporary() as root, patch.object(rootfs.builder, "logged", return_value=""), self.assertRaises(SafetyError):
            rootfs.expect_integrity_denial(root, "unexpected-success", ["synthetic"])


if __name__ == "__main__":
    unittest.main()
