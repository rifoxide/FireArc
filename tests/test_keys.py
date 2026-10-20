"""Offline tests for the development key hierarchy generation."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import keys
from firearc.integrity import SafetyError, write_json

from support import temporary


class FakeRunner:
    """Records every logged command and materializes its planned outputs."""

    def __init__(self, root):
        self.root = Path(root)
        self.commands = []
        self.fingerprints = {
            "sha256 Fingerprint=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99": None,
        }

    def __call__(self, work, name, command, *, env=None, timeout=300):
        self.commands.append((name, command))
        if name.startswith("describe-"):
            role = name.removeprefix("describe-")
            return (f"subject={keys.SUBJECTS[role]}\nserial=1\n"
                    "notAfter=Jan  1 00:00:00 2036 GMT\n"
                    "sha256 Fingerprint=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
                    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\n")
        if name == "tool-versions":
            return "OpenSSL 3.5.7\nsbsign 0.9.4\nsbvarsign 0.9.4\n"
        for step_name, step_command, outputs in keys.build_plan():
            if step_name == name:
                for output in outputs:
                    (self.root / "secrets" / output).write_bytes(b"fixture")
                return ""
        return ""


class KeyHierarchyTests(unittest.TestCase):
    def test_plan_shapes_the_full_uefi_chain(self):
        plan = keys.build_plan()
        names = [name for name, _, _ in plan]
        self.assertEqual(names, ["generate-pk", "generate-kek", "generate-sb",
                                 "siglist-pk", "siglist-kek", "siglist-db",
                                 "varsign-pk", "varsign-kek", "varsign-db"])
        joined = {name: " ".join(command) for name, command, _ in plan}
        self.assertIn("-subj /CN=FireArc Development Platform Key/", joined["generate-pk"])
        self.assertIn("-newkey rsa:3072", joined["generate-pk"])
        self.assertIn("extendedKeyUsage=codeSigning", joined["generate-sb"])
        self.assertNotIn("extendedKeyUsage=codeSigning", joined["generate-pk"])
        # db carries the image-signing certificate; not a db key/cert of its own.
        self.assertIn("/keys/sb.crt", joined["siglist-db"])
        self.assertNotIn("db.key", " ".join(argument for _, command, _ in plan for argument in command))
        # Auth chain: PK self-enrolls, KEK is authorized by PK, db by KEK.
        self.assertIn("--key /keys/pk.key --cert /keys/pk.crt", joined["varsign-pk"])
        self.assertIn("--key /keys/pk.key --cert /keys/pk.crt", joined["varsign-kek"])
        self.assertIn("--key /keys/kek.key --cert /keys/kek.crt", joined["varsign-db"])
        self.assertIn("TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                      joined["varsign-db"])
        self.assertIn(keys.OWNER_GUID, joined["siglist-pk"])
        for name, _, outputs in plan:
            for output in outputs:
                self.assertTrue(output in keys.ALL_OUTPUTS, output)

    def test_generation_writes_hierarchy_and_manifest_once(self):
        with temporary() as root:
            runner = FakeRunner(root)
            (root / "deps" / "tools-aaaaaaaaaaaa").mkdir(parents=True)
            write_json(root / "deps" / "tools-aaaaaaaaaaaa" / "export-result.json",
                       {"image_id": "sha256:" + "a" * 64})
            (root / "build").mkdir(mode=0o700)
            with patch.object(keys.builder, "verify_tools"), \
                 patch.object(keys.builder, "logged", side_effect=runner), \
                 patch.object(keys.builder, "parent", return_value=root / "deps"):
                first = keys.ensure(root, "tools-aaaaaaaaaaaa")
            self.assertFalse(first["already_present"])
            for name in keys.KEY_FILES + keys.CERT_FILES + keys.ESL_FILES + keys.AUTH_FILES:
                self.assertTrue((root / "secrets" / name).is_file(), name)
            manifest_path = root / "secrets" / "manifest.json"
            self.assertTrue(manifest_path.is_file())
            self.assertIn("certificates", manifest_path.read_text())
            # A complete hierarchy is reported, never regenerated.
            again = keys.ensure(root, "tools-aaaaaaaaaaaa")
            self.assertTrue(again["already_present"])

    def test_partial_hierarchy_fails_closed(self):
        with temporary() as root:
            (root / "secrets").mkdir(mode=0o700)
            (root / "secrets" / "pk.key").write_bytes(b"half")
            with self.assertRaises(SafetyError):
                keys.state(root)
            # An empty secrets tree is treated as fresh, not partial.
            (root / "secrets" / "pk.key").unlink()
            self.assertEqual(keys.state(root)[0], "empty")

    def test_failed_generation_leaves_no_partial_hierarchy(self):
        with temporary() as root:
            (root / "deps" / "tools-aaaaaaaaaaaa").mkdir(parents=True)
            write_json(root / "deps" / "tools-aaaaaaaaaaaa" / "export-result.json",
                       {"image_id": "sha256:" + "a" * 64})
            (root / "build").mkdir(mode=0o700)

            def failing(work, name, command, *, env=None, timeout=300):
                if name == "generate-kek":
                    raise SafetyError("boom")
                for step_name, _, outputs in keys.build_plan():
                    if step_name == name:
                        for output in outputs:
                            (root / "secrets").mkdir(mode=0o700, exist_ok=True)
                            (root / "secrets" / output).write_bytes(b"fixture")
                return ""

            with patch.object(keys.builder, "verify_tools"), \
                 patch.object(keys.builder, "logged", side_effect=failing), \
                 patch.object(keys.builder, "parent", return_value=root / "deps"):
                with self.assertRaises(SafetyError):
                    keys.ensure(root, "tools-aaaaaaaaaaaa")
            self.assertFalse((root / "secrets").exists())


if __name__ == "__main__":
    unittest.main()
