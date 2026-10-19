"""Project structure, input integrity and credential screening."""

import ast
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import host, inputs
from firearc.integrity import SafetyError, parse_manifest, private_directory, public_name, regular_file, relative_name, sha256, verify_file, write_json
from support import temporary


class IntegrityTests(unittest.TestCase):
    def test_paths_must_be_canonical_and_confined(self):
        for name in ["", ".", "../file", "/etc/passwd", "a/../file", "a//file", "a\\file", "a\nfile"]:
            with self.subTest(name=name), self.assertRaises(SafetyError): relative_name(name)
        self.assertEqual(str(relative_name("public/file")), "public/file")

    def test_private_names_are_not_public_inputs(self):
        for name in ["secrets/file", "private/file", ".ssh/id", "key.key", "key.pfx", ".env"]:
            with self.subTest(name=name), self.assertRaises(SafetyError): public_name(name)

    def test_manifests_reject_duplicates_traversal_and_invalid_format(self):
        digest = "a" * 64
        self.assertEqual(parse_manifest(f"{digest}  file\n".encode()), {"file": digest})
        for data in [b"", f"{digest} file\n".encode(), f"{digest}  ../file\n".encode(), f"{digest}  file\n{digest}  file\n".encode()]:
            with self.subTest(data=data), self.assertRaises(SafetyError): parse_manifest(data)

    def test_pins_detect_mutation_and_require_sha256(self):
        with temporary() as root:
            file = root / "file"
            file.write_text("original")
            digest = sha256(file)
            verify_file(file, digest)
            file.write_text("changed")
            for value in [digest, "latest", None]:
                with self.subTest(value=value), self.assertRaises(SafetyError): verify_file(file, value)

    def test_regular_files_and_parent_directories_cannot_be_symlinks(self):
        with temporary() as root:
            (root / "real").mkdir()
            (root / "real/file").write_text("public")
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(SafetyError): regular_file(root, "link/file")

    def test_private_directory_and_exclusive_evidence(self):
        with temporary() as root:
            private_directory(root)
            file = root / "record.json"
            write_json(file, {"passed": True})
            with self.assertRaises(FileExistsError): write_json(file, {})
            root.chmod(0o755)
            with self.assertRaises(SafetyError): private_directory(root)

    def test_private_key_pattern_is_detected_across_chunks(self):
        with temporary() as root:
            file = root / "public.pem"
            file.write_bytes(b"x" * (1024 * 1024 - 8) + b"\n-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n")
            with self.assertRaises(SafetyError): sha256(file, scan_private=True)


class ProjectTests(unittest.TestCase):
    def test_specification_pin(self):
        self.assertEqual(inputs.validate_locks(ROOT)["pages"], 13)

    def test_python_source_syntax(self):
        for path in [*ROOT.glob("src/**/*.py"), *ROOT.glob("scripts/*.py"), *ROOT.glob("tests/*.py")]:
            ast.parse(path.read_text(), filename=str(path))

    def test_document_links_and_fences(self):
        for path in [ROOT / "README.md", ROOT / "PLAN.md", *ROOT.glob("docs/**/*.md")]:
            text = path.read_text()
            self.assertEqual(len(re.findall(r"^```", text, re.M)) % 2, 0, path)
            for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
                if "://" not in target:
                    self.assertTrue((path.parent / target).is_file(), (path, target))

    def test_screening_rejects_generated_trees_and_dangling_symlinks(self):
        with temporary() as root:
            for name in [b"build/cache/file\0", b"private/file\0"]:
                with patch.object(host.subprocess, "check_output", return_value=name), self.assertRaises(SafetyError): host.scan_repository(root)
            (root / "file").symlink_to(root / "absent")
            with patch.object(host.subprocess, "check_output", return_value=b"file\0"), self.assertRaises(SafetyError): host.scan_repository(root)

    def test_screening_skips_deleted_files_but_checks_new_content(self):
        with temporary() as root:
            (root / "new").write_text("public")
            with patch.object(host.subprocess, "check_output", return_value=b"absent\0new\0"):
                result = host.scan_repository(root)
                self.assertEqual(result["files_checked"], 1)
                self.assertEqual(result["files_absent"], 1)
            (root / "new").write_text("ghp_" + "a" * 36)
            with patch.object(host.subprocess, "check_output", return_value=b"new\0"), self.assertRaises(SafetyError): host.scan_repository(root)
