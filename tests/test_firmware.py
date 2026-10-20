"""Offline firmware source-acquisition tests using synthetic local Git repos."""

from pathlib import Path
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import firmware
from firearc.integrity import SafetyError, read_json, write_json
from support import temporary

IDENTITY = ["-c", "user.name=FireArc test", "-c", "user.email=test@invalid",
            "-c", "commit.gpgsign=false"]


def repository(path, *files):
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", "-b", "main"], cwd=path, check=True)
    for name, text in files:
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(["git", *IDENTITY, "add", "--all"], cwd=path, check=True)
    subprocess.run(["git", *IDENTITY, "commit", "--quiet", "-m", "fixture"], cwd=path, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=True).stdout.strip()


def parent_repository(path, links):
    """A top-level repository whose tree records gitlinks as (path, commit)."""
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", "-b", "main"], cwd=path, check=True)
    (path / "Makefile").write_text("parent\n")
    subprocess.run(["git", *IDENTITY, "add", "--all"], cwd=path, check=True)
    for name, commit in links:
        subprocess.run(["git", *IDENTITY, "update-index", "--add", "--cacheinfo",
                        f"160000,{commit},{name}"], cwd=path, check=True)
    subprocess.run(["git", *IDENTITY, "commit", "--quiet", "-m", "fixture"], cwd=path, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=True).stdout.strip()


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(os.environ["HOME"])
        subprocess.run(["git", "config", "--global", "--get", "protocol.file.allow"],
                       capture_output=True)
        # Permit file:// transports only inside this test process environment.
        os.environ["GIT_CONFIG_COUNT"] = "1"
        os.environ["GIT_CONFIG_KEY_0"] = "protocol.file.allow"
        os.environ["GIT_CONFIG_VALUE_0"] = "always"
        self.addCleanup(os.environ.update, {"GIT_CONFIG_COUNT": "0"})

    def universe(self, upstream):
        """Synthetic coreboot/edk2 parents with three pinned and one declined submodule."""
        vboot = repository(upstream / "vboot", ("vboot.py", "vboot\n"))
        brotli = repository(upstream / "brotli", ("brotli.c", "brotli\n"))
        openssl = repository(upstream / "openssl", ("openssl.c", "openssl\n"))
        coreboot = parent_repository(upstream / "coreboot", [
            ("3rdparty/vboot", vboot),
            ("3rdparty/declined", openssl)])
        edk2 = parent_repository(upstream / "edk2", [
            ("CryptoPkg/Library/OpensslLib/openssl", openssl),
            ("BaseTools/Source/C/BrotliCompress/brotli", brotli),
            ("MdeModulePkg/Library/BrotliCustomDecompressLib/brotli", brotli)])
        return {
            "sources": [
                {"name": "coreboot", "repository": f"file://{upstream / 'coreboot'}", "commit": coreboot},
                {"name": "edk2", "repository": f"file://{upstream / 'edk2'}", "commit": edk2},
                {"name": "vboot", "repository": f"file://{upstream / 'vboot'}", "commit": vboot,
                 "destinations": [{"repository": "coreboot", "path": "3rdparty/vboot"}]},
                {"name": "brotli", "repository": f"file://{upstream / 'brotli'}", "commit": brotli,
                 "destinations": [{"repository": "edk2", "path": "BaseTools/Source/C/BrotliCompress/brotli"},
                                  {"repository": "edk2", "path": "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli"}]},
                {"name": "openssl", "repository": f"file://{upstream / 'openssl'}", "commit": openssl,
                 "destinations": [{"repository": "edk2", "path": "CryptoPkg/Library/OpensslLib/openssl"}]},
            ],
            "gitlink_census": {
                "coreboot": {"3rdparty/vboot": vboot, "3rdparty/declined": openssl},
                "edk2": {"CryptoPkg/Library/OpensslLib/openssl": openssl,
                         "BaseTools/Source/C/BrotliCompress/brotli": brotli,
                         "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli": brotli},
            },
        }

    def test_fetch_materializes_listed_submodules_and_verify_rechecks_them(self):
        with temporary() as root, temporary() as upstream:
            pins = self.universe(upstream)
            with patch.object(firmware, "load_lock", return_value=pins):
                result = firmware.fetch(root, "fw-a", allow_network=True)
                self.assertTrue(result["passed"])
                self.assertEqual(result["sources"], 5)
                self.assertEqual(result["submodules"], 4)
                base = root / "build/firmware/fw-a/sources"
                self.assertTrue((base / "coreboot/3rdparty/vboot/vboot.py").is_file())
                self.assertTrue((base / "edk2/BaseTools/Source/C/BrotliCompress/brotli/brotli.c").is_file())
                self.assertTrue((base / "edk2/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli/brotli.c").is_file())
                self.assertTrue((base / "edk2/CryptoPkg/Library/OpensslLib/openssl/openssl.c").is_file())
                # The census-listed gitlink without a destination stays unmaterialized.
                declined = base / "coreboot/3rdparty/declined"
                self.assertTrue(declined.is_dir())
                self.assertEqual(list(declined.iterdir()), [])
                records = firmware.verify(root, "fw-a")
                self.assertTrue(records["submodules_fetched"])
                self.assertEqual(records["materialized"], [
                    "coreboot:3rdparty/vboot",
                    "edk2:BaseTools/Source/C/BrotliCompress/brotli",
                    "edk2:CryptoPkg/Library/OpensslLib/openssl",
                    "edk2:MdeModulePkg/Library/BrotliCustomDecompressLib/brotli"])
                self.assertEqual(records["gitlink_census"], pins["gitlink_census"])
                receipt = read_json(root / "build/firmware/fw-a/result.json")
                self.assertTrue(receipt["passed"])
                self.assertEqual(receipt["submodules"], 4)

    def test_fetch_refuses_offline_and_rejects_drifted_or_dirty_trees(self):
        with temporary() as root, temporary() as upstream:
            pins = self.universe(upstream)
            with patch.object(firmware, "load_lock", return_value=pins):
                with self.assertRaises(SafetyError):
                    firmware.fetch(root, "fw-b", allow_network=False)
                firmware.fetch(root, "fw-c", allow_network=True)
                # A later local modification of a parent invalidates the acquisition.
                (root / "build/firmware/fw-c/sources/edk2/Makefile").write_text("tampered\n")
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-c")
            # A submodule checkout modified after acquisition is equally fatal.
            with patch.object(firmware, "load_lock", return_value=pins):
                firmware.fetch(root, "fw-d", allow_network=True)
                submodule = root / "build/firmware/fw-d/sources/coreboot/3rdparty/vboot/vboot.py"
                submodule.write_text("tampered\n")
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-d")

    def test_verify_refuses_pre_closure_records_pin_and_census_drift(self):
        with temporary() as root, temporary() as upstream:
            pins = self.universe(upstream)
            with patch.object(firmware, "load_lock", return_value=pins):
                firmware.fetch(root, "fw-e", allow_network=True)
                record = read_json(root / "build/firmware/fw-e/output/sources.json")
                record["submodules_fetched"] = False
                (root / "build/firmware/fw-e/output/sources.json").unlink()
                write_json(root / "build/firmware/fw-e/output/sources.json", record)
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-e")
            drifted = json.loads(json.dumps(pins))
            drifted["sources"][0]["commit"] = "f" * 40
            with patch.object(firmware, "load_lock", return_value=drifted):
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-e")
            censored = json.loads(json.dumps(pins))
            del censored["gitlink_census"]["coreboot"]["3rdparty/declined"]
            for index, broken in enumerate([censored, drifted]):
                with patch.object(firmware, "load_lock", return_value=broken):
                    with self.assertRaises(SafetyError):
                        firmware.fetch(root, f"fw-f{index}", allow_network=True)

    def test_unexpected_materialization_is_refused(self):
        with temporary() as root, temporary() as upstream:
            pins = self.universe(upstream)
            with patch.object(firmware, "load_lock", return_value=pins):
                firmware.fetch(root, "fw-g", allow_network=True)
                declined = root / "build/firmware/fw-g/sources/coreboot/3rdparty/declined"
                self.assertEqual(list(declined.iterdir()), [])
                subprocess.run(["git", "clone", "--quiet", f"file://{upstream / 'vboot'}", str(declined)],
                               check=True)
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-g")

    def test_unexpected_pin_shapes_are_refused(self):
        with temporary() as root, temporary() as upstream:
            pins = self.universe(upstream)
            cases = []
            for name in ["../escape", "Upper", "sp ace"]:
                broken = json.loads(json.dumps(pins))
                broken["sources"][2]["name"] = name
                cases.append(broken)
            for path in ["../escape", "/absolute", "a/.git/b", "", "a//b"]:
                broken = json.loads(json.dumps(pins))
                broken["sources"][2]["destinations"][0]["path"] = path
                cases.append(broken)
            broken = json.loads(json.dumps(pins))
            broken["sources"][2]["destinations"][0]["repository"] = "vboot"
            cases.append(broken)
            broken = json.loads(json.dumps(pins))
            broken["sources"][3]["destinations"][1]["path"] = \
                broken["sources"][3]["destinations"][0]["path"]
            cases.append(broken)
            broken = json.loads(json.dumps(pins))
            broken["sources"][2]["commit"] = "0" * 40
            cases.append(broken)
            broken = json.loads(json.dumps(pins))
            del broken["gitlink_census"]["edk2"]
            cases.append(broken)
            for index, broken in enumerate(cases):
                with self.subTest(case=index), patch.object(firmware, "load_lock", return_value=broken):
                    with self.assertRaises(SafetyError):
                        firmware.fetch(root, f"fw-h{index}", allow_network=True)


if __name__ == "__main__":
    unittest.main()
