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


class FirmwareTests(unittest.TestCase):
    def pins(self, coreboot, edk2):
        return {"sources": [
            {"name": "coreboot", "repository": f"file://{coreboot[0]}", "commit": coreboot[1]},
            {"name": "edk2", "repository": f"file://{edk2[0]}", "commit": edk2[1]},
        ]}

    def setUp(self):
        self.home = Path(os.environ["HOME"])
        subprocess.run(["git", "config", "--global", "--get", "protocol.file.allow"],
                       capture_output=True)
        # Permit file:// transports only inside this test process environment.
        os.environ["GIT_CONFIG_COUNT"] = "1"
        os.environ["GIT_CONFIG_KEY_0"] = "protocol.file.allow"
        os.environ["GIT_CONFIG_VALUE_0"] = "always"
        self.addCleanup(os.environ.update, {"GIT_CONFIG_COUNT": "0"})

    def test_fetch_acquires_exact_commits_and_verify_rechecks_them(self):
        with temporary() as root, temporary() as upstream:
            coreboot = upstream / "coreboot"
            edk2 = upstream / "edk2"
            pins = self.pins((str(coreboot), repository(coreboot, ("Makefile", "coreboot\n"))),
                             (str(edk2), repository(edk2, ("edk2.path", "edk2\n"))))
            with patch.object(firmware, "load_lock", return_value=pins):
                result = firmware.fetch(root, "fw-a", allow_network=True)
                self.assertTrue(result["passed"])
                self.assertEqual(result["sources"], 2)
                records = firmware.verify(root, "fw-a")
                self.assertFalse(records["submodules_fetched"])
                for pin in pins["sources"]:
                    self.assertEqual(records["sources"][pin["name"]]["commit"], pin["commit"])
                    self.assertRegex(records["sources"][pin["name"]]["tree"], r"^[0-9a-f]{40}$")

    def test_fetch_refuses_offline_and_rejects_drifted_or_dirty_trees(self):
        with temporary() as root, temporary() as upstream:
            coreboot = upstream / "coreboot"
            commit = repository(coreboot, ("Makefile", "coreboot\n"))
            pins = self.pins((str(coreboot), commit), (str(upstream / "edk2"), "0" * 40))
            with patch.object(firmware, "load_lock", return_value=pins):
                with self.assertRaises(SafetyError):
                    firmware.fetch(root, "fw-b", allow_network=False)
                # The edk2 pin points at a nonexistent commit: acquisition must fail.
                with self.assertRaises(SafetyError):
                    firmware.fetch(root, "fw-b", allow_network=True)
                self.assertFalse((root / "build/firmware/fw-b/result.json").exists())
                working_pins = self.pins((str(coreboot), commit), (str(coreboot), commit))
                with patch.object(firmware, "load_lock", return_value=working_pins):
                    firmware.fetch(root, "fw-c", allow_network=True)
                # A later local modification invalidates the acquisition.
                (root / "build/firmware/fw-c/sources/edk2/Makefile").write_text("tampered\n")
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-c")

    def test_verify_refuses_submodule_state_and_pin_drift(self):
        with temporary() as root, temporary() as upstream:
            coreboot = upstream / "coreboot"
            commit = repository(coreboot, ("Makefile", "coreboot\n"))
            pins = self.pins((str(coreboot), commit), (str(coreboot), commit))
            with patch.object(firmware, "load_lock", return_value=pins):
                firmware.fetch(root, "fw-d", allow_network=True)
                record = read_json(root / "build/firmware/fw-d/output/sources.json")
                record["submodules_fetched"] = True
                (root / "build/firmware/fw-d/output/sources.json").unlink()
                write_json(root / "build/firmware/fw-d/output/sources.json", record)
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-d")
            drifted = self.pins((str(coreboot), "f" * 40), (str(coreboot), commit))
            with patch.object(firmware, "load_lock", return_value=drifted):
                with self.assertRaises(SafetyError):
                    firmware.verify(root, "fw-d")

    def test_unexpected_pin_shapes_are_refused(self):
        with temporary() as root:
            for name in ["../escape", "Upper", "sp ace"]:
                pins = {"sources": [{"name": name, "repository": "file:///x", "commit": "0" * 40}]}
                with self.subTest(name=name), patch.object(firmware, "load_lock", return_value=pins):
                    with self.assertRaises(SafetyError):
                        firmware.fetch(root, "fw-e", allow_network=True)


if __name__ == "__main__":
    unittest.main()
