"""Offline tests for superseded-evidence retention (pipeline.prune)."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import pipeline
from firearc.integrity import read_json, write_json
from support import temporary


def fabricate(root):
    """Three device generations, two rootfs generations and decoys."""
    build = root / "build"
    build.mkdir(mode=0o700)
    images = build / "images"
    images.mkdir(mode=0o700)
    for name, age, content in (("device-aaaaaaaaaaaa", 3000, b"old"),
                                ("device-bbbbbbbbbbbb", 2000, b"middle"),
                                ("device-cccccccccccc", 1000, b"current")):
        (images / name).mkdir(mode=0o700)
        (images / name / "result.json").write_bytes(content)
        import os
        os.utime(images / name, (age, age))
    for name, age in (("rootfs-aaaaaaaaaaaa", 3000), ("rootfs-bbbbbbbbbbbb", 1000)):
        (images / name).mkdir(mode=0o700)
        import os
        os.utime(images / name, (age, age))
    # Content-addressed metadata and non-stage decoys must never be touched.
    (build / "dependencies").mkdir(mode=0o700)
    (build / "dependencies/metadata-0123456789abcdef").mkdir(mode=0o700)
    (images / "randomthing-aaaaaaaaaaaa").mkdir(mode=0o700)
    write_json(build / "state.json", {"schema": 1, "stages": {
        "device": {"id": "device-cccccccccccc"},
        "rootfs": {"id": "rootfs-bbbbbbbbbbbb"},
    }})


class PruneTests(unittest.TestCase):
    def test_prune_keeps_current_and_previous_generation(self):
        with temporary() as root:
            fabricate(root)
            result = pipeline.prune(root, keep=1)
            removed = [item["dir"] for item in result["removed"]]
            # device: current (c) plus newest superseded (a) stay; oldest (b) goes.
            # rootfs: the only superseded generation stays within the keep budget.
            self.assertEqual(removed, ["device-bbbbbbbbbbbb"])
            self.assertIn("device-aaaaaaaaaaaa", result["kept"])
            self.assertIn("rootfs-aaaaaaaaaaaa", result["kept"])
            self.assertTrue((root / "build/images/device-cccccccccccc").is_dir())
            self.assertTrue((root / "build/images/rootfs-bbbbbbbbbbbb").is_dir())

    def test_prune_protects_profile_pinned_evidence(self):
        with temporary() as root:
            fabricate(root)
            devices = root / "build/devices/dev1"
            devices.mkdir(parents=True, mode=0o700)
            write_json(devices / "profile.json",
                       {"provenance": {"device_label": "device-aaaaaaaaaaaa",
                                       "firmware_label": "firmware-build-aaaaaaaaaaaa"}})
            result = pipeline.prune(root, keep=1)
            removed = [item["dir"] for item in result["removed"]]
            # The pinned oldest generation is protected outright, so it never
            # consumes the keep budget: the remaining superseded generation
            # stays within it and nothing is deleted in this scenario.
            self.assertEqual(removed, [])
            self.assertTrue((root / "build/images/device-aaaaaaaaaaaa").is_dir())
            self.assertTrue((root / "build/images/device-bbbbbbbbbbbb").is_dir())

    def test_prune_ignores_content_addressed_and_unknown_dirs(self):
        with temporary() as root:
            fabricate(root)
            pipeline.prune(root, keep=0)
            images = root / "build/images"
            self.assertTrue((root / "build/dependencies/metadata-0123456789abcdef").is_dir())
            self.assertTrue((images / "randomthing-aaaaaaaaaaaa").is_dir())
            self.assertFalse((images / "device-bbbbbbbbbbbb").exists())

    def test_prune_reports_freed_bytes(self):
        with temporary() as root:
            fabricate(root)
            result = pipeline.prune(root, keep=1)
            self.assertGreater(result["bytes_freed"], 0)
            self.assertEqual(result["bytes_freed"],
                             sum(item["bytes"] for item in result["removed"]))

    def test_prune_without_build_tree_is_a_noop(self):
        with temporary() as root:
            self.assertEqual(pipeline.prune(root),
                             {"removed": [], "kept": [], "bytes_freed": 0})


if __name__ == "__main__":
    unittest.main()
