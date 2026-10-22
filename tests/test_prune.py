"""Offline tests for superseded-evidence retention (pipeline.prune)."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import pipeline
from firearc.integrity import SafetyError, read_json, sha256, write_json
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


def fabricate_check(root, stage="check-boot", *, passed=True, complete=True, published=False):
    label = stage + "-aaaaaaaaaaaa"
    (root / "build").mkdir(mode=0o700, exist_ok=True)
    (root / "build/images").mkdir(mode=0o700, exist_ok=True)
    work = root / "build/images" / label
    work.mkdir(parents=True, mode=0o700)
    scratch = work if stage == "check-boot" else work / "disks"
    scratch.mkdir(mode=0o700, exist_ok=True)
    disk = scratch / "device-good.raw"
    disk.write_bytes(b"disposable working disk")
    log = work / "serial-good.log"
    log.write_bytes(b"permanent validation evidence")
    write_json(work / "result.json", {"passed": passed})
    record = {"id": label}
    if complete:
        files = {path.relative_to(root).as_posix(): sha256(path)
                 for path in (work / "result.json", log)}
        if published:
            files[disk.relative_to(root).as_posix()] = sha256(disk)
        write_json(work / "completion.json", {"passed": True, "stage": stage, "files": files})
        record.update(receipt=(work / "completion.json").relative_to(root).as_posix(),
                      receipt_sha256=sha256(work / "completion.json"))
    (root / "build/state.json").unlink(missing_ok=True)
    write_json(root / "build/state.json", {"stages": {stage: record}})
    return work, disk


class PruneTests(unittest.TestCase):
    def test_prune_default_keeps_only_referenced_evidence(self):
        with temporary() as root:
            fabricate(root)
            result = pipeline.prune(root)
            removed = [item["dir"] for item in result["removed"]]
            # Default retention: only the state-pinned current generation (and
            # anything a device profile pins) survives; superseded generations
            # and failed-run debris go away immediately.
            self.assertEqual(sorted(removed),
                             ["device-aaaaaaaaaaaa", "device-bbbbbbbbbbbb",
                              "rootfs-aaaaaaaaaaaa"])
            self.assertTrue((root / "build/images/device-cccccccccccc").is_dir())
            self.assertTrue((root / "build/images/rootfs-bbbbbbbbbbbb").is_dir())

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

    def test_prune_resolves_truncated_legacy_stage_prefixes(self):
        with temporary() as root:
            build = root / "build"
            build.mkdir(mode=0o700)
            images = build / "images"
            images.mkdir(mode=0o700)
            for name in ("check-secure-bo-aaaaaaaaaaaa",   # truncated legacy prefix
                         "check-secure-boot-bbbbbbbbbbbb",  # full name
                         "firmware-source-cccccccccccc"):   # truncated legacy prefix
                (images / name).mkdir(mode=0o700)
            write_json(root / "build/state.json",
                       {"schema": 1, "stages": {}})
            result = pipeline.prune(root)
            # Unprotected generations under either spelling go away; only
            # state-pinned or profile-pinned dirs survive.
            removed = sorted(item["dir"] for item in result["removed"])
            self.assertEqual(removed, ["check-secure-bo-aaaaaaaaaaaa",
                                       "check-secure-boot-bbbbbbbbbbbb",
                                       "firmware-source-cccccccccccc"])

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
                             {"removed": [], "scratch_removed": [], "kept": [], "bytes_freed": 0})

    def test_completed_checks_drop_only_unpublished_working_disks(self):
        for stage in ("check-boot", "check-secure-boot", "check-firmware-vboot"):
            with self.subTest(stage=stage), temporary() as root:
                work, disk = fabricate_check(root, stage)
                size = disk.stat().st_size
                artifact = work / "output/device.raw"
                artifact.parent.mkdir()
                artifact.write_bytes(b"published artifact")
                profile = root / "build/devices/dev1"
                profile.mkdir(parents=True)
                write_json(profile / "profile.json", {"provenance": {}})
                (profile / "disk.raw").write_bytes(b"persistent data")
                result = pipeline.prune(root)
                self.assertFalse(disk.exists())
                self.assertEqual(result["bytes_freed"], size)
                self.assertEqual(len(result["scratch_removed"]), 1)
                self.assertTrue((work / "serial-good.log").exists())
                self.assertTrue((work / "completion.json").exists())
                self.assertEqual(artifact.read_bytes(), b"published artifact")
                self.assertEqual((profile / "disk.raw").read_bytes(), b"persistent data")
                self.assertEqual(pipeline.prune(root)["scratch_removed"], [])

    def test_incomplete_or_failed_current_checks_keep_their_disks(self):
        for options in ({"complete": False}, {"passed": False}):
            with self.subTest(options=options), temporary() as root:
                _, disk = fabricate_check(root, **options)
                self.assertEqual(pipeline.prune(root)["scratch_removed"], [])
                self.assertTrue(disk.exists())

    def test_receipt_published_disks_are_not_scratch(self):
        with temporary() as root:
            _, disk = fabricate_check(root, published=True)
            self.assertEqual(pipeline.prune(root)["scratch_removed"], [])
            self.assertTrue(disk.exists())

    def test_tampered_evidence_blocks_scratch_deletion(self):
        for name in ("result.json", "completion.json", "serial-good.log"):
            with self.subTest(file=name), temporary() as root:
                work, disk = fabricate_check(root)
                with (work / name).open("ab") as stream:
                    stream.write(b"tampered")
                with self.assertRaises(SafetyError):
                    pipeline.prune(root)
                self.assertTrue(disk.exists())

    def test_scratch_symlinks_are_refused_without_touching_the_target(self):
        with temporary() as root:
            _, disk = fabricate_check(root)
            outside = root / "do-not-delete"
            outside.write_bytes(b"saved data")
            disk.unlink()
            disk.symlink_to(outside)
            with self.assertRaises(SafetyError):
                pipeline.prune(root)
            self.assertEqual(outside.read_bytes(), b"saved data")
            self.assertTrue(disk.is_symlink())

    def test_all_check_receipts_are_verified_before_any_scratch_is_deleted(self):
        with temporary() as root:
            first, first_disk = fabricate_check(root)
            first_record = read_json(root / "build/state.json")["stages"]["check-boot"]
            second, second_disk = fabricate_check(root, "check-secure-boot")
            state = read_json(root / "build/state.json")
            state["stages"]["check-boot"] = first_record
            (root / "build/state.json").unlink()
            write_json(root / "build/state.json", state)
            (second / "serial-good.log").write_text("tampered")
            with self.assertRaises(SafetyError):
                pipeline.prune(root)
            self.assertTrue(first_disk.exists())
            self.assertTrue(second_disk.exists())


if __name__ == "__main__":
    unittest.main()
