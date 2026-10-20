"""Offline tests for dependency selection, receipts, publication and cleanup."""

from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import pipeline
from firearc.integrity import SafetyError, read_json, sha256, write_json
from support import temporary


class FakePipeline(pipeline.Pipeline):
    def __init__(self, *args, **kwargs):
        self.calls = []
        self.fail = None
        super().__init__(*args, **kwargs)

    def produce(self, stage, build_id, deps):
        self.calls.append(stage)
        if self.fail == stage:
            raise SafetyError("synthetic failure")
        group = "dependencies" if stage in {"metadata", "packages-tools", "packages-root", "tools", "sbom"} else "images"
        work = self.build / group / build_id
        work.mkdir(mode=0o700)
        if stage == "metadata":
            (work / "repository").mkdir()
            (work / "repository/index").write_text("authenticated index fixture")
        elif stage.startswith("packages-"):
            (work / "context").mkdir()
            (work / "context/package.deb").write_text("package fixture")
            write_json(work / "packages.json", {})
        elif stage == "tools":
            for name in ["build-result.json", "export-result.json", "tools-inventory.json", "packages.json"]:
                write_json(work / name, {"passed": True})
            return work, {"image_id": "sha256:" + "a" * 64}
        elif stage == "sbom":
            output = work / "output"
            output.mkdir()
            (output / "sbom.json").write_text("{}")
            write_json(work / "result.json", {"passed": True, "artifacts": {"sbom.json": sha256(output / "sbom.json")}})
            return work, {}
        else:
            output = work / "output"
            output.mkdir()
            names = ["firearc-root.tar", "firearc-root.vmlinuz", "firearc-initrd.img"] if stage == "root" else ["root.ext4", "root.verity", "verity-authority.json"] if stage == "rootfs" else []
            for name in names:
                (output / name).write_text(name)
            write_json(work / "result.json", {"passed": True, "artifacts": {name: sha256(output / name) for name in names}, "root_payload": "root.ext4"})
        return work, {}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.patches = [patch.object(pipeline, "validate_locks"), patch.object(pipeline.builder, "lock"),
                        patch.object(pipeline.builder, "root_lock"), patch.object(pipeline.builder, "verify_tools"),
                        patch.object(pipeline.subprocess, "run")]
        for item in self.patches: item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])

    def workspace(self, root):
        for name in ["src/firearc", "images", "containers", "locks"]:
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "src/firearc/example.py").write_text("initial")
        for name in ["debian-build", "root"]:
            (root / f"locks/{name}.json").write_text('{"schema":1}')

    def test_automatic_dependencies_and_cached_success_need_no_labels(self):
        with temporary() as root:
            self.workspace(root)
            first = FakePipeline(root, online=True)
            record = first.ensure("rootfs")
            self.assertEqual(first.calls, ["metadata", "packages-tools", "tools", "packages-root", "root", "rootfs"])
            self.assertIn("rootfs-", record["id"])
            second = FakePipeline(root)
            self.assertEqual(second.ensure("rootfs"), record)
            self.assertEqual(second.calls, [])

    def test_code_changes_invalidate_builds_but_not_authenticated_downloads(self):
        with temporary() as root:
            self.workspace(root)
            first = FakePipeline(root, online=True)
            previous = first.ensure("rootfs")
            (root / "src/firearc/example.py").write_text("changed")
            next_build = FakePipeline(root)
            current = next_build.ensure("rootfs")
            self.assertNotEqual(previous["id"], current["id"])
            self.assertEqual(next_build.calls, ["tools", "root", "rootfs"])

    def test_failed_stage_does_not_publish_success(self):
        with temporary() as root:
            self.workspace(root)
            build = FakePipeline(root, online=True)
            build.fail = "root"
            with self.assertRaises(SafetyError): build.ensure("root")
            self.assertNotIn("root", read_json(root / "build/state.json")["stages"])

    def test_tampered_output_is_not_reused_or_silently_repaired(self):
        with temporary() as root:
            self.workspace(root)
            record = FakePipeline(root, online=True).ensure("root")
            (root / "build/images" / record["id"] / "output/firearc-root.tar").write_text("tampered")
            with self.assertRaises(SafetyError): FakePipeline(root).ensure("root")

    def test_no_downloads_without_explicit_online_acquisition(self):
        with temporary() as root:
            self.workspace(root)
            build = FakePipeline(root)
            with self.assertRaises(SafetyError): build.ensure("root")
            self.assertEqual(build.calls, [])

    def test_output_aliases_are_stable_and_never_replace_a_regular_user_file(self):
        with temporary() as root:
            self.workspace(root)
            build = FakePipeline(root, online=True)
            outputs = build.publish()
            self.assertEqual(set(outputs), {"kernel.efi", "initrd.img", "root.tar", "root.ext4", "root.verity", "verity-authority.json", "sbom.json"})
            self.assertTrue((root / "build/output/root.ext4").is_symlink())
            (root / "build/output/root.ext4").unlink()
            (root / "build/output/root.ext4").write_text("keep")
            with self.assertRaises(SafetyError): build.publish()
            self.assertEqual((root / "build/output/root.ext4").read_text(), "keep")

    def test_project_lock_excludes_other_build_or_cleanup(self):
        with temporary() as root:
            with pipeline.project_lock(root):
                with self.assertRaises(SafetyError):
                    with pipeline.project_lock(root): pass

    def test_clean_requires_confirmation_and_refuses_symlink_target(self):
        with temporary() as root, temporary() as outside:
            (outside / "keep").write_text("keep")
            (root / "build").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(SafetyError): pipeline.clean(root)
            with self.assertRaises(SafetyError): pipeline.clean(root, confirmed=True)
            self.assertEqual((outside / "keep").read_text(), "keep")

    def test_clean_targets_only_build_in_rootless_namespace(self):
        with temporary() as root:
            self.workspace(root)
            (root / "build").mkdir(mode=0o700)
            with patch.object(pipeline.subprocess, "run") as run:
                pipeline.clean(root, confirmed=True)
            command = run.call_args.args[0]
            self.assertEqual(command[-1], str(root / "build"))
            self.assertIn("--user", command)
            self.assertIn("--net", command)

    def test_fingerprint_refuses_source_symlinks(self):
        with temporary() as root:
            self.workspace(root)
            (root / "src/link").symlink_to(root / "locks/root.json")
            with self.assertRaises(SafetyError): pipeline.project_digest(root)

    def test_reproduction_requires_confirmation_and_compares_both_clean_rounds(self):
        with temporary() as root:
            self.workspace(root)
            with self.assertRaises(SafetyError): pipeline.reproduce(root)
            cleaned = []
            def reset(path, *, confirmed):
                self.assertTrue(confirmed)
                cleaned.append(path)
                if (path / "build").exists(): shutil.rmtree(path / "build")
            with patch.object(pipeline, "clean", side_effect=reset), patch.object(pipeline, "Pipeline", FakePipeline):
                report = pipeline.reproduce(root, confirmed=True)
            self.assertEqual(len(cleaned), 2)
            self.assertTrue(report["passed"])
            self.assertEqual(len(report["clean_download_build_rounds"]), 2)

    def test_reproduction_records_failure_when_payloads_differ(self):
        with temporary() as root:
            self.workspace(root)
            def reset(path, *, confirmed):
                if (path / "build").exists(): shutil.rmtree(path / "build")
            with patch.object(pipeline, "clean", side_effect=reset), patch.object(pipeline, "Pipeline", FakePipeline), \
                    patch.object(FakePipeline, "publish", side_effect=[{"kernel.efi": "a" * 64}, {"kernel.efi": "b" * 64}]):
                with self.assertRaises(SafetyError): pipeline.reproduce(root, confirmed=True)
            self.assertFalse(read_json(root / "build/reproducibility.json")["passed"])
