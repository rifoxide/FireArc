"""Offline tests: no VM, container daemon, network, mount or private credentials."""

from contextlib import contextmanager
import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from firearc_lib import baseline, host, inputs, qmp
from firearc_lib.integrity import (
    SafetyError, identifier, parse_manifest, private_directory, public_name,
    regular_file, relative_name, safe_qemu_path, sha256, verify_archive,
    verify_file, write_json,
)


@contextmanager
def temporary():
    approved = Path("/tmp/opencode")
    with tempfile.TemporaryDirectory(prefix="firearc-test-", dir=approved if approved.is_dir() else None) as path:
        yield Path(path)


def json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def small_workspace(root, reference):
    """Minimal synthetic public archive; no real historical or secret inputs."""
    pdf = root / "spec.pdf"
    pdf.write_bytes(b"synthetic specification")
    archive = reference / "artifacts/exp-029/fixture"
    archive.mkdir(parents=True)
    (archive / "public").mkdir()
    (archive / "public/root").write_bytes(b"synthetic immutable root")
    row = sha256(archive / "public/root") + "  public/root\n"
    (archive / "SHA256SUMS").write_text(row)
    json_file(root / "locks/research-baseline.json", {
        "schema": 1, "experiment": "EXP-029", "archive_base": "artifacts/exp-029",
        "specification": {"path": "spec.pdf", "sha256": sha256(pdf)},
        "manifests": {"fixture": sha256(archive / "SHA256SUMS")},
        "files": {"root.ext4": {"archive": "fixture", "path": "public/root"}},
    })
    json_file(root / "locks/firmware-sources.json", {"schema": 1, "sources": [
        {"name": f"source-{i}", "commit": f"{i:040x}", "repository": "https://example.invalid/source.git",
         "reference_path": f"sources/source-{i}"} for i in range(9)
    ]})
    json_file(root / "locks/lab-tools.json", {"schema": 1, "tools": {}})
    return archive


class IntegrityTests(unittest.TestCase):
    def test_relative_paths_are_canonical_and_confined(self):
        self.assertEqual(str(relative_name("public/db.der")), "public/db.der")
        for name in ("", ".", "/etc/passwd", "../key", "a/../../key", "a/./key", "a//key", "a/", "a\\key", "a\nkey"):
            with self.subTest(name=name), self.assertRaises(SafetyError):
                relative_name(name)

    def test_private_filenames_refused_public_certificates_allowed(self):
        for name in ("private/db.pem", "secrets/recovery", ".ssh/id_ed25519", "db.key", "db.pfx", ".env", "a/.env.local"):
            with self.subTest(name=name), self.assertRaises(SafetyError):
                public_name(name)
        self.assertEqual(str(public_name("public/db.key-public.pem")), "public/db.key-public.pem")

    def test_manifest_strict_format_duplicates_and_paths(self):
        digest = "a" * 64
        self.assertEqual(parse_manifest(f"{digest}  public/a\n".encode()), {"public/a": digest})
        invalid = [b"", f"{digest} a\n".encode(), f"{digest}  ../a\n".encode(),
                   f"{digest}  a\n{digest}  a\n".encode(), f"{'A' * 64}  a\n".encode()]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(SafetyError):
                parse_manifest(data)

    def test_full_manifest_verification_and_digest_mismatch(self):
        with temporary() as root:
            (root / "a").write_bytes(b"good")
            (root / "SHA256SUMS").write_text(sha256(root / "a") + "  a\n")
            pin = sha256(root / "SHA256SUMS")
            self.assertEqual(len(verify_archive(root, pin)), 1)
            (root / "a").write_bytes(b"bad")
            with self.assertRaises(SafetyError):
                verify_archive(root, pin)

    def test_manifest_itself_is_pinned(self):
        with temporary() as root:
            (root / "SHA256SUMS").write_text("a" * 64 + "  missing\n")
            with self.assertRaisesRegex(SafetyError, "mismatch"):
                verify_archive(root, "b" * 64)

    def test_symlink_file_and_intermediate_directory_refused(self):
        with temporary() as root:
            (root / "real").mkdir()
            (root / "real/file").write_text("public data")
            (root / "link").symlink_to(root / "real/file")
            (root / "directory").symlink_to(root / "real", target_is_directory=True)
            for name in ("link", "directory/file"):
                with self.subTest(name=name), self.assertRaises(SafetyError):
                    regular_file(root, name)

    def test_private_pem_detected_across_chunk_boundary(self):
        with temporary() as root:
            header = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n"
            (root / "public.pem").write_bytes(b"a" * (1024 * 1024 - 9) + b"\n" + header + b"not-a-real-key")
            with self.assertRaisesRegex(SafetyError, "Private-key"):
                sha256(root / "public.pem", scan_private=True)

    def test_non_hex_or_missing_pin_refused(self):
        with temporary() as root:
            (root / "a").write_text("a")
            for pin in (None, "", "latest", "G" * 64):
                with self.subTest(pin=pin), self.assertRaises(SafetyError):
                    verify_file(root / "a", pin)

    def test_evidence_write_never_overwrites(self):
        with temporary() as root:
            write_json(root / "result.json", {"passed": False})
            with self.assertRaises(FileExistsError):
                write_json(root / "result.json", {"passed": True})
            self.assertFalse(json.loads((root / "result.json").read_text())["passed"])

    def test_private_directory_permissions_and_symlink(self):
        with temporary() as root:
            private_directory(root / "state", create=True)
            (root / "state").chmod(0o755)
            with self.assertRaises(SafetyError):
                private_directory(root / "state", create=True)
            (root / "link").symlink_to(root / "state", target_is_directory=True)
            with self.assertRaises(SafetyError):
                private_directory(root / "link")

    def test_identifiers_and_qemu_paths(self):
        self.assertEqual(identifier("q35-a"), "q35-a")
        for value in ("../a", "", "a/b", "A", "x" * 33, "a,readonly=off"):
            with self.subTest(value=value), self.assertRaises(SafetyError):
                identifier(value)
        for path in ("a,readonly=off", "a\nb", "a\rb", "a\tb", "a\x7fb"):
            with self.subTest(path=path), self.assertRaises(SafetyError):
                safe_qemu_path(path)


class InputTests(unittest.TestCase):
    def test_real_requirement_hash_and_lock_structure(self):
        self.assertEqual(inputs.validate_locks(ROOT)["experiment"], "EXP-029")

    def test_readonly_reference_verification(self):
        with temporary() as root, temporary() as reference:
            archive = small_workspace(root, reference)
            before = {p.relative_to(reference): sha256(p) for p in reference.rglob("*") if p.is_file()}
            result = inputs.verify_reference(root, reference, check_sources=False)
            self.assertTrue(result["passed"])
            self.assertEqual(result["manifest_files_checked"], 1)
            self.assertEqual(before, {p.relative_to(reference): sha256(p) for p in reference.rglob("*") if p.is_file()})
            (archive / "public/root").write_text("changed")
            with self.assertRaises(SafetyError):
                inputs.verify_reference(root, reference, check_sources=False)

    def test_curated_import_no_overwrite_and_subsequent_validation(self):
        with temporary() as root, temporary() as reference:
            small_workspace(root, reference)
            with patch.object(inputs, "verify_reference", return_value={"manifest_files_checked": 1}):
                result = inputs.import_baseline(root, reference)
            self.assertEqual(result["files"], 1)
            self.assertEqual(set(inputs.verify_import(root)), {"root.ext4"})
            with self.assertRaises(SafetyError):
                inputs.import_baseline(root, reference)
            imported = inputs.imported_path(root) / "root.ext4"
            imported.chmod(0o600)
            imported.write_bytes(b"changed")
            with self.assertRaises(SafetyError):
                inputs.verify_import(root)

    def test_existing_symlink_import_target_refused(self):
        with temporary() as root, temporary() as reference:
            small_workspace(root, reference)
            target = inputs.imported_path(root)
            target.parent.mkdir(parents=True)
            target.symlink_to(root / "nonexistent")
            with self.assertRaises(SafetyError):
                inputs.import_baseline(root, reference)

    def test_specification_changes_are_not_accepted(self):
        with temporary() as root, temporary() as reference:
            small_workspace(root, reference)
            (root / "spec.pdf").write_bytes(b"replacement specification")
            with self.assertRaises(SafetyError):
                inputs.validate_locks(root)

    def test_tool_pin_changes_and_missing_tools_fail_closed(self):
        with patch.object(inputs, "load_lock", return_value={"tools": {"tool": {"sha256": "0" * 64}}}):
            with patch.object(inputs.shutil, "which", return_value=None), self.assertRaises(SafetyError):
                inputs.tool_paths(ROOT, ["tool"])
            with temporary() as root:
                path = root / "tool"
                path.write_text("unexpected binary")
                with patch.object(inputs.shutil, "which", return_value=str(path)), self.assertRaises(SafetyError):
                    inputs.tool_paths(ROOT, ["tool"])


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.config = baseline.profile(ROOT)
        self.metadata = {"root_hash": "a" * 64, "salt": "b" * 64, "data_blocks": 2, "data_bytes": 8192,
                         "cmdline": "root=/dev/mapper/firearc-root ro signed-example"}
        self.boot_id = "11111111-1111-4111-8111-111111111111"
        self.console = "\n".join([
            f'FIREARC_ROOT_FULL_SCAN_OK hash={self.metadata["root_hash"]} blocks=2',
            "FIREARC_ROOT_MAPPING_OK", "FIREARC_ROOT_REPORT_BEGIN", "ID=debian", 'VERSION_ID="13"',
            self.metadata["cmdline"], "none [integrity] confidentiality", "FIREARC_SECUREBOOT_1_SETUPMODE_0",
            "FIREARC_DB_SHA256=db", "status:      verified", "mode:        readonly",
            f'0 16 verity 1 8:0 8:16 4096 4096 2 0 sha256 {self.metadata["root_hash"]} {self.metadata["salt"]}',
            "/dev/mapper/firearc-root ext4 ro,relatime,norecovery", "FIREARC_BOOT_ID=" + self.boot_id,
            "FIREARC_ROOT_READY", "FIREARC_ROOT_REPORT_END", "reboot: Power down", "",
        ])

    def test_full_good_report_required_not_just_ready(self):
        result = baseline.validate_console(self.console, "good", self.metadata, "db", 0)
        self.assertEqual(result["boot_id"], self.boot_id)
        for marker in ("FIREARC_ROOT_FULL_SCAN_OK", "FIREARC_ROOT_MAPPING_OK", "FIREARC_SECUREBOOT_1_SETUPMODE_0",
                       "FIREARC_ROOT_REPORT_END", "FIREARC_DB_SHA256=db", "mode:        readonly",
                       "0 16 verity", "/dev/mapper/firearc-root ext4 ro,", self.boot_id):
            with self.subTest(marker=marker), self.assertRaises(SafetyError):
                baseline.validate_console(self.console.replace(marker, "MISSING"), "good", self.metadata, "db", 0)

    def test_good_boot_needs_clean_exit(self):
        with self.assertRaises(SafetyError):
            baseline.validate_console(self.console, "good", self.metadata, "db", -15)

    def test_root_negative_must_fail_before_mapping(self):
        denied = "FIREARC_ROOT_REJECTED stage=full-scan\nreboot: Power down\n"
        self.assertTrue(baseline.validate_console(denied, "data-unused", self.metadata, "db", 0)["full_scan_rejection_verified"])
        with self.assertRaises(SafetyError):
            baseline.validate_console(denied + "FIREARC_ROOT_MAPPING_OK", "data-unused", self.metadata, "db", 0)

    def test_firmware_denial_is_not_kernel_or_root_denial(self):
        denied = "UEFI Secure Boot is enabled.\nAccess Denied\n"
        self.assertTrue(baseline.validate_console(denied, "unsigned", self.metadata, "db", 0)["firmware_denial_verified"])
        with self.assertRaises(SafetyError):
            baseline.validate_console(denied + "Linux version untrusted", "unsigned", self.metadata, "db", 0)

    def test_boot_command_is_headless_networkless_and_tpm_isolated(self):
        p = Path("/tmp/opencode/example")
        args = (self.config, {"qemu-system-x86_64": "/usr/bin/qemu-system-x86_64"}, p / "flash", p / "root",
                p / "hash", p / "media", p / "boot", p / "sockets")
        command = baseline.boot_command(*args)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command[command.index("-display") + 1], "none")
        self.assertNotIn("-tpmdev", command)
        attached = baseline.boot_command(*args, tpm=True)
        self.assertIn("tpm-tis,tpmdev=tpm0", attached)
        self.assertIn("emulator,id=tpm0,chardev=chrtpm", attached)
        self.assertFalse(any("/dev/tpm" in item or "0.0.0.0" in item for item in attached))

    def test_missing_device_run_never_provisions(self):
        with temporary() as root, patch.object(baseline, "profile", return_value=self.config):
            with self.assertRaises(FileNotFoundError):
                baseline.run_device(root, "missing", label="attempt-a")
            self.assertFalse((root / "run").exists())

    def test_existing_device_creation_cannot_reset_it(self):
        with temporary() as root:
            path = baseline.state_parent(root) / "device-a"
            path.mkdir(mode=0o700)
            (path / "preserve").write_text("existing device state")
            with patch.object(baseline, "profile", return_value=self.config), \
                    patch.object(baseline, "verify_import", return_value={}), \
                    patch.object(baseline, "tool_paths", return_value={}), self.assertRaises(FileExistsError):
                baseline.new_device(root, "device-a")
            self.assertEqual((path / "preserve").read_text(), "existing device state")

    def test_exclusive_device_lock(self):
        with temporary() as root:
            with baseline.device_lock(root):
                with self.assertRaises(SafetyError):
                    with baseline.device_lock(root):
                        self.fail("Second lock must not succeed")

    def test_console_cleanup(self):
        self.assertEqual(baseline.clean_console(b"\x1b[31mhello\x1b[0m\r\n"), "hello\n")

    def test_lock_symlink_is_not_followed(self):
        with temporary() as root:
            (root / "other").write_text("must not be overwritten")
            (root / ".lock").symlink_to(root / "other")
            with self.assertRaises(OSError):
                with baseline.device_lock(root):
                    self.fail("Symlink lock must not be opened")
            self.assertEqual((root / "other").read_text(), "must not be overwritten")

    def test_stop_owns_process_object_and_reaps_it(self):
        process = Mock()
        process.poll.return_value = None
        baseline.stop_owned(process)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)
        process.kill.assert_not_called()

    def test_stuck_owned_process_is_killed_and_reaped(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("test-owned-process", 10), 0]
        baseline.stop_owned(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_already_exited_process_is_not_signalled(self):
        process = Mock()
        process.poll.return_value = 0
        baseline.stop_owned(process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        baseline.stop_owned(None)

    def test_overlay_backing_and_format_are_mandatory(self):
        backing = Path("/tmp/opencode/public-root")
        valid = {"format": "qcow2", "full-backing-filename": str(backing), "backing-filename-format": "raw"}
        with patch.object(baseline, "read_json_output", return_value=valid):
            baseline.validate_overlay("qemu-img", Path("overlay"), backing)
        for key, value in [("format", "raw"), ("full-backing-filename", "/dev/sda"), ("backing-filename-format", "qcow2")]:
            with self.subTest(key=key), patch.object(baseline, "read_json_output", return_value={**valid, key: value}), \
                    self.assertRaises(SafetyError):
                baseline.validate_overlay("qemu-img", Path("overlay"), backing)

    def test_control_cannot_target_an_arbitrary_socket(self):
        with temporary() as root:
            device = baseline.state_parent(root) / "device-a"
            device.mkdir(mode=0o700)
            private_directory(root / "run/sockets", create=True)
            write_json(device / "active.json", {"id": "device-a", "qmp": "/tmp/opencode/other/qmp.sock"})
            with patch.object(baseline, "request") as request, self.assertRaises(SafetyError):
                baseline.control_device(root, "device-a", "powercut")
            request.assert_not_called()

    def test_tpm_persistence_requires_existing_nonempty_private_state(self):
        with temporary() as root:
            private_directory(root / "tpm", create=True)
            with self.assertRaises(FileNotFoundError):
                baseline.tpm_state(root)
            state = root / "tpm/tpm2-00.permall"
            state.write_bytes(b"")
            state.chmod(0o600)
            with self.assertRaises(SafetyError):
                baseline.tpm_state(root)
            state.write_bytes(b"synthetic private state, do not read")
            with patch.object(Path, "open", side_effect=AssertionError("TPM state contents must not be read")):
                self.assertEqual(baseline.tpm_state(root), state)
            state.chmod(0o644)
            with self.assertRaises(SafetyError):
                baseline.tpm_state(root)

    def test_tpm_initialization_flags_only_in_explicit_creation(self):
        root = Path("/tmp/opencode/device")
        ordinary = baseline.swtpm_command("swtpm", root, root / "sockets")
        creation = baseline.swtpm_command("swtpm", root, root / "sockets", initialize=True)
        self.assertEqual(ordinary[ordinary.index("--flags") + 1], "not-need-init")
        self.assertEqual(creation[creation.index("--flags") + 1], "not-need-init,startup-clear")

    def test_tpm_guest_detection_keeps_duplicate_probe_warning_visible(self):
        good = "tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x1, rev-id 1)\n"
        warning = "tpm_tis MSFT0101:01: error -EBUSY: can't request region\n"
        result = baseline.validate_tpm_console(good + warning)
        self.assertTrue(result["tpm2_guest_detected"])
        self.assertTrue(result["tpm_duplicate_probe_warning"])
        self.assertFalse(result["tpm_policy_qualified"])
        with self.assertRaises(SafetyError):
            baseline.validate_tpm_console("No TPM device detected")

    def test_normal_tpm_shutdown_before_guest_wait_is_not_a_backend_failure(self):
        tpm, guest = Mock(), Mock()
        tpm.poll.return_value = 0
        guest.wait.return_value = 0
        self.assertTrue(baseline.tpm_finished_with_guest(tpm, guest))
        guest.wait.assert_called_once_with(timeout=5)

    def test_backend_exit_with_guest_still_running_is_rejected(self):
        tpm, guest = Mock(), Mock()
        tpm.poll.return_value = 0
        guest.wait.side_effect = subprocess.TimeoutExpired("guest", 5)
        with self.assertRaises(SafetyError):
            baseline.tpm_finished_with_guest(tpm, guest)

    def test_abnormal_backend_exit_is_rejected(self):
        tpm, guest = Mock(), Mock()
        tpm.poll.return_value = 1
        with self.assertRaises(SafetyError):
            baseline.tpm_finished_with_guest(tpm, guest)
        guest.wait.assert_not_called()

    def test_live_backend_does_not_wait_for_guest(self):
        tpm, guest = Mock(), Mock()
        tpm.poll.return_value = None
        self.assertFalse(baseline.tpm_finished_with_guest(tpm, guest))
        guest.wait.assert_not_called()


class RepositoryStructureTests(unittest.TestCase):
    def test_python_source_syntax(self):
        for path in [*ROOT.glob("scripts/*.py"), *ROOT.glob("scripts/firearc_lib/*.py"), *ROOT.glob("tests/*.py")]:
            with self.subTest(path=path):
                ast.parse(path.read_text(), filename=str(path))

    def test_document_local_links_and_fences(self):
        import re
        for path in [ROOT / "README.md", ROOT / "PLAN.md", *ROOT.glob("docs/**/*.md")]:
            text = path.read_text()
            with self.subTest(path=path):
                self.assertEqual(len(re.findall(r"^```", text, re.M)) % 2, 0)
                for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
                    if "://" not in target:
                        self.assertTrue((path.parent / target).is_file(), (path, target))


class RepositoryScanTests(unittest.TestCase):
    def test_does_not_walk_ignored_private_state(self):
        with temporary() as root:
            (root / "README.md").write_text("public")
            (root / "run").mkdir()
            (root / "run/private.key").write_text("not to be opened")
            with patch.object(host.subprocess, "check_output", return_value=b"README.md\0"):
                self.assertEqual(host.scan_repository(root)["files_checked"], 1)

    def test_forced_tracked_private_state_is_refused(self):
        with temporary() as root:
            with patch.object(host.subprocess, "check_output", return_value=b"run/tpm/state\0"), self.assertRaises(SafetyError):
                host.scan_repository(root)

    def test_known_token_pattern_is_not_printed(self):
        with temporary() as root:
            token = "ghp_" + "a" * 36
            (root / "README.md").write_text(token)
            with patch.object(host.subprocess, "check_output", return_value=b"README.md\0"):
                with self.assertRaises(SafetyError) as caught:
                    host.scan_repository(root)
            self.assertNotIn(token, str(caught.exception))


class QmpTests(unittest.TestCase):
    def test_events_interleaved_with_id_matched_response(self):
        with temporary() as root:
            path = root / "qmp.sock"
            errors = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                server.listen(1)
                server.settimeout(5)

                def serve():
                    try:
                        connection, _ = server.accept()
                        with connection, connection.makefile("rwb", buffering=0) as stream:
                            stream.write(b'{"QMP": {}}\r\n')
                            for _ in range(2):
                                value = json.loads(stream.readline())
                                stream.write(b'{"event": "TEST_EVENT"}\r\n')
                                reply = {"id": value["id"], "return": {"status": "running"}}
                                stream.write(json.dumps(reply).encode() + b"\r\n")
                    except BaseException as error:
                        errors.append(error)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                self.assertEqual(qmp.request(path, "query-status"), {"status": "running"})
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)

    def test_only_allowlisted_operations_and_real_sockets(self):
        with temporary() as root:
            path = root / "not-socket"
            path.write_text("not a socket")
            with self.assertRaises(SafetyError):
                qmp.request(path, "query-status")
            with self.assertRaises(SafetyError):
                qmp.request(path, "human-monitor-command")


if __name__ == "__main__":
    unittest.main()
