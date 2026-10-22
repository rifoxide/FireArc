"""Public commands stay small; stage selection is explicit and fail-closed."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import cli, pipeline
from firearc.integrity import SafetyError
from support import temporary


class CommandTests(unittest.TestCase):
    def invoke(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["firearc", *arguments]), redirect_stdout(out), redirect_stderr(err):
            cli.main()
        return json.loads(out.getvalue())

    @contextmanager
    def recorded_lock(self, events):
        events.append("lock")
        try:
            yield
        finally:
            events.append("unlock")

    def test_device_commands_preserve_arguments_and_hold_the_project_lock(self):
        cases = (
            (("device-provision", "--name", "test"), "provision", ("test",), {"replace": False}),
            (("device-provision", "--name", "test", "--replace"), "provision", ("test",), {"replace": True}),
            (("device-boot", "--name", "test"), "boot", ("test",), {"count": 2, "tcg": False}),
            (("device-boot", "--name", "test", "--count", "3", "--tcg"), "boot", ("test",), {"count": 3, "tcg": True}),
            (("data-enroll", "--name", "test"), "data_enroll", ("test",), {}),
            (("device-reboot", "--name", "test"), "reboot", ("test",), {"resets": 2}),
            (("device-reboot", "--name", "test", "--resets", "3"), "reboot", ("test",), {"resets": 3}),
            (("device-stop", "--name", "test"), "stop", ("test",), {}),
            (("device-powercut", "--name", "test"), "powercut", ("test",), {}),
            (("device-snapshot", "--name", "test", "--label", "baseline"), "snapshot", ("test", "baseline"), {}),
            (("device-restore", "--name", "test", "--label", "baseline"), "restore", ("test", "baseline"), {}),
        )
        for argv, operation, arguments, keywords in cases:
            with self.subTest(args=argv):
                events = []
                def run(*args, **kwargs):
                    events.append("operation")
                    return {"passed": True}
                with patch.object(cli.pipeline, "project_lock", side_effect=lambda root: self.recorded_lock(events)) as lock, \
                        patch.object(cli.profile, operation, side_effect=run) as action:
                    self.assertEqual(self.invoke(*argv), {"passed": True})
                    action.assert_called_once_with(cli.ROOT, *arguments, **keywords)
                    lock.assert_called_once_with(cli.ROOT)
                self.assertEqual(events, ["lock", "operation", "unlock"])

    def test_key_roles_preserve_dependency_order_and_locking(self):
        for command, module in (("keys", cli.keys), ("vboot-keys", cli.vboot_keys), ("pcr-keys", cli.pcr_keys)):
            with self.subTest(command=command):
                events = []
                def ensure(stage):
                    events.append(stage)
                    return {"id": stage + "-id"}
                def sign(*args):
                    events.append("key-role")
                    return {"passed": True}
                with patch.object(cli.pipeline, "project_lock", side_effect=lambda root: self.recorded_lock(events)), \
                        patch.object(cli.pipeline, "Pipeline") as factory, \
                        patch.object(module, "ensure", side_effect=sign) as action:
                    factory.return_value.ensure.side_effect = ensure
                    self.invoke(command)
                    factory.assert_called_once_with(cli.ROOT)
                    arguments = (cli.ROOT, "tools-id", "futility-id") if command == "vboot-keys" else (cli.ROOT, "tools-id")
                    action.assert_called_once_with(*arguments)
                expected = ["lock", "tools"] + (["futility"] if command == "vboot-keys" else [])
                self.assertEqual(events, expected + ["key-role", "unlock"])

    def test_clean_and_prune_hold_the_lock_but_reproduction_owns_its_lock(self):
        cases = ((("clean", "--yes"), "clean", {"confirmed": True}),
                 (("prune",), "prune", {"keep": 0}),
                 (("prune", "--keep", "2"), "prune", {"keep": 2}))
        for argv, operation, keywords in cases:
            with self.subTest(command=argv):
                events = []
                def run(*args, **kwargs):
                    events.append("operation")
                    return {"passed": True}
                with patch.object(cli.pipeline, "project_lock", side_effect=lambda root: self.recorded_lock(events)), \
                        patch.object(cli.pipeline, operation, side_effect=run) as action:
                    result = self.invoke(*argv)
                    action.assert_called_once_with(cli.ROOT, **keywords)
                    if operation == "clean":
                        self.assertEqual(result, {"passed": True, "removed": "build/"})
                self.assertEqual(events, ["lock", "operation", "unlock"])
        with patch.object(cli.pipeline, "project_lock") as lock, \
                patch.object(cli.pipeline, "reproduce", return_value={"passed": True}) as action:
            self.invoke("reproduce", "--yes")
            action.assert_called_once_with(cli.ROOT, confirmed=True)
            lock.assert_not_called()

    def test_validation_order_and_diagnostic_results_are_unchanged(self):
        operations = Mock()
        with patch.object(cli, "validate_locks", operations.validate), \
                patch.object(cli.builder, "lock", operations.tools), \
                patch.object(cli.builder, "root_lock", operations.root):
            self.assertEqual(self.invoke("verify-inputs"), {
                "passed": True, "scope": "Specification and project input locks"})
        self.assertEqual(operations.mock_calls, [call.validate(cli.ROOT), call.tools(cli.ROOT), call.root(cli.ROOT)])
        for command, name in (("doctor", "doctor"), ("secrets", "scan_repository")):
            with self.subTest(command=command), patch.object(cli, name, return_value={"passed": True}) as action:
                self.assertEqual(self.invoke(command), {"passed": True})
                action.assert_called_once_with(cli.ROOT)

    def test_pipeline_commands_keep_offline_defaults(self):
        for command in ("build", "verify-build", "status", "check-boot", "check-secure-boot",
                        "check-firmware-vboot", "firmware-sources"):
            with self.subTest(command=command), patch.object(cli.pipeline, "run", return_value={"passed": True}) as action:
                self.invoke(command)
                action.assert_called_once_with(cli.ROOT, command, online=False)

    def test_success_output_is_one_sorted_json_document(self):
        out = io.StringIO()
        with patch.object(sys, "argv", ["firearc", "build"]), redirect_stdout(out), \
                patch.object(cli.pipeline, "run", return_value={"z": 1, "a": 2}):
            self.assertIsNone(cli.main())
        self.assertEqual(out.getvalue(), '{\n  "a": 2,\n  "z": 1\n}\n')

    def test_shell_owns_the_terminal_without_json_output(self):
        from firearc import shell
        out = io.StringIO()
        with patch.object(sys, "argv", ["firearc", "shell"]), redirect_stdout(out), \
                patch.object(shell, "boot", return_value={"must_not_print": True}) as boot:
            self.assertIsNone(cli.main())
        boot.assert_called_once_with(cli.ROOT)
        self.assertEqual(out.getvalue(), "")

    def test_operational_errors_and_interrupts_preserve_exit_status_and_stderr(self):
        errors = (SafetyError("refused"), OSError("missing"), KeyError("key"),
                  ValueError("invalid"), subprocess.SubprocessError("tool failed"), KeyboardInterrupt())
        for error in errors:
            with self.subTest(error=type(error).__name__):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, "argv", ["firearc", "build"]), redirect_stdout(out), redirect_stderr(err), \
                        patch.object(cli.pipeline, "run", side_effect=error):
                    with self.assertRaises(SystemExit) as exited:
                        cli.main()
                interrupted = isinstance(error, KeyboardInterrupt)
                self.assertEqual(exited.exception.code, 130 if interrupted else 1)
                self.assertEqual(out.getvalue(), "")
                expected = "Interrupted; no incomplete stage is published as successful.\n" if interrupted else f"ERROR: {error}\n"
                self.assertEqual(err.getvalue(), expected)

    def test_device_failure_releases_lock_before_reporting_error(self):
        events = []
        with patch.object(sys, "argv", ["firearc", "device-boot", "--name", "test"]), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                patch.object(cli.pipeline, "project_lock", side_effect=lambda root: self.recorded_lock(events)), \
                patch.object(cli.profile, "boot", side_effect=SafetyError("refused")):
            with self.assertRaises(SystemExit) as exited:
                cli.main()
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(events, ["lock", "unlock"])

    def test_parser_is_side_effect_free_and_preserves_destructive_defaults(self):
        with patch.object(cli.pipeline, "project_lock") as lock, \
                patch.object(cli.pipeline, "Pipeline") as build:
            parser = cli.create_parser()
            self.assertFalse(parser.parse_args(["clean"]).yes)
            self.assertFalse(parser.parse_args(["reproduce"]).yes)
            self.assertFalse(parser.parse_args(["device-provision", "--name", "test"]).replace)
            boot = parser.parse_args(["device-boot", "--name", "test"])
            self.assertEqual((boot.count, boot.tcg), (2, False))
            self.assertEqual(parser.parse_args(["device-reboot", "--name", "test"]).resets, 2)
            lock.assert_not_called()
            build.assert_not_called()

    def test_execute_returns_the_operation_result_without_rendering_it(self):
        args = cli.create_parser().parse_args(["stage", "rootfs"])
        result = {"passed": True}
        out = io.StringIO()
        with redirect_stdout(out), patch.object(cli.pipeline, "run", return_value=result) as run:
            self.assertIs(cli.execute(args), result)
        self.assertEqual(out.getvalue(), "")
        run.assert_called_once_with(cli.ROOT, "rootfs")

    def test_every_exposed_stage_uses_the_same_offline_dispatch(self):
        for stage in cli.BUILD_STAGES:
            with self.subTest(stage=stage), patch.object(cli.pipeline, "run", return_value={"passed": True}) as run:
                self.assertTrue(self.invoke("stage", stage)["passed"])
                run.assert_called_once_with(cli.ROOT, stage)
                self.assertIn(stage, pipeline.DEPENDENCIES)
                self.assertFalse(stage.startswith("shell-"))

    def test_unknown_stages_old_aliases_and_online_builds_are_rejected(self):
        for arguments in (("stage", "typo"), ("stage", "shell-uki"),
                          ("build-rootfs",), ("build", "--online"),
                          ("stage", "root", "--online")):
            with self.subTest(args=arguments), patch.object(cli.pipeline, "run") as run:
                with self.assertRaises(SystemExit) as error:
                    self.invoke(*arguments)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()

    def test_only_acquisition_commands_allow_network(self):
        for arguments in (("bootstrap",), ("firmware-sources", "--online")):
            with self.subTest(args=arguments), patch.object(cli.pipeline, "run", return_value={"passed": True}) as run:
                self.invoke(*arguments)
                run.assert_called_once_with(cli.ROOT, arguments[0], online=True)
        with patch.object(cli.pipeline, "run", return_value={"passed": True}) as run:
            self.invoke("build")
            run.assert_called_once_with(cli.ROOT, "build", online=False)

    def test_stage_rootfs_builds_rootfs_not_the_entire_published_image(self):
        with temporary() as root, patch.object(pipeline, "Pipeline") as factory:
            self.assertTrue(pipeline.run(root, "rootfs")["passed"])
            factory.return_value.ensure.assert_called_once_with("rootfs")
            factory.return_value.publish.assert_not_called()

    def test_explicit_firmware_acquisition_also_prepares_the_pinned_sdk(self):
        for online in (False, True):
            with self.subTest(online=online), temporary() as root, \
                    patch.object(pipeline, "Pipeline") as factory, \
                    patch.object(pipeline, "load_lock", return_value={"sdk_image": "pinned"}), \
                    patch.object(pipeline.firmware_build, "ensure_sdk") as sdk:
                factory.return_value.ensure.return_value = {"id": "firmware-sources-aaaaaaaaaaaa"}
                pipeline.run(root, "firmware-sources", online=online)
                sdk.assert_called_once_with(root / "build/firmware/firmware-sources-aaaaaaaaaaaa",
                                            {"sdk_image": "pinned"}, allow_network=online)
                factory.return_value.ensure.assert_called_once_with("firmware-sources")

    def test_unknown_pipeline_commands_fail_before_creating_any_build_state(self):
        with temporary() as root, patch.object(pipeline, "Pipeline") as factory:
            with self.assertRaisesRegex(SafetyError, "Unknown build command"):
                pipeline.run(root, "typo")
            factory.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])
