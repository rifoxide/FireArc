"""The console shell is explicit, signed, gated and disposable."""

from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, pipeline, shell
from firearc.integrity import SafetyError
from support import temporary
from test_device import AUTHORITY, parse_cpio


class ShellTests(unittest.TestCase):
    def test_shell_variant_changes_only_the_signed_terminal_unit(self):
        normal = parse_cpio(device.dev_cpio(AUTHORITY))
        console = parse_cpio(device.dev_cpio(AUTHORITY, shell=True))
        self.assertEqual(set(normal), set(console))
        changed = {name for name in normal if normal[name] != console[name]}
        self.assertEqual(changed, {"etc/systemd/system/firearc-dev-done.service"})
        unit = console[changed.pop()][1].decode()
        for required in ("Requires=sysroot.mount firearc-data-mount.service",
                         "After=sysroot.mount firearc-data-mount.service",
                         "RootDirectory=/sysroot", "MountAPIVFS=yes",
                         "StandardInput=tty-force", "TTYPath=/dev/ttyS0",
                         "ExecStart=/bin/bash --noprofile --norc -i",
                         "OnFailure=firearc-boot-failure.service",
                         "ExecStart=/usr/bin/systemctl --no-block poweroff",
                         "ExecStart=/usr/bin/sleep infinity", "SYSTEMD_IGNORE_CHROOT=1"):
            self.assertIn(required, unit)
        self.assertNotIn(b"ExecStart=/bin/bash", device.dev_cpio(AUTHORITY))
        self.assertNotIn("rd.shell=1", device.KERNEL_CMDLINE)

    def test_shell_signing_and_enrollment_are_not_normal_build_dependencies(self):
        def closure(stage):
            return {stage}.union(*(closure(dep) for dep in pipeline.DEPENDENCIES[stage]))
        normal = closure("device") | closure("enroll")
        self.assertFalse(any(stage.startswith("shell-") for stage in normal))
        self.assertIn("shell-uki", closure("shell-device"))
        self.assertIn("shell-pcr-sign", closure("shell-device"))
        self.assertEqual(pipeline.DEPENDENCIES["shell-enroll"],
                         ("firmware-sign", "shell-sign"))

    def test_normal_and_shell_stages_use_the_same_builders_with_isolated_labels(self):
        pipe = object.__new__(pipeline.Pipeline)
        pipe.root = ROOT
        pipe.build = ROOT / "build"
        cases = (
            ("uki", "uki", (ROOT, "tools", "root", "rootfs", "uki-test"), {"shell": False}),
            ("pcr-sign", "pcr_sign", (ROOT, "tools", "uki", "pcr-sign-test"), {}),
            ("sign", "sign", (ROOT, "tools", "root", "pcr-sign", "sign-test"), {}),
            ("enroll", "enroll", (ROOT, "firmware-sign", "sign", "enroll-test"), {}),
            ("shell-uki", "uki", (ROOT, "tools", "root", "rootfs", "shell-uki-test"), {"shell": True}),
            ("shell-pcr-sign", "pcr_sign", (ROOT, "tools", "shell-uki", "shell-pcr-sign-test"), {}),
            ("shell-sign", "sign", (ROOT, "tools", "root", "shell-pcr-sign", "shell-sign-test"), {}),
            ("shell-enroll", "enroll", (ROOT, "firmware-sign", "shell-sign", "shell-enroll-test"), {}),
        )
        for stage, module, args, kwargs in cases:
            deps = {name: {"id": name} for name in pipeline.DEPENDENCIES[stage]}
            with self.subTest(stage=stage), patch.object(getattr(pipeline, module), "build") as build:
                output, _ = pipe.produce(stage, stage + "-test", deps)
                build.assert_called_once_with(*args, **kwargs)
                self.assertEqual(output, ROOT / "build/images" / (stage + "-test"))
            error = SafetyError("builder refused")
            with patch.object(getattr(pipeline, module), "build", side_effect=error):
                with self.assertRaises(SafetyError) as refused:
                    pipe.produce(stage, stage + "-test", deps)
                self.assertIs(refused.exception, error)
        for stage, source in (("device", "sign"), ("shell-device", "shell-sign")):
            deps = {name: {"id": name} for name in pipeline.DEPENDENCIES[stage]}
            with self.subTest(stage=stage), patch.object(device, "assemble") as assemble:
                pipe.produce(stage, stage + "-test", deps)
                assemble.assert_called_once_with(ROOT, "tools", "rootfs", source, stage + "-test")
            error = SafetyError("assembler refused")
            with patch.object(device, "assemble", side_effect=error):
                with self.assertRaises(SafetyError) as refused:
                    pipe.produce(stage, stage + "-test", deps)
                self.assertIs(refused.exception, error)

    def test_shell_variants_require_the_existing_keys_not_new_identities(self):
        with temporary() as root:
            pipe = object.__new__(pipeline.Pipeline)
            pipe.root = root
            pipe.memo = {}
            for stage in ("shell-sign", "shell-enroll"):
                with self.subTest(stage=stage), self.assertRaisesRegex(SafetyError, "just keys"):
                    pipe.ensure(stage)
            with self.assertRaisesRegex(SafetyError, "just pcr-keys"):
                pipe.ensure("shell-pcr-sign")

    def test_interactive_qemu_has_terminal_and_snapshots_all_drives(self):
        command = device.qemu_command("flash.rom", "device.raw", "serial.log",
                                      kvm=True, tpm="tpm.sock", interactive=True)
        self.assertEqual(command[command.index("-serial") + 1], "mon:stdio")
        self.assertIn("-snapshot", command)
        self.assertIn("-no-reboot", command)
        self.assertIn("tpm-tis,tpmdev=tpm0", command)
        self.assertEqual(command[command.index("-net") + 1], "none")
        normal = device.qemu_command("flash.rom", "device.raw", "serial.log", kvm=True)
        self.assertNotIn("-snapshot", normal)
        self.assertIn("file:serial.log", normal)

    def test_shell_rejects_noninteractive_use_before_building(self):
        with patch.object(sys.stdin, "isatty", return_value=False), \
                patch.object(shell.pipeline, "Pipeline") as build:
            with self.assertRaisesRegex(SafetyError, "interactive terminal"):
                shell.boot(ROOT)
            build.assert_not_called()

    def test_startup_failure_stops_qemu_before_caller_removes_tpm(self):
        with temporary() as work, patch.object(device, "VmSession") as session_type:
            session = session_type.return_value
            session.start.side_effect = SafetyError("no QMP")
            with self.assertRaisesRegex(SafetyError, "no QMP"):
                device.start_vm(work, "qemu", flash="flash", disk="disk",
                                serial=work / "serial", kvm=True, interactive=True)
            session.kill.assert_called_once()
            session.close.assert_called_once()

    def test_interactive_session_inherits_terminal_descriptors(self):
        with temporary() as work, patch.object(device.subprocess, "Popen") as popen, \
                patch.object(device.qmp, "QmpControl"), \
                patch.object(Path, "exists", return_value=True):
            session = device.VmSession(work, "qemu", ["qemu-system-x86_64"], work / "qmp")
            session.start(work / "serial.log", interactive=True)
            args = popen.call_args.kwargs
            self.assertIsNone(args["stdin"])
            self.assertIsNone(args["stdout"])
            self.assertIsNone(args["stderr"])
            self.assertIsNone(session._out)
            popen.return_value.returncode = 0
            session.close()

    def test_shell_lifecycle_always_quits_and_removes_scratch_state(self):
        for code in (0, 1):
            with self.subTest(code=code), temporary() as work:
                (work / "build").mkdir()
                output = work / "artifacts"
                output.mkdir()
                for name in ("device.raw", "enrolled.rom"):
                    (output / name).write_bytes(b"verified artifact")
                machine = MagicMock()
                machine.session.process.wait.return_value = code
                pins = {name: {"sha256": "digest"}
                        for name in ("qemu-system-x86_64", "swtpm")}
                with patch.object(sys.stdin, "isatty", return_value=True), \
                        patch.object(sys.stdout, "isatty", return_value=True), \
                        patch.object(shell, "load_lock", return_value={"tools": pins}), \
                        patch.object(shell.shutil, "which", side_effect=lambda name: "/bin/" + name), \
                        patch.object(shell, "sha256", return_value="digest"), \
                        patch.object(shell.pipeline, "Pipeline") as build, \
                        patch.object(shell.device, "_stage_outputs", return_value=(work, output, {})), \
                        patch.object(shell.profile, "Machine") as vm:
                    build.return_value.ensure.side_effect = lambda stage: {"id": stage}
                    vm.return_value.__enter__.return_value = machine
                    if code:
                        with self.assertRaisesRegex(SafetyError, "exited with rc=1"):
                            shell.boot(work)
                    else:
                        shell.boot(work)
                    self.assertTrue(vm.call_args.kwargs["interactive"])
                    machine.session.quit.assert_called_once()
                    build.return_value.ensure.assert_any_call("shell-device")
                    build.return_value.ensure.assert_any_call("shell-enroll")
                self.assertEqual(list((work / "build").iterdir()), [])
