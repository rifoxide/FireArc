"""Execute the actual initrd shell library with synthetic block/tool backends.

No root, real device, EFI state or mapping is used. These are logic tests, not
evidence of a successful or securely rejected boot.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc.rootfs import render_initrd_authority
from firearc.initrd import check_modules, REQUIRED, FORBIDDEN
from firearc.integrity import SafetyError
from support import temporary

LIBRARY = ROOT / "images/initrd/99firearc-root/authority.sh"

BACKEND = r'''
import json, os, sys
from pathlib import Path
tool=Path(sys.argv[0]).name
args=sys.argv[1:]
mode=os.environ.get('FA_TEST_MODE','good')
with open(os.environ['FA_TEST_LOG'],'a') as log:
    log.write(json.dumps([tool,*args])+'\n')
if tool=='blkid':
    if '-p' in args:
        print('11111111-2222-3333-4444-555555555555'); sys.exit(0)
    label=next(x.split('=',1)[1] for x in args if x.startswith('PARTLABEL='))
    if mode=='missing' and 'HASH' in label: sys.exit(2)
    value={'FIREARC_ROOT_A':'/dev/vda2','FIREARC_HASH_A':'/dev/vda3','FIREARC_ROOT_B':'/dev/vda4','FIREARC_HASH_B':'/dev/vda5','FIREARC_ESP':'/dev/vda1'}[label]
    print(value)
    if mode=='duplicate' and 'ROOT' in label: print('/dev/vdb2')
elif tool=='lsblk':
    if 'TYPE' in args: print('disk' if args[-1]=='/dev/vda' or args[-1]=='/dev/vdb' else 'part')
    elif 'PKNAME' in args: print('vdb' if mode=='wrong-disk' and args[-1]=='/dev/vda3' else 'vda')
elif tool=='blockdev':
    if '--getsize64' in args:
        print(4096 if mode=='wrong-size' else 134217728 if args[-1] in ['/dev/vda3','/dev/vda5'] else 4294967296)
    elif '--getro' in args: print(0 if mode=='writable-mapping' else 1)
elif tool=='veritysetup':
    if args[0]=='verify' and mode=='corrupt': sys.exit(2)
    if args[0]=='open' and mode=='open-fails': sys.exit(1)
elif tool=='od':
    if '-j4' in args:
        value='11111111-2222-3333-4444-555555555555' if mode!='wrong-esp' else 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        if mode=='loader-uppercase': value=value.upper()
        print((value+chr(0)).encode('utf-16le').hex())
    else: os.execv('/usr/bin/od',['od',*args])
'''


class InitrdTests(unittest.TestCase):
    def authority(self, slot="A"):
        value = {"schema": 1, "format": 1, "algorithm": "sha256", "data_bytes": 4294967296,
                 "hash_bytes": 134217728, "data_blocks": 1048576, "data_block_size": 4096,
                 "hash_block_size": 4096, "hash_offset": 0, "salt": "a" * 64}
        value["root_hash"] = "b" * 64
        return render_initrd_authority(value, slot)

    def run_library(self, root, authority, mode="good", body="fa_select_devices && fa_check_boot_esp && fa_verify_and_open"):
        file = root / "authority"
        file.write_bytes(authority if isinstance(authority, bytes) else authority.encode())
        tools = root / "bin"
        tools.mkdir()
        for name in ["blkid", "lsblk", "blockdev", "veritysetup", "od"]:
            path = tools / name
            path.write_text("#!" + sys.executable + "\n" + BACKEND)
            path.chmod(0o700)
        log = root / "commands.jsonl"
        wrapper = '. "$1"; fa_load_authority "$2" || exit 71; fa_is_block() { return 0; }; fa_mapping_absent() { return 0; }; ' + body
        result = subprocess.run(["/bin/sh", "-c", wrapper, "test-initrd", str(LIBRARY), str(file)],
                                env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin", "FA_TEST_MODE": mode,
                                     "FA_TEST_LOG": str(log)}, capture_output=True, text=True, timeout=30)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def test_actual_shell_parser_accepts_complete_a_and_b_authority(self):
        for slot in ["A", "B"]:
            with self.subTest(slot=slot), temporary() as root:
                result, calls = self.run_library(root, self.authority(slot))
                self.assertEqual(result.returncode, 0, result.stderr)
                operations = [row[1] for row in calls if row[0] == "veritysetup"]
                self.assertEqual(operations, ["verify", "open"])
                self.assertLess(result.stdout.index("FIREARC_VERITY_PREVERIFY_OK"), result.stdout.index("FIREARC_VERITY_MAPPING_READY"))
                for row in calls:
                    if row[0] == "veritysetup":
                        self.assertIn("--no-superblock", row)
                        self.assertIn("--data-blocks=1048576", row)
                        # veritysetup open has no --readonly option; read-only
                        # mapping behavior is asserted after the open instead.
                        if row[1] == "open": self.assertNotIn("--readonly", row)

    def test_malformed_authority_is_denied_before_any_device_access(self):
        good = self.authority()
        malformed = [good + "slot=A\n", good.replace("data_blocks=1048576", "data_blocks=1"),
                     good.replace("slot=A", "slot=C"), good.replace("salt=" + "a" * 64, "salt=bad"),
                     good.replace("schema=1\n", ""), good + "root_device=/dev/vda2\n",
                     good + "x=$(touch_bad)\n", good + "\n", good.encode() + b"\0", "x=" + "a" * 5000]
        for value in malformed:
            with self.subTest(value=value[:50]), temporary() as root:
                result, calls = self.run_library(root, value)
                self.assertEqual(result.returncode, 71)
                self.assertEqual(calls, [])

    def test_ambiguous_missing_wrong_disk_geometry_or_boot_esp_never_reach_verity(self):
        for mode in ["missing", "duplicate", "wrong-disk", "wrong-size", "wrong-esp"]:
            with self.subTest(mode=mode), temporary() as root:
                result, calls = self.run_library(root, self.authority(), mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(row[0] == "veritysetup" for row in calls))

    def test_loader_supplied_uppercase_guid_is_normalized_not_matched_raw(self):
        # Boot loaders emit LoaderDevicePartUUID with uppercase hex; the exact
        # byte comparison must accept either whole-string GUID casing.
        with temporary() as root:
            result, calls = self.run_library(root, self.authority(), "loader-uppercase")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([row[1] for row in calls if row[0] == "veritysetup"], ["verify", "open"])

    def test_failed_preverification_never_opens_mapping(self):
        with temporary() as root:
            result, calls = self.run_library(root, self.authority(), "corrupt")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual([row[1] for row in calls if row[0] == "veritysetup"], ["verify"])
            self.assertNotIn("FIREARC_VERITY_MAPPING_READY", result.stdout)

    def test_preexisting_mapping_is_refused_without_reusing_or_closing_it(self):
        with temporary() as root:
            result, calls = self.run_library(root, self.authority(), body=
                'fa_mapping_absent() { return 1; }; fa_select_devices && fa_check_boot_esp && fa_verify_and_open')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(row[0] == "veritysetup" for row in calls))
            self.assertFalse(any(row[:2] == ["blockdev", "--setro"] for row in calls))

    def test_open_failure_and_writable_mapping_never_report_ready(self):
        for mode in ["open-fails", "writable-mapping"]:
            with self.subTest(mode=mode), temporary() as root:
                result, calls = self.run_library(root, self.authority(), mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("FIREARC_VERITY_MAPPING_READY", result.stdout)
                if mode == "writable-mapping": self.assertIn(["veritysetup", "close", "firearc-root"], calls)

    def test_mount_is_required_after_gate_and_has_no_raw_device_path(self):
        base = LIBRARY.parent
        mount = (base / "sysroot.mount").read_text()
        self.assertIn("Requires=firearc-verify-root.service", mount)
        self.assertIn("After=firearc-verify-root.service", mount)
        self.assertIn("What=/dev/mapper/firearc-root", mount)
        self.assertIn("Options=ro,noload", mount)
        self.assertIn("OnFailure=firearc-boot-failure.service", mount)
        self.assertNotIn("/dev/vda", mount)

    def test_missing_or_symlinked_authority_is_refused(self):
        with temporary() as root:
            missing = root / "absent"
            link = root / "link"
            target = root / "real"
            target.write_text(self.authority())
            link.symlink_to(target)
            for path in [missing, link]:
                result = subprocess.run(["/bin/sh", "-c", '. "$1"; fa_load_authority "$2"', "test", str(LIBRARY), str(path)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    def test_shell_syntax_and_no_emergency_or_automatic_mount_fallback(self):
        base = LIBRARY.parent
        for shell, name in [("/bin/sh", "authority.sh"), ("/bin/sh", "firearc-verify-root"), ("/bin/bash", "module-setup.sh")]:
            subprocess.run([shell, "-n", str(base / name)], check=True, capture_output=True)
        module = (base / "module-setup.sh").read_text()
        self.assertIn("systemd-gpt-auto-generator systemd-fstab-generator", module)
        self.assertIn("emergency.service rescue.service debug-shell.service", module)
        self.assertIn('chmod 0755 "$initdir/usr/lib/firearc/verify-root"', module)
        fail = (base / "firearc-boot-failure.service").read_text()
        self.assertIn("--force poweroff", fail)
        self.assertNotIn("sulogin", fail)

    def test_static_audit_requires_gate_and_rejects_each_alternate_module(self):
        good = "\n".join(sorted(REQUIRED))
        check_modules(good)
        for name in REQUIRED:
            with self.subTest(missing=name), self.assertRaises(SafetyError):
                check_modules("\n".join(REQUIRED - {name}))
        for name in FORBIDDEN:
            with self.subTest(forbidden=name), self.assertRaises(SafetyError):
                check_modules(good + "\n" + name)

    def test_cmdline_requires_matching_slot_mapper_and_no_debug_or_writable_override(self):
        good = "root=/dev/mapper/firearc-root rootfstype=ext4 rootflags=ro,noload ro rauc.slot=A rd.shell=0 rd.emergency=poweroff console=ttyS0"
        candidates = [(good, True), (good.replace("rauc.slot=A", "rauc.slot=B"), False),
                      (good.replace("root=/dev/mapper/firearc-root", "root=/dev/vda2"), False),
                      (good.replace(" ro ", " "), False), (good + " root=/dev/mapper/firearc-root", False)]
        candidates += [(good + " " + arg, False) for arg in ["rw", "rootflags=rw", "rd.shell=1", "rd.break", "init=/bin/sh", "rdinit=/bin/sh", "rd.systemd.unit=emergency.target", "systemd.debug_shell=1"]]
        for cmdline, expected in candidates:
            with self.subTest(cmdline=cmdline), temporary() as root:
                path = root / "cmdline"
                path.write_text(cmdline + "\n")
                result = subprocess.run(["/bin/sh", "-c", '. "$1"; FA_SLOT=A; fa_check_cmdline "$2"', "test", str(LIBRARY), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
