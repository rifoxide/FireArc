"""Synthetic, offline tests for Debian build-input authentication boundaries."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import builder
from firearc.integrity import SafetyError, relative_name, sha256, write_json
from support import temporary


class BuilderTests(unittest.TestCase):
    def test_debian_lock_and_versions(self):
        value = builder.lock(ROOT)
        self.assertEqual(value["snapshot"], "20261018T000000Z")
        self.assertIn("mkosi=25.3-7", value["tools"])
        self.assertIn("systemd-ukify=257.13-1~deb13u1", value["tools"])
        self.assertIn("systemd-boot-efi=257.13-1~deb13u1", value["tools"])
        self.assertIn("@sha256:", value["base_image"])
        self.assertTrue(all("=" in package for package in value["tools"]))
        self.assertEqual(value["package_count"], 231)

    def test_complete_dependency_closure_is_order_independent_and_detects_drift(self):
        first = {"repository": "debian", "filename": "pool/a.deb", "version": "1", "sha256": "a" * 64}
        second = {"repository": "debian-security", "filename": "pool/b.deb", "version": "2", "sha256": "b" * 64}
        self.assertEqual(builder.closure_digest([first, second]), builder.closure_digest([second, first]))
        self.assertNotEqual(builder.closure_digest([first, second]), builder.closure_digest([first, {**second, "version": "3"}]))

    def test_mkosi_tar_delta_sorts_only_tar_and_uses_stable_pax_names(self):
        script = (ROOT / "containers/builder/build.sh").read_text().split("python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        tar = '                "tar",\n                "--create",\n'
        cpio = '                "cpio",\n                "--create",\n'
        pax = '"--pax-option=delete=atime,delete=ctime,delete=mtime"'
        with temporary() as root:
            source = root / "archive.py"
            source.write_text(tar + pax + "\n" + cpio)
            with patch("pathlib.Path", return_value=source):
                exec(compile(script, "builder-mkosi-tar-delta", "exec"), {})
            updated = source.read_text()
            self.assertIn(tar + '                "--sort=name",\n', updated)
            self.assertIn("exthdr.name=%d/PaxHeaders/%f", updated)
            self.assertIn(cpio, updated)
            self.assertEqual(updated.count('"--sort=name"'), 1)
            for unexpected in [cpio, tar + tar + pax, tar]:
                source.write_text(unexpected)
                with patch("pathlib.Path", return_value=source), self.assertRaises(SystemExit):
                    exec(compile(script, "builder-mkosi-tar-delta", "exec"), {})

    def test_appliance_root_uses_exact_versions_and_matching_kernel(self):
        value = builder.root_lock(ROOT)
        self.assertEqual(value["profile"], "root")
        self.assertIn(value["kernel_package"] + "=" + value["kernel_version"], value["packages"])
        self.assertTrue(all("=" in package for package in value["packages"]))
        self.assertIn("dracut=106-6", value["packages"])
        self.assertIn("systemd-boot-efi=257.13-1~deb13u1", value["packages"])

    def test_appliance_lock_refuses_unpinned_or_mismatched_kernel(self):
        original = builder.root_lock(ROOT)
        for value in [{**original, "packages": [*original["packages"], "unversioned"]},
                      {**original, "kernel_version": "wrong"}, {**original, "kernel_release": "../../bad"}]:
            with self.subTest(value=value), patch.object(builder, "load_lock", return_value=value), self.assertRaises(SafetyError):
                builder.root_lock(ROOT)

    def test_appliance_recipe_is_explicit_preassembly_not_unsigned_boot(self):
        recipe = (ROOT / "images/root/mkosi.conf").read_text()
        self.assertIn("Bootable=no", recipe)
        self.assertIn("Autologin=no", recipe)
        self.assertIn("RootPassword=hashed:!", recipe)
        dracut = (ROOT / "images/root/skeleton/etc/dracut.conf.d/10-firearc-root.conf").read_text()
        self.assertIn('hostonly="no"', dracut)
        self.assertIn("rd.shell=0", dracut)
        self.assertIn("rd.emergency=poweroff", dracut)

    def test_unknown_package_profile_is_refused_before_acquisition(self):
        with self.assertRaises(SafetyError):
            builder.plan_packages(ROOT, "not-created", profile="unknown")

    def test_deb822_wrapped_fields_do_not_become_new_records(self):
        data = "Package: one\nVersion: 1\nDescription: short\n long: wrapped\n\nPackage: two\nVersion: 2\n"
        records = list(builder.deb822(data))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["Description"], "short\nlong: wrapped")

    def test_deb822_duplicates_and_malformed_fields_refused(self):
        for text in [" continuation\n", "Package: x\nPackage: y\n", "not-a-field\n"]:
            with self.subTest(text=text), self.assertRaises(SafetyError):
                list(builder.deb822(text))

    def test_signed_release_must_cover_exact_raw_index_bytes(self):
        with temporary() as root:
            path = root / "Packages"
            path.write_bytes(b"Package: x\nVersion: 1\n")
            release = f"Suite: stable\nSHA256:\n {sha256(path)} {path.stat().st_size} main/binary-amd64/Packages\n"
            builder.index_authorized(release, path)
            path.write_bytes(b"substituted package index")
            with self.assertRaises(SafetyError):
                builder.index_authorized(release, path)

    def test_unsigned_or_other_architecture_index_not_accepted(self):
        with temporary() as root:
            path = root / "Packages"
            path.write_bytes(b"x")
            for release in ["Suite: stable\n", f"SHA256:\n {sha256(path)} 1 main/binary-arm64/Packages\n"]:
                with self.subTest(release=release), self.assertRaises(SafetyError):
                    builder.index_authorized(release, path)

    def test_apt_configuration_keeps_authentication_enabled(self):
        text = builder.apt_config("/work/empty.status")
        self.assertIn('Acquire::Check-Valid-Until "false";', text)
        self.assertIn('Acquire::AllowInsecureRepositories "false";', text)
        self.assertIn('APT::Get::AllowUnauthenticated "false";', text)
        with self.assertRaises(SafetyError):
            builder.apt_config("/etc/shadow")

    def test_sources_are_explicit_signed_local_main_and_security(self):
        value = builder.lock(ROOT)
        text = builder.sources(value)
        self.assertIn("signed-by=/repository/archive-keyring.gpg", text)
        self.assertIn("file:/repository/debian trixie main", text)
        self.assertIn("file:/repository/debian-security trixie-security main", text)
        self.assertNotIn("trusted=yes", text.lower())
        self.assertNotIn("http:", text)
        with self.assertRaises(SafetyError):
            builder.sources(value, "/unreviewed/path")

    def test_plan_uri_is_matched_to_signed_index_not_apt_weak_digest(self):
        record = {"name": "x", "version": "1", "repository": "debian", "filename": "pool/main/x/x_1_all.deb",
                  "size": 123, "sha256": "a" * 64, "architecture": "all"}
        uri = "'file:/repository/debian/pool/main/x/x_1_all.deb' x_1_all.deb 123 MD5Sum:irrelevant\n"
        self.assertEqual(builder.parse_uris(uri, {"debian/" + record["filename"]: record}), [record])
        self.assertEqual(builder.parse_uris(uri.replace("MD5Sum:irrelevant", ""), {"debian/" + record["filename"]: record}), [record])
        for text in [uri.replace("file:/repository/", "https://untrusted.invalid/"), uri.replace(" 123 ", " 122 "),
                     uri + uri, uri.replace("pool/main/x/", "../../"), "No package URIs"]:
            with self.subTest(text=text), self.assertRaises(SafetyError):
                builder.parse_uris(text, {"debian/" + record["filename"]: record})

    def test_mkosi_sources_use_signed_deb822_stanzas(self):
        records = list(builder.deb822(builder.mkosi_sources(builder.lock(ROOT))))
        self.assertEqual(len(records), 2)
        self.assertEqual({row["Suites"] for row in records}, {"trixie", "trixie-security"})
        for row in records:
            self.assertEqual(row["Types"], "deb")
            self.assertTrue(row["URIs"].startswith("copy:/etc/firearc-build/repository/"))
            self.assertEqual(row["Signed-By"], "/etc/firearc-build/repository/archive-keyring.gpg")
            self.assertNotIn("Trusted", row)

    def test_planning_container_has_no_network_or_host_privileges(self):
        command = builder.docker_args("image")
        for value in ["--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user"]:
            self.assertIn(value, command)
        self.assertNotIn("--privileged", command)
        self.assertFalse(any("docker.sock" in item or "/dev/tpm" in item for item in command))

    def test_mkosi_build_uses_isolated_namespaces_without_privileged_docker(self):
        command = builder.mkosi_command(Path("/tools"), Path("/work"), build=True)
        for option in ["--user", "--map-root-user", "--map-auto", "--net", "--mount", "--pid", "--fork"]:
            self.assertIn(option, command)
        self.assertEqual(command[0], "unshare")
        self.assertEqual(command[-1], "build")
        self.assertNotIn("docker", command)
        self.assertNotIn("sudo", command)
        self.assertNotIn("unshare", builder.mkosi_command(Path("/tools"), Path("/work"), build=False))

    def test_network_acquisition_requires_explicit_flag(self):
        with self.assertRaises(SafetyError):
            builder.fetch_packages(ROOT, "never-created", allow_network=False)

    def test_download_checks_sha256_size_and_retains_failed_partial(self):
        payload = b"synthetic binary package"
        record = {"repository": "debian", "filename": "pool/main/x/x.deb", "size": len(payload),
                  "sha256": hashlib.sha256(payload).hexdigest()}
        def response(url):
            stream = io.BytesIO(payload)
            stream.url = url
            return stream
        with temporary() as root:
            destination = root / "x.deb"
            with patch.object(builder.urllib.request, "urlopen", return_value=response("https://snapshot.debian.org/package")):
                builder.download_package({"snapshot": "20261018T000000Z"}, record, destination)
            self.assertEqual(destination.read_bytes(), payload)
            with self.assertRaises(SafetyError):
                builder.download_package({"snapshot": "20261018T000000Z"}, {**record, "sha256": "b" * 64}, destination)
            other = root / "bad.deb"
            with patch.object(builder.urllib.request, "urlopen", return_value=response("https://snapshot.debian.org/package")), \
                    self.assertRaises(SafetyError):
                builder.download_package({"snapshot": "20261018T000000Z"}, {**record, "size": len(payload) - 1}, other)
            self.assertFalse(other.exists())
            self.assertTrue(list(root.glob("bad.deb.partial-*")))

    def test_download_rejects_https_downgrade(self):
        stream = io.BytesIO(b"x")
        stream.url = "http://untrusted.invalid/package"
        record = {"repository": "debian", "filename": "pool/main/x/x.deb", "size": 1, "sha256": "a" * 64}
        with temporary() as root, patch.object(builder.urllib.request, "urlopen", return_value=stream), self.assertRaises(SafetyError):
            builder.download_package({"snapshot": "20261018T000000Z"}, record, root / "x.deb")

    def test_linux_inventory_allows_literal_systemd_escape_but_input_paths_do_not(self):
        name = r"usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice"
        with self.assertRaises(SafetyError):
            relative_name(name)
        with temporary() as root:
            path = root / name
            path.parent.mkdir(parents=True)
            path.write_text("public unit")
            inventory = builder.tree_inventory(root)
            self.assertEqual(inventory[name]["sha256"], sha256(path))
            self.assertEqual(inventory[name]["type"], "file")

    def test_inventory_does_not_follow_symlink_to_external_directory(self):
        with temporary() as root, temporary() as outside:
            (outside / "not-an-input").write_text("must not be inventoried")
            (root / "link").symlink_to(outside, target_is_directory=True)
            inventory = builder.tree_inventory(root)
            self.assertEqual(set(inventory), {"link"})
            self.assertEqual(inventory["link"]["target"], str(outside))

    def smoke_tar(self, path, changes=None):
        files = {"etc/shadow": "root:!:1::::::\n", "etc/machine-id": "uninitialized\n",
                 "var/lib/dpkg/status": "Package: systemd\nVersion: 257.13-1~deb13u1\nStatus: install ok installed\n"}
        files.update(changes or {})
        with tarfile.open(path, "w:") as archive:
            for name, value in files.items():
                payload = value.encode()
                member = tarfile.TarInfo("./" + name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    def test_smoke_tar_selected_invariants_without_extraction(self):
        with temporary() as root:
            path = root / "smoke.tar"
            self.smoke_tar(path)
            report = builder.inspect_root_basics(path)
            self.assertTrue(report["root_locked"])
            self.assertTrue(report["machine_identity_unprovisioned"])
            self.assertEqual(report["systemd_version"], "257.13-1~deb13u1")
            self.assertFalse((root / "etc").exists())

    def test_smoke_tar_refuses_unlocked_identity_sources_version_and_traversal(self):
        changes = [{"etc/shadow": "root::1::::::\n"}, {"etc/machine-id": "a" * 32},
                   {"var/lib/dpkg/status": "Package: systemd\nVersion: 262\nStatus: install ok installed\n"},
                   {"etc/apt/sources.list": "unwanted mirror"}, {"etc/ssh/ssh_host_rsa_key": "unwanted identity"},
                   {"../../outside": "unwanted path"}]
        for change in changes:
            with self.subTest(change=change), temporary() as root:
                path = root / "smoke.tar"
                self.smoke_tar(path, change)
                with self.assertRaises(SafetyError):
                    builder.inspect_root_basics(path)

    def appliance_tar(self, path, changes=None):
        lock = builder.root_lock(ROOT)
        release = lock["kernel_release"]
        files = {"etc/shadow": b"root:!:1::::::\n", "etc/machine-id": b"uninitialized\n",
                 "var/lib/dpkg/status": "\n\n".join(
                     f"Package: {p.split('=', 1)[0]}\nVersion: {p.split('=', 1)[1]}\nStatus: install ok installed"
                     for p in lock["packages"]).encode(),
                 "boot/config-" + release: "\n".join(f"{option}=y" for option in [
                     "CONFIG_EFI", "CONFIG_EFI_STUB", "CONFIG_BLK_DEV_DM", "CONFIG_DM_VERITY",
                     "CONFIG_DM_CRYPT", "CONFIG_TCG_TPM", "CONFIG_EXT4_FS", "CONFIG_SQUASHFS"]).encode(),
                 "boot/vmlinuz-" + release: b"MZsynthetic-kernel",
                 "boot/initrd.img-" + release: b"\x1f\x8bsynthetic-header-only",
                 "usr/lib/systemd/boot/efi/linuxx64.efi.stub": b"MZsynthetic-stub",
                 "usr/lib/systemd/boot/efi/systemd-bootx64.efi": b"MZsynthetic-boot"}
        files.update(changes or {})
        with tarfile.open(path, "w:") as archive:
            for name, payload in files.items():
                if payload is None:
                    continue
                member = tarfile.TarInfo("./" + name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return lock

    def test_appliance_artifact_checks_do_not_claim_boot_qualification(self):
        with temporary() as root:
            path = root / "root.tar"
            lock = self.appliance_tar(path)
            report = builder.inspect_root_tar(path, lock)
            self.assertFalse(report["boot_chain_qualified"])
            self.assertEqual(report["requested_packages_verified"], len(lock["packages"]))
            self.assertEqual(len(report["efi_sha256"]), 2)

    def test_appliance_missing_kernel_feature_and_initrd_are_refused(self):
        release = builder.root_lock(ROOT)["kernel_release"]
        for changes in [{"boot/config-" + release: b"CONFIG_EFI=y\n"},
                        {"boot/initrd.img-" + release: None},
                        {"usr/lib/systemd/boot/efi/linuxx64.efi.stub": b"wrong header"}]:
            with self.subTest(changes=changes), temporary() as root:
                path = root / "root.tar"
                lock = self.appliance_tar(path, changes)
                with self.assertRaises(SafetyError):
                    builder.inspect_root_tar(path, lock)


if __name__ == "__main__":
    unittest.main()
