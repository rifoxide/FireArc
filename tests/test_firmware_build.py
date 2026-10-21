"""Offline firmware build-stage tests for configuration and pin binding."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import firmware_build
from firearc.inputs import load_lock
from firearc.integrity import SafetyError
from support import temporary

CONFIGURATION = (ROOT / firmware_build.CONFIG_PATH).read_text()
EDK2_PIN = {source["name"]: source["commit"]
            for source in load_lock(ROOT, "firmware-sources")["sources"]}["edk2"]


class FirmwareBuildTests(unittest.TestCase):
    def test_sdk_reference_accepts_only_pinned_digests(self):
        image, name, digest = firmware_build.sdk_reference({"sdk_image": "coreboot/coreboot-sdk@sha256:" + "a" * 64})
        self.assertEqual(name, "coreboot/coreboot-sdk")
        self.assertEqual(digest, "sha256:" + "a" * 64)
        self.assertEqual(image, "coreboot/coreboot-sdk@sha256:" + "a" * 64)
        for bad in [None, "coreboot/coreboot-sdk", "coreboot/coreboot-sdk@sha256:abc",
                    "coreboot/coreboot-sdk@Sha256:" + "a" * 64, "coreboot/Coreboot-sdk@sha256:" + "a" * 64,
                    "coreboot/coreboot sdk@sha256:" + "a" * 64]:
            with self.subTest(pin=bad), self.assertRaises(SafetyError):
                firmware_build.sdk_reference({"sdk_image": bad})

    def test_shipped_configuration_binds_to_the_pinned_edk2_revision(self):
        firmware_build.check_configuration(CONFIGURATION, EDK2_PIN)

    def test_unbound_or_unpinned_configurations_are_refused(self):
        cases = [CONFIGURATION.replace(EDK2_PIN, "0" * 40),
                 CONFIGURATION + "\nCONFIG_BUILD_IPXE=y\n",
                 CONFIGURATION + "\nCONFIG_EDK2_ENABLE_IPXE=y\n",
                 CONFIGURATION + '\nCONFIG_EDK2_BOOTSPLASH_FILE="3rdparty/dasharo-blobs/dasharo/bootsplash.bmp"\n']
        for case in cases:
            with self.subTest(case=case[-40:]), self.assertRaises(SafetyError):
                firmware_build.check_configuration(case, EDK2_PIN)

    def test_expected_rom_size_is_the_q35_board_flash_size(self):
        self.assertEqual(firmware_build.EXPECTED_ROM_SIZE, 0x800000)
        self.assertEqual(firmware_build.PAYLOAD_WORKSPACE.as_posix(),
                         "payloads/external/edk2/workspace/Dasharo")

    def test_shipped_configuration_names_a_valid_tracked_flash_layout(self):
        layout = firmware_build.fmd_reference(CONFIGURATION)
        self.assertEqual(layout, "q35-vboot.fmd")
        fmd = (ROOT / "images/firmware" / layout).read_text()
        firmware_build.check_fmd(layout, fmd)

    def test_flash_layout_validation_fails_closed(self):
        good = (ROOT / "images/firmware" / "q35-vboot.fmd").read_text()
        cases = {"path traversal": ("../../etc/passwd", good),
                 "not an fmd": ("layout.txt", good),
                 "missing SMMSTORE": ("q35-vboot.fmd", good.replace("SMMSTORE 0x40000", "STORE 0x40000")),
                 "wrong SMMSTORE size": ("q35-vboot.fmd", good.replace("SMMSTORE 0x40000", "SMMSTORE 0x30000")),
                 "missing RW_NVRAM": ("q35-vboot.fmd", good.replace("RW_NVRAM", "NVRAM")),
                 "missing WP_RO": ("q35-vboot.fmd", good.replace("WP_RO", "RO")),
                 "missing vblock": ("q35-vboot.fmd", good.replace("VBLOCK_A", "BLOCK_A")),
                 "missing GBB": ("q35-vboot.fmd", good.replace("GBB", "GB")),
                 "wrong image size": ("q35-vboot.fmd", good.replace("0x800000", "0x400000"))}
        for name, (layout, text) in cases.items():
            with self.subTest(case=name), self.assertRaises(SafetyError):
                firmware_build.check_fmd(layout, text)

    def test_fmd_reference_absent_for_default_layout(self):
        self.assertIsNone(firmware_build.fmd_reference("CONFIG_VBOOT=y\n"))
        self.assertEqual(firmware_build.fmd_reference('CONFIG_FMDFILE="q35-vboot.fmd"\n'),
                         "q35-vboot.fmd")

    def test_payload_description_files_follow_the_flash_definition(self):
        with temporary() as workspace:
            package = workspace / "DasharoPayloadPkg"
            package.mkdir(parents=True, mode=0o700)
            (package / "DasharoPayloadPkg.dsc").write_text(
                "[Defines]\n  FLASH_DEFINITION                    = DasharoPayloadPkg/DasharoPayloadPkg.fdf\n")
            (package / "DasharoPayloadPkg.fdf").write_bytes(b"fdf")
            dsc, fdf = firmware_build.payload_description_files(workspace)
            self.assertEqual(dsc.name, "DasharoPayloadPkg.dsc")
            self.assertEqual(fdf.read_bytes(), b"fdf")
            (package / "DasharoPayloadPkg.fdf").unlink()
            # A missing FDF (or a DSC without FLASH_DEFINITION) fails closed.
            with self.assertRaises((SafetyError, FileNotFoundError)):
                firmware_build.payload_description_files(workspace)
            (package / "DasharoPayloadPkg.dsc").write_text("[Defines]\n")
            with self.assertRaises(SafetyError):
                firmware_build.payload_description_files(workspace)


if __name__ == "__main__":
    unittest.main()
