"""Offline tests for firmware flash-map parsing, classification and write confinement."""

import inspect
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import device, firmware_layout
from firearc.integrity import SafetyError

IMAGE = 0x40000
AREAS = [("BIOS", 0, IMAGE), ("SMMSTORE", 0, 0x8000), ("FMAP", 0x8000, 0x400),
         ("BOOTSPLASH", 0x8400, 0x4000), ("COREBOOT", 0xC400, 0x40000 - 0xC400)]
GAP_IMAGE_AREAS = [area for area in AREAS if area[0] != "COREBOOT"] + \
    [("COREBOOT", 0xC400, 0x30000 - 0xC400)]


def fmap_bytes(areas, *, size=IMAGE, version=(1, 1), nareas=None, base=0xFF800000):
    header = bytearray(56)
    header[0:8] = b"__FMAP__"
    header[8], header[9] = version
    struct.pack_into("<Q", header, 10, base)
    struct.pack_into("<I", header, 18, size)
    header[22:28] = b"FLASH\x00"
    struct.pack_into("<H", header, 54, nareas if nareas is not None else len(areas))
    table = bytearray()
    for name, offset, area_size in areas:
        table += struct.pack("<II", offset, area_size)
        table += name.encode().ljust(32, b"\0")[:32] + struct.pack("<H", 0)
    return bytes(header) + bytes(table)


def synthetic_image(areas=AREAS, *, fmap_offset=0x8000, fmap=None):
    image = bytearray(b"\xff" * IMAGE)
    fmap = fmap if fmap is not None else fmap_bytes(areas)
    image[fmap_offset:fmap_offset + len(fmap)] = fmap
    image[0x8400:0x8400 + 28] = b"LARCHIVE" + b"\x00" * 20  # stale deleted-file marker
    coreboot = bytes(range(256)) * ((0x40000 - 0xC400) // 256 + 1)
    image[0xC400:0x40000] = coreboot[:0x40000 - 0xC400]
    return bytes(image)


def layout_of(image):
    return firmware_layout.classify(image, firmware_layout.parse_fmap(image))


class ParseTests(unittest.TestCase):
    def test_q35_shaped_layout_classifies_roles_and_records_facts(self):
        layout = layout_of(synthetic_image())
        self.assertEqual(layout["container_area"], "BIOS")
        self.assertEqual(layout["child_gaps"], [])
        self.assertEqual(layout["vboot_regions"], [])
        self.assertEqual(layout["permitted_writable"], ["SMMSTORE"])
        self.assertEqual(layout["variable_store"], {"name": "SMMSTORE", "offset": 0,
                                                    "size": 0x8000,
                                                    "erased_in_pristine_image": True})
        roles = {area["name"]: (area["role"], area["erased"], area["cbfs_file_marker"])
                 for area in layout["areas"]}
        self.assertEqual(roles["SMMSTORE"][0], "uefi-variable-store")
        self.assertEqual(roles["FMAP"][0], "flash-map")
        self.assertEqual(roles["COREBOOT"][0], "cbfs-code")
        self.assertEqual(roles["BOOTSPLASH"][0], "preserved")
        self.assertTrue(roles["BOOTSPLASH"][2])
        self.assertFalse(roles["COREBOOT"][2])
        self.assertTrue(roles["SMMSTORE"][1])
        self.assertFalse(roles["COREBOOT"][1])
        self.assertEqual([area["offset"] for area in layout["areas"]],
                         [0, 0, 0x8000, 0x8400, 0xC400])
        self.assertTrue(all(len(area["sha256"]) == 64 for area in layout["areas"]))

    def test_malformed_flash_maps_are_rejected(self):
        beyond = [("BIOS", 0, IMAGE), ("SMMSTORE", 0, 0x8000), ("FMAP", 0x8000, 0x400),
                  ("BOOTSPLASH", 0x8400, 0x4000), ("COREBOOT", 0xC400, IMAGE)]
        cases = {
            "no fmap": b"\xff" * IMAGE,
            "wrong version": synthetic_image(fmap=fmap_bytes(AREAS, version=(2, 0))),
            "size mismatch": synthetic_image(fmap=fmap_bytes(AREAS, size=IMAGE - 4096)),
            "no areas": synthetic_image(fmap=fmap_bytes(AREAS, nareas=0)),
            "too many areas": synthetic_image(fmap=fmap_bytes(AREAS, nareas=65)),
            "area beyond image": synthetic_image(areas=beyond, fmap=fmap_bytes(beyond)),
            "ambiguous duplicate map": (synthetic_image()[:0xC400] + fmap_bytes(AREAS)
                                        + synthetic_image()[0xC400 + 266:]),
        }
        for name, image in cases.items():
            with self.subTest(case=name), self.assertRaises(SafetyError):
                layout_of(image)

    def test_unprintable_and_unterminated_area_names_are_rejected(self):
        for poisoned in (b"A" * 32, b"AREAS\x80\x81"):
            fmap = bytearray(fmap_bytes(AREAS))
            field = 56 + 8  # first area-table entry, name field
            fmap[field:field + 32] = poisoned.ljust(32, b"\0")[:32]
            with self.subTest(name=poisoned[:6]), self.assertRaises(SafetyError):
                layout_of(synthetic_image(fmap=bytes(fmap)))

    def test_duplicate_area_names_are_rejected(self):
        areas = [("BIOS", 0, IMAGE), ("SMMSTORE", 0, 0x8000), ("FMAP", 0x8000, 0x400),
                 ("SMMSTORE", 0x8400, 0x4000), ("COREBOOT", 0xC400, IMAGE - 0xC400)]
        with self.assertRaises(SafetyError):
            layout_of(synthetic_image(areas=areas, fmap=fmap_bytes(areas)))

    def test_layout_requires_the_harness_region_contract(self):
        for missing in ("SMMSTORE", "COREBOOT", "FMAP"):
            areas = [area for area in AREAS if area[0] != missing]
            with self.subTest(missing=missing), self.assertRaises(SafetyError):
                layout_of(synthetic_image(areas=areas, fmap=fmap_bytes(areas)))
        overlap = [("BIOS", 0, IMAGE), ("SMMSTORE", 0, 0x8000), ("FMAP", 0x8000, 0x400),
                   ("BOOTSPLASH", 0x8400, 0x4400), ("COREBOOT", 0xC400, IMAGE - 0xC400)]
        with self.assertRaises(SafetyError):
            layout_of(synthetic_image(areas=overlap, fmap=fmap_bytes(overlap)))

    def test_unmapped_gaps_are_recorded_not_assumed_erased(self):
        layout = layout_of(synthetic_image(areas=GAP_IMAGE_AREAS,
                                           fmap=fmap_bytes(GAP_IMAGE_AREAS)))
        self.assertEqual(layout["child_gaps"], [{"offset": 0x30000, "size": 0x10000}])


class ConfinementTests(unittest.TestCase):
    def setUp(self):
        self.pristine = synthetic_image()
        self.layout = layout_of(self.pristine)

    def test_permitted_variable_store_writes_are_reported(self):
        booted = bytearray(self.pristine)
        booted[0x100:0x108] = b"\x00" * 8
        booted[0x2000:0x2010] = b"\x00" * 16
        report = firmware_layout.write_confinement(self.pristine, bytes(booted), self.layout)
        self.assertTrue(report["writes_observed"])
        self.assertEqual(report["permitted_area"], "SMMSTORE")
        changed = report["changed_areas"]["SMMSTORE"]
        self.assertEqual(changed["changed_blocks"], [0, 2])
        self.assertEqual(changed["changed_byte_count"], 24)
        self.assertEqual(changed["first_changed_offset"], 0x100)
        self.assertEqual(changed["last_changed_offset"], 0x200F)
        self.assertEqual(report["unchanged_areas"], ["FMAP", "BOOTSPLASH", "COREBOOT"])
        self.assertEqual(set(report["area_sha256_after_boot"]),
                         {"SMMSTORE", "FMAP", "BOOTSPLASH", "COREBOOT"})

    def test_unchanged_flash_records_no_writes(self):
        report = firmware_layout.write_confinement(self.pristine, self.pristine, self.layout)
        self.assertFalse(report["writes_observed"])
        self.assertEqual(report["changed_areas"], {})

    def test_writes_outside_the_variable_store_fail_closed(self):
        cases = {
            "COREBOOT code": 0xC400 + 0x123,
            "FMAP descriptor": 0x8000 + 4,
            "preserved area": 0x8400 + 0x50,
        }
        for name, offset in cases.items():
            booted = bytearray(self.pristine)
            booted[offset] ^= 0xFF
            with self.subTest(area=name), self.assertRaises(SafetyError) as raised:
                firmware_layout.write_confinement(self.pristine, bytes(booted), self.layout)
            self.assertIn("variable store", str(raised.exception))
            self.assertIn(hex(offset), str(raised.exception))

    def test_unmapped_gap_writes_fail_closed(self):
        image = synthetic_image(areas=GAP_IMAGE_AREAS, fmap=fmap_bytes(GAP_IMAGE_AREAS))
        layout = layout_of(image)
        booted = bytearray(image)
        booted[0x30010:0x30018] = b"\x00" * 8
        with self.assertRaises(SafetyError):
            firmware_layout.write_confinement(image, bytes(booted), layout)

    def test_size_mismatch_is_refused(self):
        with self.assertRaises(SafetyError):
            firmware_layout.write_confinement(self.pristine, self.pristine[:-1], self.layout)


class HarnessWiringTests(unittest.TestCase):
    def test_check_boot_enforces_flash_write_confinement(self):
        source = inspect.getsource(device.check_boot)
        self.assertIn("firmware_layout.classify", source)
        self.assertIn("write_confinement", source)
        self.assertIn("firmware_layout.VARIABLE_STORE_AREA", source)

    def test_real_built_rom_layout_when_present(self):
        state = ROOT / "build/state.json"
        rom = None
        if state.is_file():
            record = json.loads(state.read_text())["stages"].get("firmware-build")
            if record:
                candidate = ROOT / "build/firmware-build" / record["id"] / "output/coreboot.rom"
                rom = candidate if candidate.is_file() else None
        if rom is None:
            self.skipTest("firmware-build evidence not present in this checkout")
        image = rom.read_bytes()
        layout = layout_of(image)
        self.assertEqual(layout["rom_bytes"], device.FIRMWARE_BYTES)
        self.assertEqual(layout["container_area"], "BIOS")
        self.assertEqual(layout["variable_store"], {"name": "SMMSTORE", "offset": 0,
                                                    "size": 0x40000,
                                                    "erased_in_pristine_image": True})
        self.assertEqual(layout["fmap"]["offset"], 0x40000)
        self.assertEqual(layout["fmap"]["version"], "1.1")
        areas = {area["name"]: area for area in layout["areas"]}
        self.assertEqual(areas["FMAP"]["size"], 512)
        self.assertEqual((areas["COREBOOT"]["offset"], areas["COREBOOT"]["size"]),
                         (0x80200, 0x77FE00))
        self.assertTrue(areas["BOOTSPLASH"]["cbfs_file_marker"])
        self.assertEqual(layout["child_gaps"], [])
        self.assertEqual(layout["vboot_regions"], [])


if __name__ == "__main__":
    unittest.main()
