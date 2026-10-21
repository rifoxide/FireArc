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

IMAGE = 0x100000
AREAS = [
    ("SI_BIOS", 0, IMAGE),
    ("RW_SECTION_A", 0, 0x30000),
    ("VBLOCK_A", 0, 0x4000),
    ("FW_MAIN_A", 0x4000, 0x2b000),
    ("RW_FWID_A", 0x2f000, 0x1000),
    ("SMMSTORE", 0x30000, 0x40000),
    ("RW_VPD", 0x70000, 0x1000),
    ("RW_NVRAM", 0x71000, 0x1000),
    ("BOOTSPLASH", 0x72000, 0xE000),
    ("WP_RO", 0x80000, 0x80000),
    ("FMAP", 0x80000, 0x400),
    ("RO_FRID", 0x80400, 0x100),
    ("RO_PADDING", 0x80500, 0x300),
    ("RO_VPD", 0x80800, 0x1000),
    ("GBB", 0x81800, 0x2000),
    ("COREBOOT", 0x83800, IMAGE - 0x83800),
]
GAP_IMAGE_AREAS = [area for area in AREAS if area[0] != "BOOTSPLASH"] + \
    [("BOOTSPLASH", 0x72000, 0x8000)]


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


def synthetic_image(areas=AREAS, *, fmap_offset=0x80000, fmap=None):
    image = bytearray(b"\xff" * IMAGE)
    fmap = fmap if fmap is not None else fmap_bytes(areas)
    image[fmap_offset:fmap_offset + len(fmap)] = fmap
    image[0x72000:0x72000 + 28] = b"LARCHIVE" + b"\x00" * 20  # stale deleted-file marker
    coreboot = bytes(range(256)) * ((IMAGE - 0x83800) // 256 + 1)
    image[0x83800:IMAGE] = coreboot[:IMAGE - 0x83800]
    return bytes(image)


def layout_of(image):
    return firmware_layout.classify(image, firmware_layout.parse_fmap(image))


class ParseTests(unittest.TestCase):
    def test_vboot_shaped_layout_classifies_roles_and_records_facts(self):
        layout = layout_of(synthetic_image())
        self.assertEqual(layout["container_area"], "SI_BIOS")
        self.assertEqual(layout["top_level_areas"],
                         ["RW_SECTION_A", "SMMSTORE", "RW_VPD", "RW_NVRAM",
                          "BOOTSPLASH", "WP_RO"])
        self.assertEqual(layout["protected_ro_areas"],
                         ["FMAP", "RO_FRID", "RO_PADDING", "RO_VPD", "GBB", "COREBOOT"])
        self.assertEqual(layout["rw_slot_areas"],
                         ["VBLOCK_A", "FW_MAIN_A", "RW_FWID_A"])
        self.assertEqual(layout["child_gaps"], [])
        self.assertEqual(len(layout["vboot_regions"]), 9)
        self.assertEqual(layout["permitted_writable"], ["SMMSTORE", "RW_NVRAM"])
        self.assertEqual(layout["variable_store"],
                         {"name": "SMMSTORE", "offset": 0x30000, "size": 0x40000,
                          "erased_in_pristine_image": True})
        roles = {area["name"]: (area["role"], area["erased"], area["cbfs_file_marker"])
                 for area in layout["areas"]}
        self.assertEqual(roles["SMMSTORE"][0], "uefi-variable-store")
        self.assertEqual(roles["FMAP"][0], "flash-map")
        self.assertEqual(roles["COREBOOT"][0], "cbfs-code")
        self.assertEqual(roles["GBB"][0], "vboot-root-key")
        self.assertEqual(roles["VBLOCK_A"][0], "vboot-verification-block")
        self.assertEqual(roles["RW_SECTION_A"][0], "vboot-rw-slot")
        self.assertEqual(roles["WP_RO"][0], "vboot-protected-ro")
        self.assertEqual(roles["RW_NVRAM"][0], "vboot-state")
        self.assertEqual(roles["BOOTSPLASH"][0], "preserved")
        self.assertTrue(roles["BOOTSPLASH"][2])
        self.assertFalse(roles["COREBOOT"][2])
        self.assertTrue(roles["SMMSTORE"][1])
        self.assertFalse(roles["COREBOOT"][1])
        self.assertTrue(all(len(area["sha256"]) == 64 for area in layout["areas"]))

    def test_unprintable_and_unterminated_area_names_are_rejected(self):
        for poisoned in (b"A" * 32, b"AREAS\x80\x81"):
            fmap = bytearray(fmap_bytes(AREAS))
            field = 56 + 8  # first area-table entry, name field
            fmap[field:field + 32] = poisoned.ljust(32, b"\0")[:32]
            with self.subTest(name=poisoned[:6]), self.assertRaises(SafetyError):
                layout_of(synthetic_image(fmap=bytes(fmap)))

    def test_duplicate_area_names_are_rejected(self):
        areas = [area for area in AREAS if area[0] != "RO_PADDING"] + \
            [("SMMSTORE", 0x80500, 0x300)]
        with self.assertRaises(SafetyError):
            layout_of(synthetic_image(areas=areas, fmap=fmap_bytes(areas)))

    def test_layout_requires_the_harness_region_contract(self):
        for missing in ("SMMSTORE", "COREBOOT", "FMAP", "GBB", "VBLOCK_A",
                        "FW_MAIN_A", "RW_NVRAM", "WP_RO", "RW_SECTION_A"):
            areas = [area for area in AREAS if area[0] != missing]
            with self.subTest(missing=missing), self.assertRaises(SafetyError):
                layout_of(synthetic_image(areas=areas, fmap=fmap_bytes(areas)))
        for name, misplaced in (("misaligned SMMSTORE", [("SMMSTORE", 0x31000, 0x40000)]
                                 if False else
                                 [area for area in AREAS if area[0] != "SMMSTORE"] +
                                 [("SMMSTORE", 0x30008, 0x40000 - 8)]),
                                ("short SMMSTORE",
                                 [area for area in AREAS if area[0] != "SMMSTORE"] +
                                 [("SMMSTORE", 0x30000, 0x30000)])):
            with self.subTest(case=name), self.assertRaises(SafetyError):
                layout_of(synthetic_image(areas=misplaced, fmap=fmap_bytes(misplaced)))
        # Overlapping RW areas fail closed.
        overlap = [area for area in AREAS if area[0] not in ("RW_FWID_A", "FW_MAIN_A")] + \
            [("FW_MAIN_A", 0x4000, 0x2b100), ("RW_FWID_A", 0x2f000, 0x1000)]
        with self.assertRaises(SafetyError):
            layout_of(synthetic_image(areas=overlap, fmap=fmap_bytes(overlap)))

    def test_unmapped_gaps_are_recorded_not_assumed_erased(self):
        layout = layout_of(synthetic_image(areas=GAP_IMAGE_AREAS,
                                           fmap=fmap_bytes(GAP_IMAGE_AREAS)))
        self.assertEqual(layout["child_gaps"], [{"offset": 0x7A000, "size": 0x6000}])


class ConfinementTests(unittest.TestCase):
    def setUp(self):
        self.pristine = synthetic_image()
        self.layout = layout_of(self.pristine)

    def test_permitted_writable_writes_are_reported(self):
        booted = bytearray(self.pristine)
        booted[0x30100:0x30108] = b"\x00" * 8          # inside SMMSTORE
        booted[0x32000:0x32010] = b"\x00" * 16         # inside SMMSTORE
        booted[0x71040:0x71048] = b"\x00" * 8          # inside RW_NVRAM (vboot VBNV)
        report = firmware_layout.write_confinement(self.pristine, bytes(booted), self.layout)
        self.assertTrue(report["writes_observed"])
        changed = report["changed_areas"]["SMMSTORE"]
        self.assertEqual(changed["changed_blocks"], [0, 2])
        self.assertEqual(changed["changed_byte_count"], 24)
        self.assertEqual(changed["first_changed_offset"], 0x30100)
        self.assertEqual(changed["last_changed_offset"], 0x3200F)
        self.assertIn("RW_NVRAM", report["changed_areas"])
        for keeper in ("FMAP", "GBB", "COREBOOT", "VBLOCK_A", "FW_MAIN_A"):
            self.assertIn(keeper, report["unchanged_areas"])

    def test_unchanged_flash_records_no_writes(self):
        report = firmware_layout.write_confinement(self.pristine, self.pristine, self.layout)
        self.assertFalse(report["writes_observed"])
        self.assertEqual(report["changed_areas"], {})

    def test_writes_outside_the_variable_store_fail_closed(self):
        cases = {
            "COREBOOT code": 0x83800 + 0x123,
            "FMAP descriptor": 0x80000 + 4,
            "preserved area": 0x72000 + 0x50,
            "GBB root key": 0x81800 + 0x20,
            "RW vblock": 0x4,
            "RW payload": 0x4000 + 0x100,
        }
        for name, offset in cases.items():
            booted = bytearray(self.pristine)
            booted[offset] ^= 0xFF
            with self.subTest(area=name), self.assertRaises(SafetyError) as raised:
                firmware_layout.write_confinement(self.pristine, bytes(booted), self.layout)
            self.assertIn("writable set", str(raised.exception))
            self.assertIn(hex(offset), str(raised.exception))

    def test_unmapped_gap_writes_fail_closed(self):
        image = synthetic_image(areas=GAP_IMAGE_AREAS, fmap=fmap_bytes(GAP_IMAGE_AREAS))
        layout = layout_of(image)
        booted = bytearray(image)
        booted[0x7A010:0x7A018] = b"\x00" * 8  # inside the recorded gap
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
        self.assertIn("firmware_layout.write_confinement", source)

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
        self.assertEqual(layout["schema"], 2)
        self.assertEqual(layout["container_area"], "SI_BIOS")
        self.assertEqual(layout["protected_ro_areas"],
                         ["FMAP", "RO_FRID", "RO_PADDING", "RO_VPD", "GBB", "COREBOOT"])
        self.assertEqual(layout["rw_slot_areas"],
                         ["VBLOCK_A", "FW_MAIN_A", "RW_FWID_A"])
        self.assertEqual(layout["permitted_writable"], ["SMMSTORE", "RW_NVRAM"])
        areas = {area["name"]: area for area in layout["areas"]}
        self.assertEqual((areas["SMMSTORE"]["offset"], areas["SMMSTORE"]["size"]),
                         (0x3C0000, 0x40000))
        self.assertTrue(areas["SMMSTORE"]["erased"])
        self.assertTrue(areas["RW_NVRAM"]["erased"])
        self.assertEqual(layout["fmap"]["offset"], 0x442000)
        self.assertEqual(layout["fmap"]["version"], "1.1")
        self.assertEqual(areas["GBB"]["size"], 0x1E000)
        self.assertEqual(areas["VBLOCK_A"]["size"], 0x10000)
