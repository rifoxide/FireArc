"""Offline firmware flash-layout inspection and boot write confinement.

Parses the flash map (FMAP) of the self-built monolithic ROM, classifies every
region by the role this harness depends on (CBFS code, UEFI variable store,
flash-map descriptor, preserved areas), and archives the region inventory.
`check-boot` additionally compares each booted flash copy against the pristine
image: guest firmware writes must land only inside the declared SMMSTORE
variable store, and every byte of code, flash-map, preserved and unmapped
space must remain identical after the run.

This is layout and write-destination evidence only. QEMU pflash provides no
hardware write protection, so it is not a protected-RO/verified-boot model
and not authenticated-variable isolation.
"""

import hashlib
from pathlib import Path
import re
import struct

from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file, sha256,
    verify_file, write_json,
)

FMAP_MAGIC = b"__FMAP__"
FMAP_HEADER_BYTES = 56
FMAP_AREA_BYTES = 42
MAX_FMAP_AREAS = 64
BLOCK = 4096

VARIABLE_STORE_AREA = "SMMSTORE"
CBFS_AREA = "COREBOOT"
FLASH_MAP_AREA = "FMAP"
VBOOT_STATE_AREA = "RW_NVRAM"       # flash-backed vboot VBNV backup
VBOOT_RO_AREA = "WP_RO"             # host-anchored write-protected subtree
VBOOT_RW_SLOT_AREA = "RW_SECTION_A" # verified RW slot (VBLOCK_A + FW_MAIN_A)
VBOOT_ROOT_KEY_AREA = "GBB"
VBOOT_VBLOCK_AREA = "VBLOCK_A"

ROLE_VARIABLE_STORE = "uefi-variable-store"
ROLE_CBFS_CODE = "cbfs-code"
ROLE_FLASH_MAP = "flash-map"
ROLE_CONTAINER = "flash-image"
ROLE_PRESERVED = "preserved"
ROLE_VBOOT_STATE = "vboot-state"
ROLE_VBOOT_ROOT = "vboot-root-key"
ROLE_VBOOT_VBLOCK = "vboot-verification-block"
ROLE_VBOOT_SLOT = "vboot-rw-slot"
ROLE_VBOOT_RO = "vboot-protected-ro"

# vboot names its flash regions GBB, VBLOCK_A/B and RO_*/RW_* sections; the
# presence of any such region is a factual prerequisite for a protected-RO
# firmware-verification model (and none exists in the pinned Q35 layout).
VBOOT_AREA_PATTERN = re.compile(r"^(GBB|VBLOCK|RO_|RW_)")

def parse_fmap(image):
    """Locate and parse the single structurally valid FMAP in a flash image.

    The magic byte string also appears inside firmware debug strings, so every
    candidate is validated against the FMAP structure (version, image size
    equality, bounded/printable/unique area table) and exactly one valid map
    must result.
    """
    candidates = []
    start = 0
    while True:
        offset = image.find(FMAP_MAGIC, start)
        if offset == -1:
            break
        start = offset + 1
        fmap = _parse_candidate(image, offset)
        if fmap is not None:
            candidates.append(fmap)
    if not candidates:
        raise SafetyError("Flash image contains no structurally valid flash map")
    if len(candidates) > 1:
        raise SafetyError("Flash image contains multiple valid flash maps")
    return candidates[0]


def _parse_candidate(image, offset):
    if offset + FMAP_HEADER_BYTES > len(image):
        return None
    ver_major, ver_minor = image[offset + 8], image[offset + 9]
    if ver_major != 1 or ver_minor > 1:
        return None
    base, size = struct.unpack_from("<QI", image, offset + 10)
    if size != len(image):
        return None
    name = _area_name(image, offset + 22)
    if name is None:
        return None
    (nareas,) = struct.unpack_from("<H", image, offset + 54)
    if not 1 <= nareas <= MAX_FMAP_AREAS:
        return None
    if offset + FMAP_HEADER_BYTES + nareas * FMAP_AREA_BYTES > len(image):
        return None
    areas = []
    seen = set()
    for index in range(nareas):
        position = offset + FMAP_HEADER_BYTES + index * FMAP_AREA_BYTES
        area_offset, area_size = struct.unpack_from("<II", image, position)
        area_name = _area_name(image, position + 8)
        if area_name is None or area_name in seen:
            return None
        seen.add(area_name)
        if area_offset > len(image) or area_size > len(image) \
                or area_offset + area_size > len(image):
            return None
        (flags,) = struct.unpack_from("<H", image, position + 40)
        areas.append({"name": area_name, "offset": area_offset,
                      "size": area_size, "flags": flags})
    return {"offset": offset, "version_major": ver_major, "version_minor": ver_minor,
            "base": base, "size": size, "name": name, "areas": areas}


def _area_name(image, position):
    field = image[position:position + 32]
    if b"\0" not in field:
        return None
    encoded = field.split(b"\0", 1)[0]
    if not encoded or not all(33 <= byte <= 126 for byte in encoded):
        return None
    return encoded.decode()


def _children_of(areas, parent):
    """Areas strictly inside `parent` and not inside any smaller container."""
    inside = [a for a in areas
              if a is not parent
              and a["offset"] >= parent["offset"]
              and a["offset"] + a["size"] <= parent["offset"] + parent["size"]]
    # The immediate child set excludes areas nested inside other children.
    immediate = []
    for area in sorted(inside, key=lambda a: (a["size"], a["offset"]), reverse=True):
        if not any(other is not area and area["offset"] >= other["offset"]
                   and area["offset"] + area["size"] <= other["offset"] + other["size"]
                   for other in immediate):
            immediate.append(area)
    return sorted(immediate, key=lambda a: a["offset"])


def _check_disjoint(areas, label):
    reach = 0
    for area in sorted(areas, key=lambda a: a["offset"]):  # overlap-safe order
        if area["offset"] < reach:
            raise SafetyError(f"Overlapping flash areas at offset 0x{area['offset']:x} "
                              f"({area['name']!r} under {label!r})")
        reach = area["offset"] + area["size"]


def classify(image, fmap):
    """Bind a parsed flash map to the region contract this harness relies on.

    The vboot layout (the pinned configuration since chain step 4) is one
    SI_BIOS container with an RW side (verified slot, variable store, vboot
    VBNV backup state, preserved VPD) and one WP_RO subtree carrying the FMAP
    descriptor, GBB root key and recovery COREBOOT CBFS. Requires exactly one
    of each contracted region in its expected place, disjoint at every level,
    the SMMSTORE 64 KiB-aligned, and records remaining facts (gaps, per-area
    digests and pristine erase state) without inventing guarantees.
    """
    if fmap["size"] != len(image):
        raise SafetyError("Flash map does not describe the whole image")
    areas = [dict(area) for area in sorted(fmap["areas"], key=lambda a: (a["offset"], a["name"]))]
    containers = [area for area in areas if area["offset"] == 0 and area["size"] == len(image)]
    if len(containers) != 1:
        raise SafetyError("Flash map needs exactly one whole-flash container area")
    container = containers[0]
    top = _children_of(areas, container)
    _check_disjoint(top, container["name"])
    for required in (VARIABLE_STORE_AREA, VBOOT_STATE_AREA, VBOOT_RO_AREA,
                     VBOOT_RW_SLOT_AREA):
        if [a["name"] for a in top].count(required) != 1:
            raise SafetyError(f"Flash map must contain exactly one {required!r} area")
    ro = next(a for a in top if a["name"] == VBOOT_RO_AREA)
    ro_children = _children_of(areas, ro)
    _check_disjoint(ro_children, ro["name"])
    for required in (FLASH_MAP_AREA, CBFS_AREA, VBOOT_ROOT_KEY_AREA):
        if [a["name"] for a in ro_children].count(required) != 1:
            raise SafetyError(f"WP_RO must contain exactly one {required!r} area")
    slot = next(a for a in top if a["name"] == VBOOT_RW_SLOT_AREA)
    slot_children = _children_of(areas, slot)
    _check_disjoint(slot_children, slot["name"])
    for required in (VBOOT_VBLOCK_AREA, "FW_MAIN_A"):
        if [a["name"] for a in slot_children].count(required) != 1:
            raise SafetyError(f"RW_SECTION_A must contain exactly one {required!r} area")
    variable_store = next(a for a in top if a["name"] == VARIABLE_STORE_AREA)
    if variable_store["offset"] % 0x10000 or variable_store["size"] != 0x40000:
        raise SafetyError("SMMSTORE must be 64 KiB aligned and 256 KiB large")
    gaps = []
    cursor = 0
    for area in top:
        if area["offset"] > cursor:
            gaps.append({"offset": cursor, "size": area["offset"] - cursor})
        cursor = max(cursor, area["offset"] + area["size"])
    if cursor < len(image):
        gaps.append({"offset": cursor, "size": len(image) - cursor})
    roles = {VARIABLE_STORE_AREA: ROLE_VARIABLE_STORE, CBFS_AREA: ROLE_CBFS_CODE,
             FLASH_MAP_AREA: ROLE_FLASH_MAP, VBOOT_STATE_AREA: ROLE_VBOOT_STATE,
             VBOOT_ROOT_KEY_AREA: ROLE_VBOOT_ROOT, VBOOT_VBLOCK_AREA: ROLE_VBOOT_VBLOCK,
             VBOOT_RW_SLOT_AREA: ROLE_VBOOT_SLOT, VBOOT_RO_AREA: ROLE_VBOOT_RO,
             container["name"]: ROLE_CONTAINER}
    inventory = []
    for area in areas:
        region = image[area["offset"]:area["offset"] + area["size"]]
        area["role"] = roles.get(area["name"], ROLE_PRESERVED)
        area["sha256"] = hashlib.sha256(region).hexdigest()
        area["erased"] = region == b"\xff" * area["size"]
        area["cbfs_file_marker"] = region[:8] == b"LARCHIVE"
        inventory.append(area)
    return {
        "schema": 2,
        "rom_bytes": len(image),
        "fmap": {"offset": fmap["offset"],
                 "version": f"{fmap['version_major']}.{fmap['version_minor']}",
                 "base": fmap["base"], "size": fmap["size"], "name": fmap["name"]},
        "areas": inventory,
        "container_area": container["name"],
        "top_level_areas": [a["name"] for a in top],
        "protected_ro_areas": [a["name"] for a in ro_children],
        "rw_slot_areas": [a["name"] for a in slot_children],
        "child_gaps": gaps,
        "vboot_regions": [area["name"] for area in areas
                          if VBOOT_AREA_PATTERN.match(area["name"])],
        "permitted_writable": [VARIABLE_STORE_AREA, VBOOT_STATE_AREA],
        "boot_selection_state": "systemd-boot boot-selection state (default entry, "
                                "timeout, try counters) is stored in UEFI variables, "
                                "which this layout carries only in the SMMSTORE region; "
                                "vboot try-count/result state rides in the RW_NVRAM "
                                "flash-backed VBNV backup",
        "variable_store": {"name": variable_store["name"], "offset": variable_store["offset"],
                           "size": variable_store["size"],
                           "erased_in_pristine_image": variable_store["erased"]},
    }


def write_confinement(pristine, booted, layout, *,
                      permitted=(VARIABLE_STORE_AREA, VBOOT_STATE_AREA)):
    """Verify a booted flash copy changed nothing outside the writable set.

    Every mapped area other than the `permitted` set (UEFI variable store and
    the flash-backed vboot VBNV backup by default), plus every unmapped gap
    byte, must be identical to the pristine image; violations fail closed
    with the offending area and first differing offset.
    """
    if len(pristine) != len(booted):
        raise SafetyError("Booted flash image size differs from the pristine ROM")
    permitted = tuple(permitted)
    for name in permitted:
        if len([area for area in layout["areas"] if area["name"] == name]) != 1:
            raise SafetyError(f"Expected exactly one permitted writable area {name!r}")
    changed, unchanged, digests = {}, [], {}
    areas = layout["areas"]
    aggregates = {area["name"] for area in areas
                  if any(other is not area
                         and other["offset"] >= area["offset"]
                         and other["offset"] + other["size"] <= area["offset"] + area["size"]
                         for other in areas)}
    for area in areas:
        # Aggregate areas (SI_BIOS, WP_RO, RW_SECTION_A) shadow their leaves;
        # confinement compares leaf regions only.
        if area["name"] in aggregates:
            continue
        start, size = area["offset"], area["size"]
        before, after = pristine[start:start + size], booted[start:start + size]
        digests[area["name"]] = hashlib.sha256(after).hexdigest()
        if before == after:
            unchanged.append(area["name"])
            continue
        if area["name"] not in permitted:
            first = next(index for index in range(size) if before[index] != after[index])
            raise SafetyError(f"Firmware flash area {area['name']!r} was modified outside "
                              f"the permitted writable set {permitted!r} (first "
                              f"difference at image offset 0x{start + first:x})")
        blocks = []
        byte_count = 0
        first_byte = last_byte = None
        for position in range(0, size, BLOCK):
            window = position // BLOCK
            before_block = before[position:position + BLOCK]
            after_block = after[position:position + BLOCK]
            if before_block == after_block:
                continue
            blocks.append(window)
            for index, (left, right) in enumerate(zip(before_block, after_block)):
                if left != right:
                    byte_count += 1
                    absolute = start + position + index
                    if first_byte is None:
                        first_byte = absolute
                    last_byte = absolute
        changed[area["name"]] = {
            "changed_blocks": blocks, "changed_blocks_count": len(blocks),
            "changed_byte_count": byte_count,
            "first_changed_offset": first_byte, "last_changed_offset": last_byte}
    for gap in layout["child_gaps"]:
        start, size = gap["offset"], gap["size"]
        if pristine[start:start + size] != booted[start:start + size]:
            raise SafetyError(f"Flash bytes outside mapped FMAP areas were modified "
                              f"(gap at 0x{start:x})")
    return {"writes_observed": bool(changed), "permitted_area": permitted,
            "changed_areas": changed, "unchanged_areas": unchanged,
            "area_sha256_after_boot": digests}


def verified_rom(root, label):
    """The verified self-built ROM from a successful firmware-build stage."""
    source = private_directory(Path(root) / "build/firmware-build" / label)
    result = read_json(regular_file(source, "result.json"))
    if not result.get("passed") or not result.get("artifacts"):
        raise SafetyError("Expected a successful firmware-build stage")
    output = private_directory(source / "output")
    for name, digest in result["artifacts"].items():
        verify_file(regular_file(output, name), digest)
    rom = regular_file(output, "coreboot.rom")
    manifest = read_json(regular_file(output, "manifest.json"))
    if manifest.get("coreboot.rom", {}).get("sha256") != sha256(rom):
        raise SafetyError("Firmware manifest does not match the ROM artifact")
    return source, rom, manifest


def inspect(root, firmware_label, label):
    """Archive the flash-map inventory and region classification offline."""
    identifier(label)
    source, rom, _ = verified_rom(root, firmware_label)
    image = rom.read_bytes()
    layout = classify(image, parse_fmap(image))
    layout["rom_sha256"] = sha256(rom)
    layout["firmware_stage"] = source.name
    layout["firmware_manifest_sha256"] = sha256(regular_file(
        Path(root) / "build/firmware-build" / firmware_label / "output", "manifest.json"))
    layout["scope"] = ("Offline flash-map inspection of the self-built ROM; no boot, "
                       "no flash write protection and no security review")
    work = private_directory(Path(root) / "build/firmware-layout", create=True) / label
    work.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    write_json(output / "layout.json", layout)
    write_json(work / "result.json", {
        "passed": True,
        "artifacts": {"layout.json": sha256(output / "layout.json")},
        "rom_sha256": layout["rom_sha256"],
        "variable_store": layout["variable_store"],
        "vboot_regions": layout["vboot_regions"],
        "child_gaps": len(layout["child_gaps"]),
        "scope": "Offline flash-map inspection; no boot executed"})
    return {"passed": True, "evidence": str(work),
            "scope": "Flash layout archived and classified (offline)"}
