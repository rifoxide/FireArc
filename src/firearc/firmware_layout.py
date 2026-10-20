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

ROLE_VARIABLE_STORE = "uefi-variable-store"
ROLE_CBFS_CODE = "cbfs-code"
ROLE_FLASH_MAP = "flash-map"
ROLE_CONTAINER = "flash-image"
ROLE_PRESERVED = "preserved"

# vboot names its flash regions GBB, VBLOCK_A/B and RO_*/RW_* sections; the
# presence of any such region is a factual prerequisite for a protected-RO
# firmware-verification model (and none exists in the pinned Q35 layout).
VBOOT_AREA_PATTERN = re.compile(r"^(GBB|VBLOCK|RO_|RW_)")

FIXED_ROLES = {VARIABLE_STORE_AREA: ROLE_VARIABLE_STORE,
               FLASH_MAP_AREA: ROLE_FLASH_MAP,
               CBFS_AREA: ROLE_CBFS_CODE}


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


def classify(image, fmap):
    """Bind a parsed flash map to the region contract this harness relies on.

    Requires exactly one guest-writable SMMSTORE variable store, one COREBOOT
    CBFS code region and one FMAP descriptor, pairwise-disjoint child areas,
    and records remaining facts (container area, gaps, vboot regions, per-area
    digests and pristine erase state) without inventing guarantees.
    """
    if fmap["size"] != len(image):
        raise SafetyError("Flash map does not describe the whole image")
    areas = [dict(area) for area in sorted(fmap["areas"], key=lambda a: (a["offset"], a["name"]))]
    containers = [area for area in areas if area["offset"] == 0 and area["size"] == len(image)]
    if len(containers) > 1:
        raise SafetyError("Ambiguous whole-flash container areas")
    children = [area for area in areas if area not in containers]
    named = [area["name"] for area in children]
    for required in (VARIABLE_STORE_AREA, CBFS_AREA, FLASH_MAP_AREA):
        if named.count(required) != 1:
            raise SafetyError(f"Flash map must contain exactly one {required!r} area")
    reach = 0
    for area in children:  # sorted by offset: overlap detection is order-safe
        if area["offset"] < reach:
            raise SafetyError(f"Overlapping flash areas at offset 0x{area['offset']:x} "
                              f"({area['name']!r})")
        reach = area["offset"] + area["size"]
    gaps = []
    cursor = 0
    for area in children:
        if area["offset"] > cursor:
            gaps.append({"offset": cursor, "size": area["offset"] - cursor})
        cursor = max(cursor, area["offset"] + area["size"])
    if cursor < len(image):
        gaps.append({"offset": cursor, "size": len(image) - cursor})
    inventory = []
    for area in areas:
        region = image[area["offset"]:area["offset"] + area["size"]]
        area["role"] = ROLE_CONTAINER if area in containers else FIXED_ROLES.get(area["name"], ROLE_PRESERVED)
        area["sha256"] = hashlib.sha256(region).hexdigest()
        area["erased"] = region == b"\xff" * area["size"]
        area["cbfs_file_marker"] = region[:8] == b"LARCHIVE"
        inventory.append(area)
    variable_store = next(area for area in children if area["name"] == VARIABLE_STORE_AREA)
    return {
        "schema": 1,
        "rom_bytes": len(image),
        "fmap": {"offset": fmap["offset"],
                 "version": f"{fmap['version_major']}.{fmap['version_minor']}",
                 "base": fmap["base"], "size": fmap["size"], "name": fmap["name"]},
        "areas": inventory,
        "container_area": containers[0]["name"] if containers else None,
        "child_gaps": gaps,
        "vboot_regions": [area["name"] for area in children
                          if VBOOT_AREA_PATTERN.match(area["name"])],
        "permitted_writable": [VARIABLE_STORE_AREA],
        "boot_selection_state": "systemd-boot boot-selection state (default entry, "
                                "timeout, try counters) is stored in UEFI variables, "
                                "which this layout carries only in the SMMSTORE region; "
                                "no separate boot-state flash region exists",
        "variable_store": {"name": variable_store["name"], "offset": variable_store["offset"],
                           "size": variable_store["size"],
                           "erased_in_pristine_image": variable_store["erased"]},
    }


def write_confinement(pristine, booted, layout, *, permitted=VARIABLE_STORE_AREA):
    """Verify a booted flash copy changed nothing outside the variable store.

    Every mapped area other than `permitted`, plus every unmapped gap byte,
    must be identical to the pristine image; violations fail closed with the
    offending area and first differing offset.
    """
    if len(pristine) != len(booted):
        raise SafetyError("Booted flash image size differs from the pristine ROM")
    permitted_areas = [area for area in layout["areas"] if area["name"] == permitted]
    if len(permitted_areas) != 1:
        raise SafetyError(f"Expected exactly one permitted variable-store area {permitted!r}")
    changed, unchanged, digests = {}, [], {}
    for area in layout["areas"]:
        if area["role"] == ROLE_CONTAINER:
            continue
        start, size = area["offset"], area["size"]
        before, after = pristine[start:start + size], booted[start:start + size]
        digests[area["name"]] = hashlib.sha256(after).hexdigest()
        if before == after:
            unchanged.append(area["name"])
            continue
        if area["name"] != permitted:
            first = next(index for index in range(size) if before[index] != after[index])
            raise SafetyError(f"Firmware flash area {area['name']!r} was modified outside "
                              f"the permitted {permitted!r} variable store (first "
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
