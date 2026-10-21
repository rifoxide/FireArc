"""vboot signing of the self-built firmware image (chain step 4).

Signs the firmware-build ROM's RW section with the development vboot keyset:
the root public key lands in the GBB, and VBLOCK_A carries the preamble
signed by the firmware data key (chained through the root-signed
firmware.keyblock). Runs in the pinned tools container with the pinned
futility binary; the keyset is mounted read-only from gitignored
secrets/vboot/. Fail-closed verification: the signed image must pass
`futility verify`, and every byte outside GBB, VBLOCK_A and RW_FWID_A must
be identical to the input ROM.
"""

from pathlib import Path
import os
import shutil

from . import builder, firmware_layout
from .builder import logged
from .integrity import (SafetyError, identifier, private_directory, read_json,
                        regular_file, sha256, write_json)

SIGNING_REGIONS = ("GBB", "VBLOCK_A", "RW_FWID_A")


def _futility(root, label):
    record = read_json(regular_file(Path(root) / "build", "state.json")) \
        .get("stages", {}).get("futility")
    if not record or record.get("id") != label:
        raise SafetyError("futility stage record does not match its label")
    return regular_file(Path(root) / "build/firmware-build" / label / "output", "futility")


def build(root, tools_label, firmware_label, futility_label, label):
    """Sign the firmware-build ROM; verify and confine the result."""
    identifier(label)
    rom_path = regular_file(Path(root) / "build/firmware-build" / firmware_label / "output",
                            "coreboot.rom")
    rom = rom_path.read_bytes()
    layout = firmware_layout.classify(rom, firmware_layout.parse_fmap(rom))
    areas = {area["name"]: area for area in layout["areas"]}
    for region in SIGNING_REGIONS:
        if region not in areas:
            raise SafetyError(f"vboot firmware image lacks the {region} region")
    futility = _futility(root, futility_label)
    tools_work = builder.parent(root) / identifier(tools_label)
    image = read_json(regular_file(tools_work, "export-result.json"))["image_id"]
    keys = Path(root) / "secrets/vboot"
    work = private_directory(Path(root) / "build/images", create=True) / label
    work.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    shutil.copyfile(rom_path, work / "unsigned.rom")

    options = builder.docker_args(image) + [
        "--env", "LC_ALL=C",
        "--mount", f"type=bind,src={futility},dst=/usr/local/bin/futility,readonly",
        # The signing container sees the keyset read-only and nothing else
        # from the secrets tree; the working ROM copy is its only output.
        "--mount", f"type=bind,src={keys},dst=/keys,readonly",
        "--mount", f"type=bind,src={work},dst=/work",
        image]
    logged(work, "sign", options + [
        "futility", "sign", "--type", "bios", "--keyset", "/keys",
        "/work/unsigned.rom"], timeout=600)
    # The coreboot build leaves the upstream vboot TEST devkeys root in the
    # GBB (no GBB keys are build inputs); signing installs our development
    # root key so the RW chain verifies against a key we custody. The HWID
    # names the project, not any physical device.
    logged(work, "set-gbb-rootkey", options + [
        "futility", "gbb_utility", "-s",
        "--rootkey=/keys/root_key.vbpubk",
        "--hwid=FIREARC_Q35_DEVELOPMENT", "/work/unsigned.rom"], timeout=300)
    verify = logged(work, "verify", options + [
        "futility", "verify", "--type", "bios", "/work/unsigned.rom"], timeout=300)
    if "Body verification succeeded" not in verify:
        raise SafetyError("futility did not report successful body verification")
    signed = (work / "unsigned.rom").read_bytes()
    if len(signed) != len(rom):
        raise SafetyError("Signed firmware image size differs from the input ROM")
    # Aggregate areas (SI_BIOS, WP_RO, RW_SECTION_A) contain the leaf regions;
    # confinement compares leaves only, plus the unmapped gaps.
    def spans_leaf(area):
        return any(other is not area
                   and other["offset"] >= area["offset"]
                   and other["offset"] + other["size"] <= area["offset"] + area["size"]
                   for other in areas.values())
    changed = []
    for name, area in sorted(areas.items()):
        if spans_leaf(area):
            continue
        before = rom[area["offset"]:area["offset"] + area["size"]]
        after = signed[area["offset"]:area["offset"] + area["size"]]
        if before != after:
            changed.append(name)
    if set(changed) - set(SIGNING_REGIONS):
        raise SafetyError(f"Signing modified regions outside {SIGNING_REGIONS}: {changed}")
    # Unmapped gap bytes must be untouched as well.
    for gap in layout["child_gaps"]:
        before = rom[gap["offset"]:gap["offset"] + gap["size"]]
        after = signed[gap["offset"]:gap["offset"] + gap["size"]]
        if before != after:
            raise SafetyError("Signing modified unmapped flash space")
    shutil.copyfile(work / "unsigned.rom", output / "signed-firmware.rom")
    manifest = read_json(regular_file(keys, "manifest.json"))
    result = {"schema": 1, "passed": True,
              "artifacts": {"signed-firmware.rom": sha256(output / "signed-firmware.rom")},
              "input": {"rom_sha256": sha256(rom_path), "firmware_label": firmware_label},
              "signed": {"rom_sha256": sha256(output / "signed-firmware.rom")},
              "changed_regions": changed,
              "keyset": {name: value["sha256"] for name, value in manifest["keys"].items()},
              "custody": "Development vboot keyset (secrets/vboot, ADR 0006 "
                         "custody rules); production firmware signing custody "
                         "is a separate owner decision"}
    write_json(work / "result.json", result)
    return {"artifacts": {"signed-firmware.rom": result["signed"]["rom_sha256"]}}
