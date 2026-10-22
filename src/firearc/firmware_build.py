"""Offline construction of the QEMU Q35 coreboot/EDK II firmware image.

The pinned acquisition is re-verified, copied into a private build tree, and
compiled inside the pinned coreboot SDK container with networking disabled.
The EDK II payload is pre-seeded at the workspace path coreboot's build
expects, so no source is fetched during the build. Output is the monolithic
8 MiB ROM (CBFS payload plus SMMSTORE variable region per the board FMAP)
with a manifest binding it to the exact inputs.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from . import firmware
from .builder import logged
from .inputs import load_lock, validate_firmware_sources
from .integrity import SafetyError, identifier, private_directory, read_json, regular_file, sha256, write_json

CONFIG_PATH = "images/firmware/q35-coreboot.config"
EXPECTED_ROM_SIZE = 8 * 1024 * 1024
PAYLOAD_WORKSPACE = Path("payloads/external/edk2/workspace/Dasharo")
BUILD_TIMEOUT = 14400


def sdk_reference(lock):
    """The pinned SDK image reference and its digest components."""
    image = lock.get("sdk_image")
    if not isinstance(image, str):
        raise SafetyError("Missing pinned coreboot SDK image")
    name, separator, digest = image.partition("@")
    if not separator or not re.fullmatch(r"[a-z0-9][a-z0-9/.-]*", name) \
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SafetyError("Invalid pinned coreboot SDK image reference")
    return image, name, digest


def ensure_sdk(work, lock, *, allow_network):
    """The SDK image is present locally under its pinned digest."""
    image, name, digest = sdk_reference(lock)
    probe = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if probe.returncode:
        if not allow_network:
            raise SafetyError("Pinned coreboot SDK image absent; run just firmware-sources --online")
        # Cached source receipts can outlive Docker's image cache. Keep each
        # explicit reacquisition's logs distinct instead of overwriting evidence.
        logged(work, "pull-sdk-" + uuid.uuid4().hex[:12],
               ["docker", "pull", image], timeout=3600)
        probe = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
        if probe.returncode:
            raise SafetyError("Pinned coreboot SDK image unusable after acquisition")
    info = json.loads(probe.stdout)[0]
    if info.get("Architecture") != "amd64" or f"{name}@{digest}" not in info.get("RepoDigests", []):
        raise SafetyError("SDK image identity does not match its pinned digest")
    return image


def container_options(image, tree):
    command = ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
               "--user", f"{os.getuid()}:{os.getgid()}",
               "--env", "HOME=/tmp", "--env", "LC_ALL=C", "--env", "TZ=UTC",
               "--mount", f"type=bind,src={tree},dst=/home/coreboot/coreboot",
               "--workdir", "/home/coreboot/coreboot", image]
    return command


def check_configuration(text, edk2_pin):
    """The build configuration binds to the pinned sources without unpinned inputs."""
    if re.search(rf'CONFIG_EDK2_TAG_OR_REV="{edk2_pin}"', text) is None:
        raise SafetyError("Build configuration EDK II revision does not match the pinned sources")
    for forbidden in ("CONFIG_BUILD_IPXE=y", "CONFIG_EDK2_ENABLE_IPXE=y"):
        if forbidden in text:
            raise SafetyError(f"Build configuration enables an unpinned firmware input: {forbidden}")
    if re.search(r'CONFIG_EDK2_BOOTSPLASH_FILE="\S', text):
        raise SafetyError("Build configuration enables the declined dasharo-blobs bootsplash")


def fmd_reference(text):
    """The CONFIG_FMDFILE value, or None when the board default layout is used."""
    match = re.search(r'^CONFIG_FMDFILE="([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else None


def check_fmd(name, text):
    """A referenced flash layout must be a tracked file with the regions the
    chain depends on: UEFI variable persistence (SMMSTORE) and, under vboot,
    flash-backed VBNV (RW_NVRAM) and a protected RO region (WP_RO)."""
    if name != Path(name).name or not name.endswith(".fmd"):
        raise SafetyError(f"CONFIG_FMDFILE must name a tracked file, got {name!r}")
    for region in ("SMMSTORE", "RW_NVRAM", "WP_RO", "FW_MAIN_A", "VBLOCK_A", "GBB"):
        if not re.search(rf"\b{region}\b", text):
            raise SafetyError(f"Flash layout {name} lacks the required {region} region")
    if not re.search(r"\bSMMSTORE\s+0x40000\b", text):
        raise SafetyError(f"Flash layout {name} must keep the qualified 256 KiB SMMSTORE")
    if not re.search(r"\bFLASH@0x[0-9a-fA-F]+\s+0x800000\b", text):
        raise SafetyError(f"Flash layout {name} must describe the 8 MiB image")


def payload_description_files(workspace):
    """The payload DSC the build consumed and the FDF its FLASH_DEFINITION names."""
    dsc = regular_file(workspace, "DasharoPayloadPkg/DasharoPayloadPkg.dsc")
    match = re.search(r"^\s*FLASH_DEFINITION\s*=\s*(\S+)", dsc.read_text(errors="replace"),
                      re.MULTILINE)
    if not match:
        raise SafetyError("Payload DSC declares no FLASH_DEFINITION")
    fdf = regular_file(workspace, match.group(1))
    return dsc, fdf


def build(root, sources_label, label, *, allow_network=False):
    """Compile the pinned sources into coreboot.rom with recorded provenance."""
    identifier(label)
    lock = load_lock(root, "firmware-sources")
    validate_firmware_sources(lock)
    edk2_pin = {source["name"]: source["commit"] for source in lock["sources"]}["edk2"]
    configuration = regular_file(root, CONFIG_PATH)
    configuration_text = configuration.read_text()
    check_configuration(configuration_text, edk2_pin)
    layout = fmd_reference(configuration_text)
    fmd = None
    if layout is not None:
        # The flash layout is a reviewed project input: track it beside the
        # config, validate its regions, copy it into the tree at the exact
        # path the configuration references, and pin its digest in evidence.
        fmd = regular_file(root, (Path(CONFIG_PATH).parent / layout).as_posix())
        check_fmd(layout, fmd.read_text())
    records = firmware.verify(root, sources_label)
    work = private_directory(Path(root) / "build/firmware-build", create=True) / label
    work.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    image = ensure_sdk(work, lock, allow_network=allow_network)

    tree = work / "tree"
    shutil.copytree(private_directory(Path(root) / "build/firmware") / sources_label / "sources" / "coreboot",
                    tree, symlinks=True)
    workspace = tree / PAYLOAD_WORKSPACE
    workspace.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(private_directory(Path(root) / "build/firmware") / sources_label / "sources" / "edk2",
                    workspace, symlinks=True)
    (tree / ".config").write_bytes(configuration.read_bytes())
    if fmd is not None:
        shutil.copyfile(fmd, tree / layout)

    logged(work, "make-olddefconfig", container_options(image, tree) + ["make", "olddefconfig"], timeout=1200)
    logged(work, "make", container_options(image, tree) + ["make", f"--jobs={os.cpu_count()}"],
           timeout=BUILD_TIMEOUT)
    logged(work, "cbfstool-print",
           container_options(image, tree) + ["build/cbfstool", "build/coreboot.rom", "print"],
           timeout=300)
    logged(work, "toolchain", ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                               "--security-opt=no-new-privileges", image, "bash", "-c",
                               "for tool in /opt/xgcc/bin/x86_64-elf-gcc /opt/xgcc/bin/i386-elf-gcc"
                               " /opt/xgcc/bin/nasm /opt/xgcc/bin/iasl /usr/bin/gcc /usr/bin/python3"
                               " /usr/bin/make /usr/bin/git; do"
                               " printf '%s ' \"$tool\"; sha256sum \"$tool\" | cut -d' ' -f1;"
                               " \"$tool\" --version 2>/dev/null | head -1 || true; done"],
           timeout=300)

    rom = tree / "build/coreboot.rom"
    if not rom.is_file() or rom.stat().st_size != EXPECTED_ROM_SIZE:
        raise SafetyError(f"Built firmware is not the expected {EXPECTED_ROM_SIZE}-byte image")
    if "payload" not in (work / "cbfstool-print.stdout").read_text().lower():
        raise SafetyError("Built firmware CBFS inventory does not list a payload")
    shutil.copyfile(rom, output / "coreboot.rom")
    # Expanded build inputs for the evidence record: the full Kconfig the
    # build actually compiled (olddefconfig expands the reviewed fragment),
    # the payload description files it consumed, and digests of every build
    # command with its exit status. No patches are applied — pinned upstream
    # sources plus the reviewed config fragment are the only project inputs.
    expanded = work / "expanded.config"
    shutil.copyfile(tree / ".config", expanded)
    dsc, fdf = payload_description_files(workspace)
    payload_dir = work / "payload-description"
    payload_dir.mkdir(mode=0o700)
    shutil.copyfile(dsc, payload_dir / dsc.name)
    shutil.copyfile(fdf, payload_dir / fdf.name)
    commands = {}
    for step_file in sorted(work.glob("*.command.json")):
        step = step_file.name[:-len(".command.json")]
        commands[step] = {"command_sha256": sha256(step_file),
                          "exit_sha256": sha256(step_file.with_name(step + ".exit.json"))}
    manifest = {"schema": 1,
                "sources": {name: {"commit": record["commit"], "tree": record["tree"]}
                            for name, record in records["sources"].items()},
                "materialized": records["materialized"],
                "sdk_image": lock["sdk_image"],
                "configuration": {"path": CONFIG_PATH, "sha256": sha256(configuration)},
                "flash_layout": ({"path": f"images/firmware/{layout}", "sha256": sha256(fmd)}
                                 if fmd is not None else
                                 {"note": "board default layout"}),
                "expanded_configuration": {"bytes": expanded.stat().st_size,
                                           "sha256": sha256(expanded)},
                "payload_description": {
                    "dsc": {"path": dsc.relative_to(workspace).as_posix(),
                            "sha256": sha256(dsc)},
                    "fdf": {"path": fdf.relative_to(workspace).as_posix(),
                            "sha256": sha256(fdf)},
                },
                "patches": {"applied": [],
                            "note": "Pinned upstream sources; the reviewed config "
                                    "fragment (and flash layout file it names) are "
                                    "the only project inputs"},
                "build_commands": commands,
                "board": "emulation/qemu-q35",
                "coreboot.rom": {"sha256": sha256(output / "coreboot.rom"), "bytes": rom.stat().st_size},
                "toolchain_evidence": {"cbfstool_print": sha256(work / "cbfstool-print.stdout"),
                                       "toolchain": sha256(work / "toolchain.stdout")},
                "scope": "Built from pinned sources in the pinned SDK container with networking disabled; "
                         "not reviewed, enrolled or trusted"}
    write_json(output / "manifest.json", manifest)
    write_json(work / "result.json", {"passed": True,
                                      "artifacts": {"coreboot.rom": manifest["coreboot.rom"]["sha256"],
                                                    "manifest.json": sha256(output / "manifest.json")},
                                      "sources": len(manifest["sources"]),
                                      "scope": "Offline firmware compile; no security qualification"})
    return {"passed": True, "evidence": str(work), "rom": str(output / "coreboot.rom"),
            "rom_sha256": manifest["coreboot.rom"]["sha256"],
            "scope": "QEMU Q35 firmware built offline from the pinned closure; not trusted yet"}
