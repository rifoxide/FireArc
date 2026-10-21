"""Offline build of the pinned vboot `futility` signing tool.

Futility is compiled inside the pinned coreboot SDK container (networking
disabled) from the exact `3rdparty/vboot` sources the firmware acquisition
stage verified — never from a host package. The binary is exported as a
stage artifact whose manifest binds it to the pinned sources, SDK image and
build commands; the keys/signing stages consume it read-only by digest.
"""

from pathlib import Path
import os
import shutil

from . import firmware
from . import firmware_build
from .builder import logged
from .inputs import load_lock, validate_firmware_sources
from .integrity import identifier, private_directory, read_json, regular_file, sha256, write_json

BUILD_TIMEOUT = 3600


def build(root, sources_label, label, *, allow_network=False):
    """Compile futility from the pinned vboot sources; export the binary."""
    identifier(label)
    lock = load_lock(root, "firmware-sources")
    validate_firmware_sources(lock)
    records = firmware.verify(root, sources_label)
    sources = private_directory(Path(root) / "build/firmware") / sources_label / "sources"
    work = private_directory(Path(root) / "build/firmware-build", create=True) / label
    work.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    image = firmware_build.ensure_sdk(work, lock, allow_network=allow_network)

    # The tool builds from a private copy; the verified acquisition tree is
    # read-only evidence and is never built in or written to.
    tree = work / "vboot"
    shutil.copytree(sources / "coreboot/3rdparty/vboot", tree, symlinks=True)
    options = ["docker", "run", "--rm", "--network", "none", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=4g",
               "--user", f"{os.getuid()}:{os.getgid()}",
               "--env", "HOME=/tmp", "--env", "LC_ALL=C", "--env", "USE_FLASHROM=0",
               "--mount", f"type=bind,src={tree},dst=/vb",
               "--workdir", "/vb", image]
    logged(work, "make-futility", options + ["make", "--jobs="
           + str(os.cpu_count()), "futil"], timeout=BUILD_TIMEOUT)
    binary = tree / "build/futility/futility"
    if not binary.is_file() or binary.stat().st_size < 100_000:
        raise SafetyError("futility did not build into the expected binary")
    shutil.copyfile(binary, output / "futility")
    (output / "futility").chmod(0o555)  # bind-mounted into key containers as a tool
    logged(work, "futility-version", options
           + ["./build/futility/futility", "--help"], timeout=120)

    commands = {}
    for step_file in sorted(work.glob("*.command.json")):
        step = step_file.name[:-len(".command.json")]
        commands[step] = {"command_sha256": sha256(step_file),
                          "exit_sha256": sha256(step_file.with_name(step + ".exit.json"))}
    result = {"schema": 1, "passed": True,
              "sources": {name: {"commit": record["commit"], "tree": record["tree"]}
                          for name, record in records["sources"].items()},
              "sdk_image": lock["sdk_image"],
              "tool": {"path": "futility", "sha256": sha256(binary),
                       "bytes": binary.stat().st_size,
                       "upstream": "coreboot 3rdparty/vboot (pinned acquisition)"},
              "patches": {"applied": [],
                          "note": "Pinned upstream sources; the only build "
                                  "switch is USE_FLASHROM=0 (flashrom support "
                                  "is unused and unbuildable offline)"},
              "build_commands": commands}
    write_json(work / "result.json", result)
    return {"artifacts": {"futility": result["tool"]["sha256"]}}
