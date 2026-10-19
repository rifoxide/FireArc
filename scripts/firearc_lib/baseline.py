"""Persistent, headless EXP-029 regression fixtures, not a production appliance.

No host mounts, host disks, network, private signing keys or reference scripts.
Only explicit new-device creation copies flash. Subsequent runs keep its state.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import time
import uuid

from .inputs import imported_path, tool_paths, verify_import
from .integrity import (
    SafetyError, identifier, private_directory, read_json, regular_file,
    safe_qemu_path, sha256, write_json,
)
from .qmp import request


SCENARIOS = ("good", "data-executable", "data-unused", "hash-tree", "replacement-pair", "unsigned", "wrong", "tampered")
FIRMWARE_NEGATIVES = {"unsigned", "wrong", "tampered"}


def profile(root):
    value = read_json(regular_file(root, "lab/q35/research.json"))
    if value.get("schema") != 1 or value.get("profile") != "exp029-research":
        raise SafetyError("Unknown laboratory profile")
    if value["network"] != "none" or value["accelerator"] != "tcg":
        raise SafetyError("Baseline requires isolated networking and the TCG profile")
    return value


def state_parent(root):
    run = private_directory(Path(root) / "run", create=True)
    return private_directory(run / "devices", create=True)


def device_path(root, device):
    identifier(device)
    # Starting an absent device must not create even its parent directories.
    run = private_directory(Path(root) / "run")
    parent = private_directory(run / "devices")
    return private_directory(parent / device)


@contextmanager
def device_lock(path):
    lock = Path(path) / ".lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise SafetyError("Unsafe device lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SafetyError("Device is already in use") from error
        yield
    finally:
        os.close(descriptor)


def run_logged(work, name, command):
    write_json(work / (name + ".command.json"), command)
    with (work / (name + ".stdout")).open("xb") as output, (work / (name + ".stderr")).open("xb") as error:
        result = subprocess.run(command, stdout=output, stderr=error, timeout=120)
    write_json(work / (name + ".exit.json"), {"returncode": result.returncode})
    if result.returncode:
        raise SafetyError(f"{name} failed ({result.returncode}); inspect {work}")
    return (work / (name + ".stdout")).read_text()


def overlay(work, name, source, destination, qemu_img):
    run_logged(work, name, [qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", safe_qemu_path(source), safe_qemu_path(destination)])


def socket_space(root):
    parent = private_directory(Path(root) / "run/sockets", create=True)
    path = parent / uuid.uuid4().hex[:12]
    path.mkdir(mode=0o700)
    if len(str(path / "qmp.sock").encode()) > 103:
        raise SafetyError("Workspace path too long for local Unix control sockets")
    return path


def tpm_state(path):
    """Metadata only; refuse absent state instead of silently creating a new TPM."""
    directory = private_directory(Path(path) / "tpm")
    state = regular_file(directory, "tpm2-00.permall")
    info = state.lstat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size == 0 or info.st_nlink != 1:
        raise SafetyError("TPM persistent state is empty or has unsafe ownership/permissions")
    return state


def swtpm_command(tool, path, sockets, *, initialize=False):
    flags = "not-need-init,startup-clear" if initialize else "not-need-init"
    return [tool, "socket", "--tpm2", "--tpmstate", "dir=" + safe_qemu_path(path / "tpm") + ",mode=0600,lock",
            "--ctrl", "type=unixio,path=" + safe_qemu_path(sockets / "tpm.sock") + ",mode=0600",
            "--flags", flags, "--seccomp", "action=kill"]


def initialize_tpm(root, path, tool):
    # Only called by explicit baseline-new, never by an ordinary boot/retry.
    private_directory(path / "tpm", create=True)
    sockets = socket_space(root)
    command = swtpm_command(tool, path, sockets, initialize=True)
    write_json(path / "initialize-tpm.command.json", command)
    process = None
    with (path / "initialize-tpm.log").open("xb") as log:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            wait_socket(sockets / "tpm.sock", process)
            deadline = time.monotonic() + 10
            while True:
                try:
                    tpm_state(path)
                    break
                except (FileNotFoundError, SafetyError):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise SafetyError("Explicit new-device TPM initialization did not persist state")
                    time.sleep(0.05)
        finally:
            stop_owned(process)
    tpm_state(path)


def new_device(root, device, *, tpm=False):
    identifier(device)
    config = profile(root)
    hashes = verify_import(root)
    tools = tool_paths(root, ["qemu-img", "swtpm"] if tpm else ["qemu-img"])
    base = imported_path(root)
    parent = state_parent(root)
    path = parent / device
    # Exclusive creation: no reset, overwrite or 'repair' of an existing device.
    path.mkdir(mode=0o700)
    (path / "boots").mkdir(mode=0o700)
    shutil.copyfile(base / "coreboot.rom", path / "pflash.raw")
    (path / "pflash.raw").chmod(0o600)
    if (path / "pflash.raw").stat().st_size != config["flash_bytes"]:
        raise SafetyError("Unexpected coreboot flash size")
    for name, source in (("root", "root.ext4"), ("hash", "root.verity")):
        overlay(path, "create-" + name, base / source, path / (name + ".qcow2"), tools["qemu-img"])
    if tpm:
        initialize_tpm(root, path, tools["swtpm"])
    write_json(path / "device.json", {
        "schema": 1, "id": device, "profile": config["profile"], "tpm": tpm,
        "tpm_initialized_during_creation": tpm,
        "created_at": datetime.now(timezone.utc).isoformat(), "input_hashes": hashes,
        "scope": "Persistent EXP-029 regression fixture; no encrypted-data or hardware-TPM provisioning",
    })
    return {"created": str(path), "tpm": tpm, "scope": "Research fixture only"}


def clean_console(raw):
    text = raw.decode(errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", text)


def database_hash(certificate):
    # Match the pinned EDK II X.509 signature list including its owner GUID.
    # This serializes public bytes, not a substitute for X.509 verification.
    if not 0 < len(certificate) <= 16384:
        raise SafetyError("Invalid public certificate size")
    x509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le
    owner = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c").bytes_le
    payload = x509 + struct.pack("<III", 44 + len(certificate), 0, 16 + len(certificate)) + owner + certificate
    return hashlib.sha256(payload).hexdigest()


def validate_console(text, scenario, metadata, expected_db, exit_code):
    """Do not infer boot acceptance from a readiness string alone."""
    if scenario in FIRMWARE_NEGATIVES:
        if ("Secure Boot is enabled." not in text or "Access Denied" not in text
                or "Linux version " in text or "FIREARC_ROOT_" in text):
            raise SafetyError("Firmware denial before kernel execution was not demonstrated")
        return {"firmware_denial_verified": True, "host_stopped_after_denial": True}
    if exit_code != 0 or "Power down" not in text:
        raise SafetyError("Guest did not power off cleanly")
    if scenario != "good":
        if ("FIREARC_ROOT_REJECTED stage=full-scan" not in text
                or "FIREARC_ROOT_MAPPING_OK" in text or "FIREARC_ROOT_READY" in text):
            raise SafetyError("Root corruption was not refused before mapping/readiness")
        return {"full_scan_rejection_verified": True}
    required = [
        "FIREARC_ROOT_FULL_SCAN_OK hash=" + metadata["root_hash"] + " blocks=" + str(metadata["data_blocks"]),
        "FIREARC_ROOT_MAPPING_OK", "FIREARC_SECUREBOOT_1_SETUPMODE_0", "FIREARC_DB_SHA256=" + expected_db,
        "FIREARC_ROOT_REPORT_BEGIN", "FIREARC_ROOT_READY", "FIREARC_ROOT_REPORT_END",
        "none [integrity] confidentiality", "mode:        readonly", "status:      verified",
    ]
    if any(item not in text for item in required) or "FIREARC_ROOT_REJECTED" in text:
        raise SafetyError("Incomplete Secure Boot/verified-root acceptance evidence")
    if not re.search(r"^ID=debian$", text, re.M) or not re.search(r'^VERSION_ID="?13"?$', text, re.M):
        raise SafetyError("Unexpected root distribution")
    if metadata["cmdline"] not in text.splitlines():
        raise SafetyError("Exact signed command line absent from userspace report")
    if not re.search(r"^/dev/mapper/firearc-root ext4 ro,[^\n]+$", text, re.M):
        raise SafetyError("Read-only root mount not evidenced")
    table = (r"^0 " + str(metadata["data_bytes"] // 512) + r" verity 1 \d+:\d+ \d+:\d+ 4096 4096 "
             + str(metadata["data_blocks"]) + " 0 sha256 " + metadata["root_hash"] + " " + metadata["salt"] + r"$")
    if not re.search(table, text, re.M):
        raise SafetyError("Expected live dm-verity geometry/digest absent")
    ids = re.findall(r"^FIREARC_BOOT_ID=([0-9a-f-]{36})$", text, re.M)
    if len(ids) != 1:
        raise SafetyError("Expected one kernel boot identity")
    uuid.UUID(ids[0])
    if not (text.index(required[0]) < text.index(required[1]) < text.index("FIREARC_ROOT_READY")):
        raise SafetyError("Invalid root-verification stage order")
    return {"boot_id": ids[0], "secure_boot_verified": True, "full_scan_verified": True,
            "readonly_verity_verified": True, "exact_db_verified": True}


def validate_tpm_console(text):
    if not re.search(r"tpm_tis .*: 2\.0 TPM \(", text):
        raise SafetyError("Attached software TPM was not detected as TPM 2.0 in the guest")
    return {"tpm2_guest_detected": True,
            "tpm_duplicate_probe_warning": bool(re.search(r"tpm_tis .*: (?:error -EBUSY|probe with driver .* failed)", text)),
            "tpm_policy_qualified": False}


def boot_command(config, tools, flash, root_disk, hash_disk, media, work, sockets, *, tpm=False):
    command = [tools["qemu-system-x86_64"], "-machine", config["machine"], "-accel", config["accelerator"],
               "-cpu", config["cpu"], "-smp", str(config["cpus"]), "-m", str(config["memory_mib"]) + "M",
               "-nodefaults", "-no-user-config", "-device", "VGA", "-display", "none", "-nic", "none",
               "-drive", "if=pflash,format=raw,file=" + safe_qemu_path(flash),
               "-drive", "if=none,id=rootdisk,format=qcow2,file=" + safe_qemu_path(root_disk),
               "-device", "ide-hd,drive=rootdisk,bus=ide.0,serial=FIREARC_ROOT_A,bootindex=2",
               "-drive", "if=none,id=hashdisk,format=qcow2,file=" + safe_qemu_path(hash_disk),
               "-device", "ide-hd,drive=hashdisk,bus=ide.1,serial=FIREARC_HASH_A,bootindex=3",
               "-device", "qemu-xhci,id=xhci", "-drive", "if=none,id=ukiusb,format=raw,readonly=on,file=" + safe_qemu_path(media),
               "-device", "usb-storage,bus=xhci.0,drive=ukiusb,removable=on,bootindex=0",
               "-serial", "file:" + safe_qemu_path(work / "serial.raw"), "-monitor", "none",
               "-qmp", "unix:" + safe_qemu_path(sockets / "qmp.sock") + ",server=on,wait=off"]
    if tpm:
        command += ["-chardev", "socket,id=chrtpm,path=" + safe_qemu_path(sockets / "tpm.sock"),
                    "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", config["tpm_frontend"] + ",tpmdev=tpm0"]
    return command


def stop_owned(process):
    """Only a Popen created in this invocation; never kill from stored PIDs."""
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def wait_socket(path, process):
    deadline = time.monotonic() + 10
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise SafetyError("Process exited or timed out before creating its control socket")
        time.sleep(0.05)


def tpm_finished_with_guest(tpm_process, guest):
    """QEMU may close swtpm just before its own process becomes waitable."""
    code = tpm_process.poll()
    if code is None:
        return False
    if code != 0:
        raise SafetyError("swtpm exited abnormally during guest execution")
    try:
        guest.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise SafetyError("swtpm exited while the guest remained running") from error
    # Caller still validates QEMU exit and the complete guest acceptance report.
    return True


def validate_overlay(tool, path, backing):
    info = read_json_output([tool, "info", "--output=json", str(path)])
    if (info.get("format") != "qcow2" or info.get("full-backing-filename") != str(backing)
            or info.get("backing-filename-format") != "raw"):
        raise SafetyError("Unexpected overlay backing or format")


def read_json_output(command):
    import json
    return json.loads(subprocess.check_output(command, text=True, timeout=30))


def mutate(work, scenario, base, metadata, tools):
    sources = {"root": base / "root.ext4", "hash": base / "root.verity"}
    if scenario not in {"data-executable", "data-unused", "hash-tree", "replacement-pair"}:
        return sources
    kind = "hash" if scenario == "hash-tree" else "root"
    path = work / ("mutated.verity" if kind == "hash" else "mutated.ext4")
    shutil.copyfile(sources[kind], path)
    path.chmod(0o600)
    if scenario == "data-executable":
        blocks = run_logged(work, "executable-block", [tools["debugfs"], "-R", "blocks /usr/bin/true", str(path)])
        if not re.fullmatch(r"[0-9\s]+", blocks):
            raise SafetyError("Unable to identify executable block")
        offset = int(blocks.split()[0]) * 4096
    elif kind == "root":
        block = metadata["data_blocks"] - 1
        report = run_logged(work, "unused-block", [tools["debugfs"], "-R", f"testb {block}", str(path)])
        if "not in use" not in report:
            raise SafetyError("Requested unused block is allocated")
        offset = block * 4096
    else:
        offset = 0
    with path.open("r+b") as stream:
        stream.seek(offset)
        before = stream.read(1)
        if not before:
            raise SafetyError("Mutation outside protected image")
        after = bytes([before[0] ^ 1])
        stream.seek(offset)
        stream.write(after)
    write_json(work / "mutation.json", {"scenario": scenario, "offset": offset, "before": before.hex(),
                                        "after": after.hex(), "source_sha256": sha256(sources[kind]),
                                        "mutated_sha256": sha256(path)})
    sources[kind] = path
    if scenario == "replacement-pair":
        tree = work / "replacement.verity"
        output = run_logged(work, "replacement-format", [tools["veritysetup"], "format", *metadata["options"], str(path), str(tree)])
        match = re.search(r"^Root hash:\s+([0-9a-f]{64})$", output, re.M)
        if not match or match[1] == metadata["root_hash"]:
            raise SafetyError("Missing/distinct replacement root hash")
        run_logged(work, "replacement-verify", [tools["veritysetup"], "verify", *metadata["options"], str(path), str(tree), match[1]])
        sources["hash"] = tree
    return sources


def snapshot_tooling(root, work):
    """Keep the actual uncommitted tooling needed to reproduce a local run."""
    files = [Path("justfile"), Path("lab/q35/research.json")]
    for pattern in ("scripts/*.py", "scripts/firearc_lib/*.py", "locks/*.json"):
        files += [path.relative_to(root) for path in Path(root).glob(pattern)]
    hashes = {}
    for relative in sorted(files):
        source = regular_file(root, relative.as_posix())
        target = work / "tooling" / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        hashes[relative.as_posix()] = sha256(target)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    write_json(work / "tooling.json", {"base_commit": head, "actual_tooling_sha256": hashes,
                                       "note": "Working tooling copied, not assumed identical to base commit"})


def run_device(root, device, *, label, scenario="good", timeout=180):
    identifier(label)
    if scenario not in SCENARIOS or not 1 <= timeout <= 600:
        raise SafetyError("Invalid scenario or deadline (1–600 seconds)")
    config = profile(root)
    path = device_path(root, device)
    with device_lock(path):
        if (path / "active.json").exists() or (path / "active.json").is_symlink():
            raise SafetyError("Existing/stale active record; inspect device, never silently replace its state")
        state = read_json(regular_file(path, "device.json"))
        if (state.get("schema") != 1 or state.get("id") != device or state.get("profile") != config["profile"]
                or not isinstance(state.get("tpm"), bool)):
            raise SafetyError("Invalid device manifest")
        inputs = verify_import(root)
        if state["input_hashes"] != inputs:
            raise SafetyError("Device belongs to different input fixtures")
        names = ["qemu-system-x86_64", "qemu-img"]
        if state["tpm"]:
            names.append("swtpm")
            tpm_state(path)
        if scenario in {"data-executable", "data-unused", "replacement-pair"}:
            names.append("debugfs")
        if scenario == "replacement-pair":
            names.append("veritysetup")
        tools = tool_paths(root, names)
        base = imported_path(root)
        flash = regular_file(path, "pflash.raw")
        original_flash = (base / "coreboot.rom").read_bytes()
        current_flash = flash.read_bytes()
        store_end = config["variable_store_bytes"]
        if len(current_flash) != config["flash_bytes"] or current_flash[store_end:] != original_flash[store_end:]:
            raise SafetyError("Persistent flash differs outside the permitted SMMSTORE region")
        for name, source in (("root", "root.ext4"), ("hash", "root.verity")):
            validate_overlay(tools["qemu-img"], regular_file(path, name + ".qcow2"), base / source)
        private_directory(path / "boots")
        work = path / "boots" / label
        work.mkdir(mode=0o700)
        sockets = socket_space(root)
        qmp = sockets / "qmp.sock"
        result = {"passed": False, "device": device, "label": label, "scenario": scenario,
                  "tpm_attached": state["tpm"], "network": "none", "profile": config["profile"],
                  "started_at": datetime.now(timezone.utc).isoformat(),
                  "scope": "Research baseline only; no systemd-boot, attestation, LUKS, A/B or hardware-root claim"}
        process = tpm_process = None
        opened = []
        start = time.monotonic()
        active_written = False
        sources = {}
        disks = {}
        try:
            snapshot_tooling(root, work)
            write_json(work / "inputs.json", inputs)
            write_json(work / "tools.json", {name: {"path": value, "sha256": sha256(value)} for name, value in tools.items()})
            metadata = read_json(base / "verity.json")
            sources = mutate(work, scenario, base, metadata, tools)
            for name in ("root", "hash"):
                disks[name] = path / (name + ".qcow2")
                if sources[name] != base / ("root.ext4" if name == "root" else "root.verity"):
                    disks[name] = work / (name + ".qcow2")
                    overlay(work, "mutant-" + name, sources[name], disks[name], tools["qemu-img"])
            media = base / ((scenario if scenario in FIRMWARE_NEGATIVES else "good") + ".img")
            if state["tpm"]:
                command = swtpm_command(tools["swtpm"], path, sockets)
                write_json(work / "swtpm.command.json", command)
                log = (work / "swtpm.log").open("xb")
                opened.append(log)
                tpm_process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                wait_socket(sockets / "tpm.sock", tpm_process)
            command = boot_command(config, tools, flash, disks["root"], disks["hash"], media, work, sockets, tpm=state["tpm"])
            write_json(work / "qemu.command.json", command)
            log = (work / "qemu.stderr").open("xb")
            opened.append(log)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            write_json(work / "processes.json", {"qemu_pid": process.pid, "swtpm_pid": tpm_process.pid if tpm_process else None})
            wait_socket(qmp, process)
            request(qmp, "query-status")
            write_json(path / "active.json", {"id": device, "label": label, "qmp": str(qmp)})
            active_written = True
            deadline = start + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise SafetyError("Guest deadline exceeded; host timeout is not automatic rollback")
                if tpm_process and tpm_finished_with_guest(tpm_process, process):
                    break
                if scenario in FIRMWARE_NEGATIVES and (work / "serial.raw").exists():
                    text = clean_console((work / "serial.raw").read_bytes())
                    if "Secure Boot is enabled." in text and "Access Denied" in text:
                        request(qmp, "quit")
                        process.wait(timeout=15)
                        break
                time.sleep(0.2)
            text = clean_console((work / "serial.raw").read_bytes())
            result.update(validate_console(text, scenario, metadata, database_hash((base / "db.der").read_bytes()), process.returncode))
            if state["tpm"] and scenario == "good":
                result.update(validate_tpm_console(text))
            result["passed"] = True
        except BaseException as error:
            result.update(passed=False, error_type=type(error).__name__, error=str(error))
            raise
        finally:
            stop_owned(process)
            stop_owned(tpm_process)
            for stream in opened:
                stream.close()
            if active_written:
                (path / "active.json").unlink()
            result.update(duration_seconds=round(time.monotonic() - start, 3),
                          qemu_exit=process.returncode if process else None,
                          swtpm_exit=tpm_process.returncode if tpm_process else None,
                          processes_reaped=all(p is None or p.poll() is not None for p in (process, tpm_process)))
            try:
                if (work / "serial.raw").exists():
                    (work / "console.txt").write_text(clean_console((work / "serial.raw").read_bytes()))
                after = flash.read_bytes()
                result["flash_writes_smmstore_only"] = len(after) == len(original_flash) and after[store_end:] == original_flash[store_end:]
                result["inputs_unchanged"] = verify_import(root) == inputs
                if state["tpm"]:
                    tpm_state(path)
                    result["tpm_state_present_after_stop"] = True
                for name, disk in disks.items():
                    run_logged(work, "compare-" + name, [tools["qemu-img"], "compare", "-f", "raw", "-F", "qcow2", str(sources[name]), str(disk)])
                result["root_hash_disks_unchanged"] = len(disks) == 2
                if not all(result.get(key) for key in ("flash_writes_smmstore_only", "inputs_unchanged", "root_hash_disks_unchanged", "processes_reaped")):
                    raise SafetyError("Input/state/process safety check failed")
            except BaseException as error:
                result.update(passed=False, cleanup_error_type=type(error).__name__, cleanup_error=str(error))
                raise
            finally:
                write_json(work / "result.json", result)
                entries = []
                for file in sorted(work.rglob("*")):
                    if file.is_file() and not file.is_symlink():
                        entries.append(sha256(file) + "  " + file.relative_to(work).as_posix())
                (work / "SHA256SUMS").write_text("\n".join(entries) + "\n")
        return {**result, "evidence": str(work)}


def control_device(root, device, operation):
    commands = {"status": "query-status", "reboot": "system_reset", "stop": "system_powerdown", "powercut": "quit"}
    if operation not in commands:
        raise SafetyError("Unknown control operation")
    path = device_path(root, device)
    active = read_json(regular_file(path, "active.json"))
    socket_path = Path(active["qmp"])
    sockets = private_directory(Path(root) / "run/sockets")
    if (active.get("id") != device or socket_path.name != "qmp.sock" or socket_path.parent.parent != sockets
            or socket_path.parent.is_symlink()):
        raise SafetyError("Invalid device QMP endpoint")
    private_directory(socket_path.parent)
    identifier(active["label"])
    private_directory(path / "boots")
    evidence = private_directory(path / "boots" / active["label"])
    # Persist the requested operation before QMP can terminate the VM. The run's
    # final manifest then includes it; this record alone is not proof of success.
    write_json(evidence / ("control-request-" + uuid.uuid4().hex + ".json"), {
        "id": device, "operation": operation, "requested_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Host request, not automatic guest recovery",
    })
    return {"device": device, "operation": operation, "reply": request(socket_path, commands[operation]),
            "scope": "Host-issued control, not guest automatic rollback or a full physical power-loss model"}
