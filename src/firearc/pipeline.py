"""Dependency-aware project builds with automatic IDs and verified success state."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid

from . import builder, firmware, initrd, rootfs, sbom
from .inputs import validate_locks
from .integrity import SafetyError, private_directory, read_json, regular_file, sha256, verify_file, write_json

DEPENDENCIES = {
    "metadata": (), "packages-tools": ("metadata",), "packages-root": ("metadata",),
    "tools": ("packages-tools",), "root": ("tools", "packages-root"),
    "rootfs": ("tools", "root"), "check-initrd": ("tools", "root"),
    "check-rootfs": ("tools", "rootfs"), "sbom": ("packages-root",),
    "firmware-sources": (),
}


def project_digest(root):
    files = {}
    for directory in ("src", "images", "containers", "locks"):
        for path in sorted((root / directory).rglob("*")):
            if path.is_symlink():
                raise SafetyError("Source inputs must not be symlinks")
            if path.is_file():
                files[path.relative_to(root).as_posix()] = [sha256(path), stat.S_IMODE(path.stat().st_mode)]
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


@contextmanager
def project_lock(root):
    path = root / ".firearc.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SafetyError("Project lock is not a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SafetyError("Another project build/cleanup is running") from error
        yield
    finally:
        os.close(descriptor)


def clean(root, *, confirmed=False):
    if not confirmed:
        raise SafetyError("Use just clean --yes to remove project build outputs")
    target = root / "build"
    if not target.exists() and not target.is_symlink():
        return
    private_directory(target)
    # Refuse mounted trees, including a mount below the cleanup root.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mount = Path(line.split()[4].replace("\\040", " "))
        if mount == target or target in mount.parents:
            raise SafetyError("Refusing to clean a mounted build tree")
    # Full ID mappings let cleanup remove owned rootless-build subordinate IDs.
    subprocess.run(["unshare", "--user", "--map-root-user", "--map-auto", "--net", "--mount",
                    sys.executable, "-B", "-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", str(target)], check=True)


class Pipeline:
    def __init__(self, root, *, online=False, force_checks=False):
        self.root = Path(root).absolute()
        if any(character in str(self.root) for character in (",", "\n", "\r")):
            raise SafetyError("Checkout path cannot contain commas or control characters")
        validate_locks(self.root)
        builder.lock(self.root)
        builder.root_lock(self.root)
        self.build = private_directory(self.root / "build", create=True)
        private_directory(self.build / "images", create=True)
        builder.parent(self.root)
        self.online = online
        self.force_checks = force_checks
        self.digest = project_digest(self.root)
        self.state = read_json(regular_file(self.build, "state.json")) if (self.build / "state.json").exists() else {"schema": 1, "stages": {}}
        if self.state.get("schema") != 1:
            raise SafetyError("Unsupported project state schema")
        self.memo = {}

    def save(self):
        temporary = self.build / (".state-" + uuid.uuid4().hex)
        write_json(temporary, self.state)
        temporary.chmod(0o600)
        temporary.replace(self.build / "state.json")

    def verify_record(self, record):
        receipt = regular_file(self.root, record["receipt"])
        verify_file(receipt, record["receipt_sha256"])
        value = read_json(receipt)
        if not value.get("passed"):
            raise SafetyError("Cached stage is not successful")
        for name, digest in value["files"].items():
            verify_file(regular_file(self.root, name), digest)
        if record["stage"] == "tools":
            builder.verify_tools(self.root, record["id"])
            subprocess.run(["docker", "image", "inspect", value["image_id"]], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def ensure(self, stage):
        if stage in self.memo:
            return self.memo[stage]
        dependencies = {name: self.ensure(name) for name in DEPENDENCIES[stage]}
        if stage == "metadata" or stage == "packages-tools":
            source = sha256(self.root / "locks/debian-build.json")
        elif stage == "packages-root":
            source = sha256(self.root / "locks/root.json")
        else:
            source = self.digest
        fingerprint = hashlib.sha256(json.dumps([source, {name: value["receipt_sha256"] for name, value in dependencies.items()}, sys.version], sort_keys=True).encode()).hexdigest()
        previous = self.state["stages"].get(stage)
        if previous and previous["fingerprint"] == fingerprint and not (self.force_checks and stage.startswith("check-")):
            self.verify_record(previous)
            self.memo[stage] = previous
            return previous
        if stage.startswith("packages-") or stage == "metadata":
            if not self.online:
                raise SafetyError("Missing/stale dependencies; run just bootstrap (explicit network acquisition)")
        build_id = stage[:15] + "-" + uuid.uuid4().hex[:12]
        print(f"Building {stage}…", file=sys.stderr, flush=True)
        work, extra = self.produce(stage, build_id, dependencies)
        files = {}
        # Keep one compact receipt per successful stage. Logs stay alongside it.
        if stage == "metadata":
            selected = [p for p in (work / "repository").rglob("*") if p.is_file()]
        elif stage.startswith("packages-"):
            selected = [work / "packages.json", *[p for p in (work / "context").rglob("*") if p.is_file()]]
        elif stage == "tools":
            selected = [work / name for name in ("build-result.json", "export-result.json", "tools-inventory.json", "packages.json")]
        else:
            result = read_json(regular_file(work, "result.json"))
            if not result.get("passed"):
                raise SafetyError("Build/check did not pass")
            selected = [work / "result.json", *[work / "output" / name for name in result.get("artifacts", {})]]
            if stage == "root":
                selected.append(work / "output/firearc-initrd.img")
        for path in selected:
            files[path.relative_to(self.root).as_posix()] = sha256(path)
        if stage != "metadata" and project_digest(self.root) != self.digest:
            raise SafetyError("Build inputs changed during execution; success not published")
        receipt = work / "completion.json"
        write_json(receipt, {"passed": True, "stage": stage, "files": files, **extra})
        record = {"stage": stage, "id": work.name, "fingerprint": fingerprint,
                  "receipt": receipt.relative_to(self.root).as_posix(), "receipt_sha256": sha256(receipt)}
        self.state["stages"][stage] = record
        self.save()
        self.memo[stage] = record
        return record

    def produce(self, stage, build_id, deps):
        root = self.root
        if stage == "firmware-sources":
            firmware.fetch(root, build_id, allow_network=self.online)
            return self.build / "firmware" / build_id, {}
        if stage == "metadata":
            target = builder.metadata_path(root)
            if target.exists():
                evidence = builder.parent(root) / build_id
                evidence.mkdir(mode=0o700)
                builder.verify_metadata(root, target / "repository", evidence)
            else:
                builder.acquire_metadata(root, allow_network=True)
            return target, {}
        if stage.startswith("packages-"):
            profile = stage.removeprefix("packages-")
            builder.plan_packages(root, build_id, allow_network=self.online, profile=profile)
            builder.fetch_packages(root, build_id, allow_network=self.online)
            return builder.parent(root) / build_id, {}
        if stage == "tools":
            source = builder.parent(root) / deps["packages-tools"]["id"]
            work = builder.parent(root) / build_id
            work.mkdir(mode=0o700)
            shutil.copyfile(source / "packages.json", work / "packages.json")
            shutil.copytree(source / "context", work / "context")
            for name in ("Dockerfile", "build.sh"):
                shutil.copyfile(root / "containers/builder" / name, work / "context" / name)
            (work / "context/repository/apt.conf").write_text(builder.apt_config("/var/lib/dpkg/status"))
            (work / "context/repository/sources.list").write_text(builder.sources(builder.lock(root)))
            result = builder.build_tools(root, build_id)
            builder.export_tools(root, build_id)
            return work, {"image_id": result["image_id"]}
        if stage == "sbom":
            sbom.generate(root, deps["packages-root"]["id"], build_id)
            return builder.parent(root) / build_id, {}
        tools = deps["tools"]["id"]
        if stage == "root":
            builder.build_root(root, tools, deps["packages-root"]["id"], build_id)
            work = self.build / "images" / build_id
            with tarfile.open(work / "output/firearc-root.tar", "r:") as archive:
                name = "./boot/initrd.img-" + builder.root_lock(root)["kernel_release"]
                member = archive.getmember(name)
                if not member.isreg() or not 0 < member.size < 256 * 1024**2:
                    raise SafetyError("Invalid generated initramfs")
                with archive.extractfile(member) as stream, (work / "output/firearc-initrd.img").open("xb") as output:
                    shutil.copyfileobj(stream, output)
        elif stage == "rootfs":
            rootfs.create(root, tools, deps["root"]["id"], build_id)
        elif stage == "check-initrd":
            initrd.audit(root, tools, deps["root"]["id"], build_id)
        elif stage == "check-rootfs":
            rootfs.check(root, tools, deps["rootfs"]["id"], build_id)
        return self.build / "images" / build_id, {}

    def publish(self):
        root = self.ensure("root")
        filesystem = self.ensure("rootfs")
        inventory = self.ensure("sbom")
        root_output = self.build / "images" / root["id"] / "output"
        fs_output = self.build / "images" / filesystem["id"] / "output"
        fs_result = read_json(fs_output.parent / "result.json")
        outputs = {"root.tar": root_output / "firearc-root.tar", "kernel.efi": root_output / "firearc-root.vmlinuz",
                   "initrd.img": root_output / "firearc-initrd.img", "root.ext4": fs_output / fs_result["root_payload"],
                   "root.verity": fs_output / "root.verity", "verity-authority.json": fs_output / "verity-authority.json",
                   "sbom.json": builder.parent(self.root) / inventory["id"] / "output" / "sbom.json"}
        directory = private_directory(self.build / "output", create=True)
        for name, source in outputs.items():
            destination = directory / name
            if destination.exists() and not destination.is_symlink():
                raise SafetyError("Refusing to replace a non-symlink output alias")
            temporary = directory / (".output-" + uuid.uuid4().hex)
            temporary.symlink_to(os.path.relpath(source, directory))
            temporary.replace(destination)
        return {name: sha256(path) for name, path in outputs.items()}


def run(root, command, *, online=False):
    with project_lock(root):
        if command == "status":
            path = root / "build/state.json"
            return read_json(path) if path.exists() else {"schema": 1, "stages": {}}
        pipeline = Pipeline(root, online=online, force_checks=command == "verify-build")
        if command == "bootstrap":
            pipeline.ensure("packages-tools")
            pipeline.ensure("packages-root")
        elif command == "build-tools": pipeline.ensure("tools")
        elif command == "build-root": pipeline.ensure("root")
        elif command == "sbom": pipeline.ensure("sbom")
        elif command == "firmware-sources": pipeline.ensure("firmware-sources")
        elif command == "check-initrd": pipeline.ensure("check-initrd")
        elif command == "check-rootfs": pipeline.ensure("check-rootfs")
        else:
            outputs = pipeline.publish()
            if command == "verify-build":
                pipeline.ensure("check-initrd")
                pipeline.ensure("check-rootfs")
            return {"passed": True, "outputs": outputs, "scope": "Unsigned build inputs; not qualified boot/release"}
        return {"passed": True, "stage": command}


def reproduce(root, *, confirmed=False):
    if not confirmed:
        raise SafetyError("Use just reproduce --yes: this deletes build/ and downloads/builds twice")
    with project_lock(root):
        initial = project_digest(root)
        rounds = []
        for number in (1, 2):
            clean(root, confirmed=True)
            pipeline = Pipeline(root, online=True, force_checks=True)
            outputs = pipeline.publish()
            pipeline.ensure("check-initrd")
            pipeline.ensure("check-rootfs")
            rounds.append({"round": number, "outputs": outputs, "verified": True})
        if project_digest(root) != initial:
            raise SafetyError("Source/configuration changed between reproduction rounds")
        identical = rounds[0]["outputs"] == rounds[1]["outputs"]
        report = {"schema": 1, "passed": identical, "clean_download_build_rounds": rounds,
                  "source_fingerprint": initial, "host_python": sys.version,
                  "scope": "Root/kernel/initramfs/ext4/verity payloads only; firmware/signing/device lifecycle pending",
                  "shared_docker_content_cache_preserved": True}
        write_json(root / "build/reproducibility.json", report)
        if not identical:
            raise SafetyError("Clean builds completed but payload hashes differ; see build/reproducibility.json")
        return report
