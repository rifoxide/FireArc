"""Authenticated Debian tools acquisition, offline container and rootless mkosi.

Docker is used only for APT planning/building a public tools filesystem. The
actual image build uses an unprivileged user namespace, not privileged Docker.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import uuid

from .inputs import load_lock
from .integrity import (
    SafetyError, SHA256, identifier, private_directory, read_json, regular_file,
    relative_name, sha256, verify_file, write_json,
)


def lock(root):
    value = load_lock(root, "debian-build")
    if (value.get("architecture") != "amd64" or value.get("release") != "trixie"
            or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", value["snapshot"])
            or not re.fullmatch(r"docker.io/library/debian@sha256:[0-9a-f]{64}", value["base_image"])):
        raise SafetyError("Invalid Debian builder lock")
    for package in value["tools"]:
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?:=[0-9A-Za-z.+:~\-]+)?", package):
            raise SafetyError("Invalid tools package specification")
    if set(value["repositories"]) != {"debian", "debian-security"}:
        raise SafetyError("Expected explicit Debian main and security repositories")
    relative_name(value["metadata_reference"])
    if not SHA256.fullmatch(value["keyring_sha256"]) or not SHA256.fullmatch(value["base_config_sha256"]):
        raise SafetyError("Invalid keyring/base configuration pin")
    for repo in value["repositories"].values():
        for key in ("inrelease_sha256", "release_sha256", "packages_sha256"):
            if not SHA256.fullmatch(repo[key]):
                raise SafetyError("Invalid snapshot metadata pin")
    return value


def parent(root):
    output = private_directory(Path(root) / "artifacts", create=True)
    return private_directory(output / "builder", create=True)


def metadata_path(root):
    return Path(root) / "artifacts/builder/metadata"


def logged(work, name, command, *, env=None, timeout=300):
    write_json(work / (name + ".command.json"), command)
    with (work / (name + ".stdout")).open("xb") as out, (work / (name + ".stderr")).open("xb") as err:
        result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout)
    write_json(work / (name + ".exit.json"), {"returncode": result.returncode})
    if result.returncode:
        raise SafetyError(f"{name} failed ({result.returncode}); inspect {work}")
    return (work / (name + ".stdout")).read_text()


def deb822(text):
    """Parse fields without treating wrapped descriptions as new fields."""
    current = {}
    key = None
    for line in text.splitlines() + [""]:
        if not line:
            if current:
                yield current
            current, key = {}, None
        elif line[0].isspace():
            if key is None:
                raise SafetyError("Deb822 continuation without a field")
            current[key] += "\n" + line[1:]
        else:
            key, separator, value = line.partition(":")
            if not separator or not re.fullmatch(r"[A-Za-z0-9-]+", key) or key in current:
                raise SafetyError("Malformed or duplicate Deb822 field")
            current[key] = value.lstrip()


def index_authorized(release, packages):
    records = list(deb822(release))
    if len(records) != 1:
        raise SafetyError("Expected a single authenticated Release record")
    rows = {}
    for row in records[0].get("SHA256", "").splitlines():
        if not row.strip():
            continue
        digest, size, name = row.split()
        relative_name(name)
        if not SHA256.fullmatch(digest) or name in rows or not size.isdecimal():
            raise SafetyError("Invalid Release SHA256 entry")
        rows[name] = (digest, int(size))
    expected = rows.get("main/binary-amd64/Packages")
    if not expected or expected != (sha256(packages), packages.stat().st_size):
        raise SafetyError("Package index not authorized by the signed Release")


def verify_metadata(root, directory, evidence):
    value = lock(root)
    keyring = regular_file(directory, "archive-keyring.gpg")
    verify_file(keyring, value["keyring_sha256"])
    gnupg = private_directory(evidence / "gnupg", create=True)
    for name, repo in value["repositories"].items():
        base = directory / name / "dists" / repo["suite"]
        release = regular_file(base, "Release")
        inrelease = regular_file(base, "InRelease")
        packages = regular_file(base, "main/binary-amd64/Packages")
        for path, pin in [(release, repo["release_sha256"]), (inrelease, repo["inrelease_sha256"]), (packages, repo["packages_sha256"])]:
            verify_file(path, pin)
        # A hash pin alone is not Debian archive authentication. Check the
        # signature and compare gpgv's authenticated output byte-for-byte.
        output = evidence / (name + ".authenticated.Release")
        logged(evidence, name + "-gpgv", ["gpgv", "--homedir", str(gnupg), "--keyring", str(keyring),
                                         "--output", str(output), str(inrelease)])
        if output.read_bytes() != release.read_bytes():
            raise SafetyError("Authenticated Release bytes differ from the recorded Release")
        index_authorized(release.read_text(), packages)
    return value


def import_metadata(root, reference):
    value = lock(root)
    target = metadata_path(root)
    if target.exists() or target.is_symlink():
        raise SafetyError("Metadata import already exists; never replace it implicitly")
    work = parent(root) / (".metadata-import-" + uuid.uuid4().hex[:12])
    work.mkdir(mode=0o700)
    repository = work / "repository"
    repository.mkdir(mode=0o700)
    source = Path(reference).absolute() / value["metadata_reference"]
    keyring = regular_file(source, "archive-keyring.gpg")
    verify_file(keyring, value["keyring_sha256"])
    shutil.copyfile(keyring, repository / "archive-keyring.gpg")
    for name, repo in value["repositories"].items():
        base = repository / name / "dists" / repo["suite"]
        (base / "main/binary-amd64").mkdir(parents=True)
        for original, relative, pin in [
            (name + ".InRelease", "InRelease", repo["inrelease_sha256"]),
            (name + ".Release", "Release", repo["release_sha256"]),
            (name + ".Packages", "main/binary-amd64/Packages", repo["packages_sha256"]),
        ]:
            path = regular_file(source, original)
            verify_file(path, pin)
            shutil.copyfile(path, base / relative)
    verify_metadata(root, repository, work)
    write_json(work / "result.json", {"passed": True, "snapshot": value["snapshot"], "signatures_verified": True,
                                       "reference": str(Path(reference).absolute()), "private_keys_accessed": False})
    work.rename(target)
    return {"passed": True, "metadata": str(target), "signatures_verified": True}


def apt_config(status):
    if status not in {"/work/empty.status", "/var/lib/dpkg/status"}:
        raise SafetyError("APT status path is not allowlisted")
    return f'''Dir::Etc "/work/apt";
Dir::Etc::main "apt.conf.empty";
Dir::Etc::parts "apt.conf.d";
Dir::State "/work/state";
Dir::State::status "{status}";
Dir::Cache "/work/cache";
Dir::Log "/work/log";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Sandbox::User "root";
Acquire::Languages "none";
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
'''


def sources(value, prefix="/repository"):
    if prefix not in {"/repository", "/etc/firearc-build/repository"}:
        raise SafetyError("Unexpected repository mount point")
    return "".join(f"deb [signed-by={prefix}/archive-keyring.gpg check-valid-until=no] file:{prefix}/{name} {repo['suite']} main\n"
                   for name, repo in value["repositories"].items())


def mkosi_sources(value):
    """APT .sources files require Deb822, unlike traditional .list files."""
    prefix = "/etc/firearc-build/repository"
    return "\n".join(
        # copy: is local-only like file:, but puts packages in APT's cache.
        # mkosi's Debian bootstrap translates cache paths outside its sandbox;
        # direct file: paths otherwise refer to sandbox-only /etc paths.
        f"Types: deb\nURIs: copy:{prefix}/{name}\nSuites: {repo['suite']}\n"
        f"Components: main\nSigned-By: {prefix}/archive-keyring.gpg\nCheck-Valid-Until: no\n"
        for name, repo in value["repositories"].items()
    )


def docker_args(image, *, user=True):
    command = ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m"]
    if user:
        command += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return command


def ensure_base(root, work, allow_network):
    value = lock(root)
    probe = subprocess.run(["docker", "image", "inspect", value["base_image"]], capture_output=True, text=True)
    if probe.returncode:
        if not allow_network:
            raise SafetyError("Pinned Debian OCI base absent; pass --allow-network for explicit acquisition")
        logged(work, "pull-base", ["docker", "pull", "--platform=linux/amd64", value["base_image"]], timeout=600)
    info = json.loads(logged(work, "inspect-base", ["docker", "image", "inspect", value["base_image"]]))[0]
    if (info["Id"] != "sha256:" + value["base_config_sha256"] or info["Architecture"] != "amd64"
            or info["Os"] != "linux" or info["Config"].get("Volumes")):
        raise SafetyError("OCI base identity, architecture or volumes differ")
    return value


def package_index(value, repository):
    result = {}
    for name, repo in value["repositories"].items():
        path = repository / name / "dists" / repo["suite"] / "main/binary-amd64/Packages"
        for fields in deb822(path.read_text()):
            if fields.get("Architecture") not in {"all", "amd64"}:
                continue
            filename = fields.get("Filename", "")
            relative_name(filename)
            digest = fields.get("SHA256", "")
            if not SHA256.fullmatch(digest) or not fields.get("Size", "").isdecimal():
                raise SafetyError("Package lacks SHA-256/size authority")
            record = {"name": fields["Package"], "version": fields["Version"], "architecture": fields["Architecture"],
                      "repository": name, "filename": filename, "sha256": digest, "size": int(fields["Size"])}
            key = name + "/" + filename
            if key in result and result[key] != record:
                raise SafetyError("Ambiguous package index entry")
            result[key] = record
    return result


def parse_uris(text, index):
    records = []
    seen = set()
    for line in text.splitlines():
        if not line.startswith("'"):
            continue
        # Modern security indexes may intentionally omit MD5. APT's optional
        # legacy digest is never authority here: require the signed SHA-256 row.
        match = re.fullmatch(r"'file:/repository/([^']+)' (\S+) ([0-9]+)(?: (\S+))?\s*", line)
        if not match:
            raise SafetyError("Unexpected APT package URI (only signed local repositories are allowed)")
        relative, output, size, _ = match.groups()
        relative = urllib.parse.unquote(relative)
        relative_name(relative)
        record = index.get(relative)
        if not record or record["size"] != int(size) or relative in seen:
            raise SafetyError("APT package URI is missing/duplicated or not authorized by the signed index")
        seen.add(relative)
        records.append(record)
    if not records:
        raise SafetyError("APT produced no package plan")
    return records


def plan_tools(root, label, *, allow_network=False):
    identifier(label)
    work = parent(root) / label
    work.mkdir(mode=0o700)
    value = ensure_base(root, work, allow_network)
    repository = metadata_path(root) / "repository"
    verify_metadata(root, repository, work)
    state = work / "apt-work"
    state.mkdir(mode=0o700)
    for name in ("apt/apt.conf.d", "apt/preferences.d", "state/lists/partial", "cache/archives/partial", "log"):
        (state / name).mkdir(parents=True, exist_ok=True)
    (state / "empty.status").touch()
    (state / "apt.conf").write_text(apt_config("/work/empty.status"))
    (state / "apt/sources.list").write_text(sources(value))
    options = docker_args(value["base_image"]) + [
        "--mount", f"type=bind,src={repository},dst=/repository,readonly",
        "--mount", f"type=bind,src={state},dst=/work",
        "--env", "APT_CONFIG=/work/apt.conf", "--env", "LC_ALL=C", value["base_image"],
    ]
    logged(work, "apt-update", options + ["apt-get", "update"])
    requested = ["?essential", "base-files", *value["tools"]]
    text = logged(work, "apt-plan", options + ["apt-get", "--yes", "--no-install-recommends", "--print-uris", "--download-only", "install", *requested])
    packages = parse_uris(text, package_index(value, repository))
    write_json(work / "packages.json", {"schema": 1, "snapshot": value["snapshot"], "packages": packages,
                                         "requested": requested, "metadata_lock_sha256": sha256(Path(root) / "locks/debian-build.json")})
    return {"passed": True, "plan": str(work), "packages": len(packages), "package_bytes": sum(p["size"] for p in packages)}


def download_package(value, record, destination):
    relative_name(record["filename"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_file(destination, record["sha256"])
        return
    url = f"https://snapshot.debian.org/archive/{record['repository']}/{value['snapshot']}/{record['filename']}"
    partial = destination.with_name(destination.name + ".partial-" + uuid.uuid4().hex[:12])
    request = urllib.request.Request(url, headers={"User-Agent": "FireArc-build-research/1"})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("xb") as output:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise SafetyError("Package download redirected away from HTTPS")
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > record["size"]:
                raise SafetyError("Package exceeds authenticated size")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if size != record["size"]:
        raise SafetyError("Truncated package")
    verify_file(partial, record["sha256"])
    partial.rename(destination)


def fetch_tools(root, label, *, allow_network=False):
    identifier(label)
    if not allow_network:
        raise SafetyError("Package acquisition requires explicit --allow-network")
    value = lock(root)
    work = parent(root) / label
    plan = read_json(regular_file(work, "packages.json"))
    if plan["metadata_lock_sha256"] != sha256(Path(root) / "locks/debian-build.json"):
        raise SafetyError("Plan belongs to different snapshot/build inputs")
    repository = metadata_path(root) / "repository"
    check = work / ("fetch-check-" + uuid.uuid4().hex[:12])
    check.mkdir(mode=0o700)
    verify_metadata(root, repository, check)
    authority = package_index(value, repository)
    for record in plan["packages"]:
        if authority.get(record["repository"] + "/" + record["filename"]) != record:
            raise SafetyError("Plan package not authorized by the signed snapshot")
    context = work / "context"
    if not context.exists():
        context.mkdir(mode=0o700)
        shutil.copytree(repository, context / "repository")
    def fetch(record):
        path = context / "repository" / record["repository"] / record["filename"]
        download_package(value, record, path)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(fetch, plan["packages"]))
    packages = sorted(f"{p['name']}={p['version']}" for p in plan["packages"])
    (context / "packages.txt").write_text("\n".join(packages) + "\n")
    for name in ("Dockerfile", "build.sh"):
        shutil.copyfile(regular_file(root, "containers/mkosi-tools/" + name), context / name)
    (context / "repository/apt.conf").write_text(apt_config("/var/lib/dpkg/status"))
    (context / "repository/sources.list").write_text(sources(value))
    write_json(check / "result.json", {"passed": True, "packages": len(packages), "sha256_checked": True})
    return {"passed": True, "context": str(context), "packages": len(packages), "network_used": True}


def build_tools(root, label):
    identifier(label)
    work = parent(root) / label
    value = lock(root)
    plan = read_json(regular_file(work, "packages.json"))
    if plan["metadata_lock_sha256"] != sha256(Path(root) / "locks/debian-build.json"):
        raise SafetyError("Plan belongs to another builder lock")
    context = work / "context"
    check = work / ("build-check-" + uuid.uuid4().hex[:12])
    check.mkdir(mode=0o700)
    ensure_base(root, check, False)
    verify_metadata(root, context / "repository", check)
    authority = package_index(value, context / "repository")
    for record in plan["packages"]:
        if authority.get(record["repository"] + "/" + record["filename"]) != record:
            raise SafetyError("Plan package not authorized by the signed snapshot")
        verify_file(regular_file(context / "repository" / record["repository"], record["filename"]), record["sha256"])
    expected_packages = "\n".join(sorted(f"{p['name']}={p['version']}" for p in plan["packages"])) + "\n"
    if regular_file(context, "packages.txt").read_text() != expected_packages:
        raise SafetyError("Offline install list differs from the authenticated plan")
    if regular_file(context, "repository/apt.conf").read_text() != apt_config("/var/lib/dpkg/status"):
        raise SafetyError("Offline APT configuration differs")
    if regular_file(context, "repository/sources.list").read_text() != sources(value):
        raise SafetyError("Offline APT sources differ")
    for name in ("Dockerfile", "build.sh"):
        verify_file(regular_file(context, name), sha256(regular_file(root, "containers/mkosi-tools/" + name)))
    if (context / "Dockerfile").read_text().splitlines()[0] != "FROM " + value["base_image"]:
        raise SafetyError("Dockerfile does not use the locked OCI base")
    image_id = work / "image.id"
    if image_id.exists():
        raise SafetyError("Tools image already built; use a fresh plan label")
    env = {**os.environ, "DOCKER_BUILDKIT": "0"}
    logged(work, "docker-build", ["docker", "build", "--network=none", "--pull=false", "--iidfile", str(image_id), str(context)], env=env, timeout=1800)
    identity = image_id.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise SafetyError("Invalid built image identity")
    info = json.loads(logged(work, "inspect-tools", ["docker", "image", "inspect", identity]))[0]
    if info["Config"].get("Volumes"):
        raise SafetyError("Unexpected tools-image volumes")
    inventory = logged(work, "tool-inventory", docker_args(identity) + [identity, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"])
    (work / "tool-packages.tsv").write_text(inventory)
    write_json(work / "build-result.json", {"passed": True, "image_id": identity, "network": "none", "privileged": False,
                                              "built_at": datetime.now(timezone.utc).isoformat(), "package_plan_sha256": sha256(work / "packages.json")})
    return {"passed": True, "image_id": identity, "evidence": str(work), "network": "none", "privileged": False}


def tree_inventory(directory):
    """Hash regular files and symlink TEXT, never follow a symlink into the host."""
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        relative = path.relative_to(directory).as_posix()
        # In a Linux filesystem a literal backslash is not a path separator.
        # systemd legitimately ships escaped unit names such as \x2d. Keep the
        # stricter default for imported manifests, package URLs and other input.
        relative_name(relative, allow_backslash=True)
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            result[relative] = {"type": "link", "target": os.readlink(path), "mode": mode}
        elif stat.S_ISREG(info.st_mode):
            result[relative] = {"type": "file", "sha256": sha256(path), "mode": mode}
        elif stat.S_ISDIR(info.st_mode):
            result[relative] = {"type": "directory", "mode": mode}
        else:
            raise SafetyError("Unexpected special file in exported public tools tree")
    return result


def resume_export_stage(work, evidence_name, identity):
    """Resume only a completed, recorded copy, not an arbitrary staging tree."""
    if not re.fullmatch(r"export-[0-9a-f]{12}", evidence_name):
        raise SafetyError("Invalid export evidence name")
    evidence = private_directory(work / evidence_name)
    cid = regular_file(evidence, "create.stdout").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise SafetyError("Invalid recorded export container")
    expected_create = ["docker", "create", "--network=none", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", identity, "/bin/true"]
    if (read_json(regular_file(evidence, "create.command.json")) != expected_create
            or read_json(regular_file(evidence, "create.exit.json")) != {"returncode": 0}):
        raise SafetyError("Recorded export creation did not complete as intended")
    first = read_json(regular_file(evidence, "copy-usr.command.json"))
    if not isinstance(first, list) or len(first) != 4:
        raise SafetyError("Invalid recorded public copy")
    stage = Path(first[3]).parent
    if stage.parent != work or not re.fullmatch(r"\.tools-export-[0-9a-f]{12}", stage.name):
        raise SafetyError("Export stage is outside the intended build")
    private_directory(stage)
    for name, relative in [("usr", "usr"), ("alternatives", "etc/alternatives"), ("ca-certs", "etc/ssl/certs")]:
        wanted = ["docker", "cp", cid + ":/" + relative + "/.", str(stage / relative)]
        if (read_json(regular_file(evidence, "copy-" + name + ".command.json")) != wanted
                or read_json(regular_file(evidence, "copy-" + name + ".exit.json")) != {"returncode": 0}):
            raise SafetyError("Public tools copy is incomplete or has an unexpected destination")
    for name in ("bin", "sbin", "lib", "lib64"):
        if not (stage / name).is_symlink() or os.readlink(stage / name) != "usr/" + name:
            raise SafetyError("Export root links differ")
    if (read_json(regular_file(evidence, "remove-owned-container.command.json")) != ["docker", "rm", cid]
            or read_json(regular_file(evidence, "remove-owned-container.exit.json")) != {"returncode": 0}):
        raise SafetyError("Export container removal did not complete")
    return stage, evidence


def export_tools(root, label, *, resume_export=None):
    identifier(label)
    work = parent(root) / label
    outcome = read_json(regular_file(work, "build-result.json"))
    if not outcome.get("passed"):
        raise SafetyError("Tools image build did not pass")
    identity = regular_file(work, "image.id").read_text().strip()
    if identity != outcome["image_id"] or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise SafetyError("Tools image identity mismatch")
    target = work / "tools"
    if target.exists() or target.is_symlink():
        raise SafetyError("Tools tree already exported; refusing replacement")
    if resume_export:
        stage, evidence = resume_export_stage(work, resume_export, identity)
    else:
        stage = work / (".tools-export-" + uuid.uuid4().hex[:12])
        stage.mkdir(mode=0o700)
        evidence = work / ("export-" + uuid.uuid4().hex[:12])
        evidence.mkdir(mode=0o700)
        # Create but NEVER START this container. Copy only public tool/CA paths,
        # not /root, /home, /etc/shadow, /etc/ssl/private or runtime identity state.
        cid = logged(evidence, "create", ["docker", "create", "--network=none", "--read-only", "--cap-drop=ALL",
                                          "--security-opt=no-new-privileges", identity, "/bin/true"]).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise SafetyError("Invalid owned export-container identity")
        for name, relative in [("usr", "usr"), ("alternatives", "etc/alternatives"), ("ca-certs", "etc/ssl/certs")]:
            destination = stage / relative
            destination.mkdir(parents=True, exist_ok=True)
            logged(evidence, "copy-" + name, ["docker", "cp", cid + ":/" + relative + "/.", str(destination)])
        for name in ("bin", "sbin", "lib", "lib64"):
            (stage / name).symlink_to("usr/" + name)
        # Removal is restricted to this newly created, never-started container ID.
        # On copy failure it remains stopped for inspection; never delete broadly.
        logged(evidence, "remove-owned-container", ["docker", "rm", cid])
    inventory = tree_inventory(stage)
    write_json(work / "tools-inventory.json", {"schema": 1, "image_id": identity, "entries": inventory})
    stage.rename(target)
    write_json(work / "export-result.json", {"passed": True, "image_id": identity, "tools_tree": str(target),
                                               "inventory_sha256": sha256(work / "tools-inventory.json"), "entries": len(inventory),
                                               "export_evidence": evidence.name, "resumed": bool(resume_export)})
    return {"passed": True, "tools_tree": str(target), "entries": len(inventory), "private_paths_exported": False}


def verify_tools(root, label):
    identifier(label)
    work = parent(root) / label
    state = read_json(regular_file(work, "export-result.json"))
    manifest = regular_file(work, "tools-inventory.json")
    verify_file(manifest, state["inventory_sha256"])
    expected = read_json(manifest)
    tools = private_directory(work / "tools")
    if (not state.get("passed") or expected["image_id"] != state["image_id"]
            or tree_inventory(tools) != expected["entries"]):
        raise SafetyError("Exported tools filesystem changed")
    return tools


def mkosi_command(tools, work, *, build):
    command = [sys.executable, "-B", "-m", "mkosi", "--directory", str(work / "config"),
               "--tools-tree", str(tools), "--output-directory", str(work / "output"),
               "--workspace-directory", str(work / "workspace"), "--cache-directory", str(work / "cache"),
               "--package-cache-directory", str(work / "package-cache"),
               "--sandbox-tree", str(work / "sandbox"), "--history=no", "build" if build else "summary"]
    if build:
        # Full subordinate mappings, private mount/PID namespaces and NO network.
        # No sudo, host root capability, loop/block device or privileged Docker.
        command = ["unshare", "--user", "--map-root-user", "--map-auto", "--net", "--mount", "--pid", "--fork", *command]
    return command


def inspect_smoke_tar(path):
    """Read, never extract, the small set of smoke-image acceptance files."""
    with tarfile.open(path, "r:") as archive:
        members = {}
        for member in archive:
            name = member.name.removeprefix("./")
            if name in {"", "."}:
                continue
            relative_name(name, allow_backslash=True)
            if name in members:
                raise SafetyError("Duplicate smoke tar member")
            members[name] = member
        def text(name):
            member = members.get(name)
            if member is None or not member.isreg() or member.size > 8 * 1024 * 1024:
                raise SafetyError(f"Missing/invalid smoke image file: {name}")
            return archive.extractfile(member).read().decode("utf-8")
        shadow = text("etc/shadow")
        root = [row.split(":") for row in shadow.splitlines() if row.startswith("root:")]
        if len(root) != 1 or root[0][1] != "!":
            raise SafetyError("Smoke root account is not locked")
        if text("etc/machine-id").strip() not in {"", "uninitialized"}:
            raise SafetyError("Smoke image contains a provisioned machine identity")
        status = list(deb822(text("var/lib/dpkg/status")))
        systemd = [row for row in status if row.get("Package") == "systemd"]
        if (len(systemd) != 1 or systemd[0].get("Version") != "257.13-1~deb13u1"
                or systemd[0].get("Status") != "install ok installed"):
            raise SafetyError("Unexpected smoke systemd version/status")
        for name, member in members.items():
            if (name == "etc/apt/sources.list" or name.endswith(".sources") and name.startswith("etc/apt/")
                    or name in {"var/cache/ldconfig/aux-cache", "var/log/alternatives.log"}
                    or "ssh_host_" in name or name.endswith(".key") and member.isreg()):
                raise SafetyError(f"Unexpected repository/identity/key file in smoke tar: {name}")
    return {"root_locked": True, "machine_identity_unprovisioned": True,
            "systemd_version": systemd[0]["Version"], "members": len(members),
            "scope": "Selected smoke invariants, not complete hardening or secret detection"}


def smoke_image(root, tools_label, label, *, build=False):
    identifier(label)
    tools = verify_tools(root, tools_label)
    value = lock(root)
    tools_work = parent(root) / tools_label
    plan = read_json(regular_file(tools_work, "packages.json"))
    if plan["metadata_lock_sha256"] != sha256(Path(root) / "locks/debian-build.json"):
        raise SafetyError("Tools tree belongs to another snapshot")
    images = private_directory(Path(root) / "artifacts/images", create=True)
    work = images / label
    work.mkdir(mode=0o700)
    for name in ("config", "output", "workspace", "cache", "package-cache", "home", "tmp"):
        (work / name).mkdir(mode=0o700)
    recipe = regular_file(root, "image/smoke/mkosi.conf")
    shutil.copyfile(recipe, work / "config/mkosi.conf")
    sandbox = work / "sandbox"
    (sandbox / "etc/apt/sources.list.d").mkdir(parents=True)
    (sandbox / "etc/apt/sources.list.d/mkosi.sources").write_text(mkosi_sources(value))
    (sandbox / "etc/apt/apt.conf.d").mkdir()
    (sandbox / "etc/apt/apt.conf.d/99firearc-offline").write_text('Acquire::Languages "none";\n')
    repository = tools_work / "context/repository"
    check = work / "input-check"
    check.mkdir(mode=0o700)
    verify_metadata(root, repository, check)
    authority = package_index(value, repository)
    for record in plan["packages"]:
        if authority.get(record["repository"] + "/" + record["filename"]) != record:
            raise SafetyError("Image input package not in signed snapshot")
        verify_file(regular_file(repository / record["repository"], record["filename"]), record["sha256"])
    (sandbox / "etc/firearc-build").mkdir()
    shutil.copytree(repository, sandbox / "etc/firearc-build/repository")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
           "XDG_CACHE_HOME": str(work / "cache"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONPATH": str(tools / "usr/lib/python3/dist-packages"), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    write_json(work / "inputs.json", {"recipe_sha256": sha256(recipe), "builder_lock_sha256": sha256(Path(root) / "locks/debian-build.json"),
                                      "tools_inventory_sha256": sha256(tools_work / "tools-inventory.json"), "host_python": sys.version,
                                      "scope": "Unsigned, nonbootable root-build probe; never provision a device from this tar"})
    logged(work, "mkosi-version", [sys.executable, "-B", "-m", "mkosi", "--version"], env=env)
    command = mkosi_command(tools, work, build=build)
    try:
        logged(work, "mkosi-build" if build else "mkosi-summary", command, env=env, timeout=1800)
    except (SafetyError, subprocess.TimeoutExpired) as error:
        write_json(work / "result.json", {"passed": False, "built": False, "error": str(error),
                                           "scope": "Builder smoke only; failed evidence retained"})
        raise
    verify_tools(root, tools_label)
    verify_file(work / "config/mkosi.conf", sha256(recipe))
    artifacts = {path.name: sha256(path) for path in (work / "output").iterdir() if path.is_file() and not path.is_symlink()}
    if build and not any(name.endswith(".tar") for name in artifacts):
        raise SafetyError("mkosi did not produce the expected smoke root tar")
    if build:
        inspection = inspect_smoke_tar(regular_file(work / "output", "firearc-root-smoke.tar"))
        write_json(work / "inspection.json", inspection)
    write_json(work / "result.json", {"passed": True, "built": build, "artifacts": artifacts, "network": "none" if build else "not-used",
                                       "scope": "Builder smoke only, not boot-chain/verity/update/release qualification"})
    return {"passed": True, "built": build, "evidence": str(work), "artifacts": artifacts, "scope": "Nonbootable builder smoke"}
