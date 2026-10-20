"""Preliminary CycloneDX inventory of the locked root dependency closure.

Describes exactly the Debian packages planned, fetched and installed into the
unsigned root stage. Not a release SBOM: no license/vulnerability review is
implied, and firmware/bootloader components are not yet included.
"""

import hashlib
import uuid

from . import builder
from .integrity import SafetyError, identifier, read_json, regular_file, sha256, write_json

NAMESPACE = uuid.UUID("5026a9ab-cd46-5b26-8903-4a86e9509275")
VERSION = "0.1.0-dev"


def component(record):
    """One immutable snapshot package record as a CycloneDX component."""
    if record.get("architecture") not in {"all", "amd64"}:
        raise SafetyError("Unexpected package architecture in inventory")
    # purl convention: arch qualifier only for architecture-specific packages.
    qualifier = "" if record["architecture"] == "all" else "?arch=" + record["architecture"]
    reference = f"pkg:deb/debian/{record['name']}@{record['version']}{qualifier}"
    return {"type": "library", "bom-ref": reference, "name": record["name"], "version": record["version"],
            "purl": reference, "hashes": [{"alg": "SHA-256", "content": record["sha256"]}],
            "properties": [{"name": "firearc:repository", "value": record["repository"]},
                           {"name": "firearc:snapshot-path", "value": record["filename"]},
                           {"name": "firearc:bytes", "value": str(record["size"])}]}


def render(plan, snapshot):
    """Deterministic CycloneDX 1.5 document for one resolved closure."""
    records = plan["packages"]
    if not records:
        raise SafetyError("Refusing an empty dependency inventory")
    closure = builder.closure_digest(records)
    serial = uuid.uuid5(NAMESPACE, closure)
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": "urn:uuid:" + str(serial),
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "firearc", "version": VERSION}]},
            "component": {"type": "device", "bom-ref": "firearc:root-payload",
                          "name": "firearc-root", "version": VERSION},
            "properties": [{"name": "firearc:snapshot", "value": snapshot},
                           {"name": "firearc:profile", "value": plan["profile"]},
                           {"name": "firearc:package-count", "value": str(len(records))},
                           {"name": "firearc:closure-sha256", "value": closure},
                           {"name": "firearc:scope",
                            "value": "Preliminary package inventory; no license or vulnerability review"}],
        },
        "components": sorted((component(record) for record in records), key=lambda item: item["bom-ref"]),
    }


def generate(root, packages_label, label):
    identifier(packages_label)
    identifier(label)
    work = builder.parent(root) / label
    work.mkdir(mode=0o700)
    plan = read_json(regular_file(builder.parent(root) / packages_label, "packages.json"))
    if plan.get("schema") != 1 or plan.get("profile") != "root":
        raise SafetyError("Expected the resolved root package plan")
    document = render(plan, plan["snapshot"])
    output = work / "output"
    output.mkdir(mode=0o700)
    write_json(output / "sbom.json", document)
    write_json(work / "result.json", {"passed": True,
                                      "artifacts": {"sbom.json": sha256(output / "sbom.json")},
                                      "package_count": len(plan["packages"]),
                                      "scope": "Preliminary CycloneDX inventory of the locked root closure"})
    return {"passed": True, "evidence": str(work),
            "scope": "Preliminary SBOM; not a release inventory"}
