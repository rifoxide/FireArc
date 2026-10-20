"""Offline tests for the preliminary CycloneDX root-closure inventory."""

from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import sbom
from firearc.integrity import SafetyError


def record(name="bash", version="5.2-3", architecture="amd64", repository="debian",
           filename="pool/main/b/bash/bash_5.2-3_amd64.deb", sha256="a" * 64, size=1234):
    return {"name": name, "version": version, "architecture": architecture,
            "repository": repository, "filename": filename, "sha256": sha256, "size": size}


class SbomTests(unittest.TestCase):
    def plan(self, packages):
        return {"schema": 1, "snapshot": "20261018T000000Z", "profile": "root", "packages": packages}

    def test_document_is_deterministic_sorted_and_closing_the_exact_records(self):
        coreutils = record("coreutils", "9.1-1", filename="pool/main/c/coreutils/coreutils_9.1-1_amd64.deb")
        first = sbom.render(self.plan([record(), coreutils]), "20261018T000000Z")
        second = sbom.render(self.plan([coreutils, record()]), "20261018T000000Z")
        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.5")
        self.assertTrue(first["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual([c["bom-ref"] for c in first["components"]],
                         sorted(c["bom-ref"] for c in first["components"]))
        component = first["components"][0]
        self.assertEqual(component["purl"], "pkg:deb/debian/bash@5.2-3?arch=amd64")
        self.assertEqual(component["hashes"], [{"alg": "SHA-256", "content": "a" * 64}])
        properties = {p["name"]: p["value"] for p in component["properties"]}
        self.assertEqual(properties["firearc:repository"], "debian")
        self.assertEqual(properties["firearc:snapshot-path"], "pool/main/b/bash/bash_5.2-3_amd64.deb")
        self.assertEqual(properties["firearc:bytes"], "1234")
        metadata = {p["name"]: p["value"] for p in first["metadata"]["properties"]}
        self.assertEqual(metadata["firearc:package-count"], "2")
        self.assertEqual(metadata["firearc:snapshot"], "20261018T000000Z")
        self.assertIn("no license or vulnerability review", metadata["firearc:scope"])

    def test_serial_number_tracks_the_exact_closure_content(self):
        changed_record = record(version="5.2-4", filename="pool/main/b/bash/bash_5.2-4_amd64.deb")
        base = sbom.render(self.plan([record()]), "20261018T000000Z")
        changed = sbom.render(self.plan([changed_record]), "20261018T000000Z")
        self.assertNotEqual(base["serialNumber"], changed["serialNumber"])

    def test_architecture_all_has_no_qualifier_and_unknown_is_refused(self):
        document = sbom.render(self.plan([record(architecture="all",
                                                 filename="pool/main/b/bash/bash_5.2-3_all.deb")]), "20261018T000000Z")
        self.assertEqual(document["components"][0]["purl"], "pkg:deb/debian/bash@5.2-3")
        with self.assertRaises(SafetyError):
            sbom.render(self.plan([record(architecture="riscv64")]), "20261018T000000Z")

    def test_empty_inventory_is_refused(self):
        for packages in ([], None):
            with self.subTest(packages=packages), self.assertRaises(SafetyError):
                sbom.render(self.plan(packages), "20261018T000000Z")

    def test_document_serializes_to_strict_json(self):
        document = sbom.render(self.plan([record()]), "20261018T000000Z")
        self.assertEqual(json.loads(json.dumps(document)), document)


if __name__ == "__main__":
    unittest.main()
