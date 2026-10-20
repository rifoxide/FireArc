"""Offline UEFI variable-store enrollment for the device firmware image.

Injects the development PK/KEK/db and the SecureBoot/SetupMode mode flags
directly into the SMMSTORE region of the self-built firmware ROM, producing
an enrolled flash image as a first-class artifact. This is the headless
enrollment mechanism the plan calls for: no guest-side tool, no interactive
firmware menu, no OVMF-only assumptions.

The store is constructed, never patched: the pristine ROM's variable region
is fully erased, and this stage writes a complete EDK II variable store in
the exact format the pinned EDK II sources define (and the payload itself
initializes on first boot):

* a 72-byte firmware-volume header (``gEfiSystemNvDataFvGuid``, checksum
  that sums to zero over the header) followed by
* a 28-byte authenticated variable-store header
  (``gEfiAuthenticatedVariableGuid``, FORMATTED/HEALTHY) and
* ``AUTHENTICATED_VARIABLE_HEADER`` entries (60 bytes, packed) with
  variable-state ADDED, names as null-terminated UTF-16LE and entries
  aligned to 4 bytes; this payload's EDK II uses ALIGNMENT 1, so names and
  data carry no internal padding.

Only the erased SMMSTORE region changes; every other ROM byte, the flash
map and the image size stay identical. The construction is deterministic
(timestamps come from the generated .auth payloads), verified by a
double build and a full re-parse, and it fails closed: a pristine region
that is not fully erased, an enrollment that does not fit, or a re-parse
that does not reproduce exactly the intended variables all abort the stage.

The certdb variable is initialized exactly as the payload writes it (an
empty certificate database): the pinned AuthVariableLib only tracks signer
certificates there for variables other than PK/KEK/db/dbx, so enrollment
needs no certdb entries. Boot-time enforcement is proven separately (the
rejection proofs); this stage records honestly that it has not been.
"""

from pathlib import Path
import hashlib
import struct
import uuid

from . import firmware_layout, keys
from .integrity import (
    SafetyError, private_directory, read_json, regular_file, sha256, write_json,
)

SYSTEM_FV_GUID = uuid.UUID("fff12b8d-7696-4c8b-a985-2747075b4f50")
AUTH_VARSTORE_GUID = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792")
GLOBAL_VARIABLE_GUID = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
SECURITY_DATABASE_GUID = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
CERT_DB_GUID = uuid.UUID("d9bee56e-75dc-49d9-b4d7-b534210f637a")

FV_ATTRIBUTES = 0x00000E36  # as the payload initializes it (erase polarity 1)
FV_HEADER_BYTES = 0x48
VARSTORE_HEADER_BYTES = 28
VARIABLE_HEADER_BYTES = 60  # AUTHENTICATED_VARIABLE_HEADER, packed
VARIABLE_DATA = 0x55AA
VAR_ADDED = 0x3F
STORE_FORMATTED = 0x5A
STORE_HEALTHY = 0xFE
ATTR_NV_BS_RT = 0x7
ATTR_NV_BS_RT_AT = 0x27
BLOCK_SIZE = 0x10000
# The payload sizes the variable store at 64 KiB (PcdVariableStoreSize in
# UefiPayloadPkg), so the store's Size field is 0xFFB8 inside the larger
# 256 KiB SMMSTORE region; the remainder stays erased spare space.
VARSTORE_SIZE = 0x10000

MODE_FLAGS = (("SecureBoot", b"\x01"), ("SetupMode", b"\x00"))


def fv_header(region_size):
    """The 72-byte system-NV-data firmware-volume header, checksummed."""
    if region_size % BLOCK_SIZE or region_size < BLOCK_SIZE:
        raise SafetyError("Variable-store region is not a whole 64 KiB multiple")
    header = bytearray(FV_HEADER_BYTES)
    struct.pack_into("<16s", header, 0, b"\x00" * 16)
    struct.pack_into("<16sQ", header, 16, SYSTEM_FV_GUID.bytes_le, region_size)
    struct.pack_into("<4sI", header, 40, b"_FVH", FV_ATTRIBUTES)
    # HeaderLength, Checksum (placeholder), ExtHeaderOffset, Reserved, Revision.
    struct.pack_into("<HHHBB", header, 48, FV_HEADER_BYTES, 0, 0, 0, 2)
    struct.pack_into("<II", header, 56, region_size // BLOCK_SIZE, BLOCK_SIZE)
    # UINT16 words of the header must sum to zero; the checksum field fixes it.
    words = struct.unpack_from("<36H", header, 0)
    total = sum(words) & 0xFFFF
    struct.pack_into("<H", header, 50, (0x10000 - total) & 0xFFFF)
    if sum(struct.unpack_from("<36H", header, 0)) & 0xFFFF:
        raise SafetyError("Firmware-volume header checksum does not sum to zero")
    return bytes(header)


def varstore_header(region_size):
    """The 28-byte authenticated variable-store header (64 KiB store)."""
    if region_size < VARSTORE_SIZE:
        raise SafetyError("Variable-store region is smaller than the payload's store")
    header = bytearray(VARSTORE_HEADER_BYTES)
    struct.pack_into("<16sI", header, 0, AUTH_VARSTORE_GUID.bytes_le,
                     VARSTORE_SIZE - FV_HEADER_BYTES)
    header[20], header[21] = STORE_FORMATTED, STORE_HEALTHY
    return bytes(header)


def entry(name, guid, attributes, data, timestamp=b"\x00" * 16):
    """One authenticated variable entry: header, UTF-16LE name, data."""
    timestamp = bytes(timestamp)
    if len(timestamp) != 16:
        raise SafetyError(f"Variable {name} timestamp is not a 16-byte EFI_TIME")
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    if len(data) > 0xFFFFFF or len(encoded) > 0xFFFFFF:
        raise SafetyError(f"Variable {name} exceeds the size fields")
    header = bytearray(VARIABLE_HEADER_BYTES)
    struct.pack_into("<HBBI", header, 0, VARIABLE_DATA, VAR_ADDED, 0, attributes)
    struct.pack_into("<Q", header, 8, 0)  # MonotonicCount
    header[16:32] = timestamp
    struct.pack_into("<III", header, 32, 0, len(encoded), len(data))  # PubKeyIndex
    struct.pack_into("<16s", header, 44, guid.bytes_le)
    return bytes(header) + encoded + data


def timestamp_of(auth_path):
    """The EFI_TIME (first 16 bytes) of a generated .auth payload, validated."""
    auth_path = Path(auth_path)
    stamp = regular_file(auth_path.parent, auth_path.name).read_bytes()[:16]
    year, month, day, hour, minute, second = struct.unpack_from("<HBBBBB", stamp, 0)
    if not 2010 <= year <= 2099 or not 1 <= month <= 12 or not 1 <= day <= 31 \
            or hour > 23 or minute > 59 or second > 60:
        raise SafetyError(f"Authenticated payload {Path(auth_path).name} "
                          f"carries an implausible timestamp")
    return stamp


def parse_store(region):
    """Parse an authenticated variable store back into its entries.

    Returns a list of {name, guid, attributes, state, data} dictionaries.
    Parsing stops at the first erased word; anything else (a truncated
    entry, sizes beyond the store) fails closed.
    """
    if len(region) < FV_HEADER_BYTES + VARSTORE_HEADER_BYTES \
            or region[40:44] != b"_FVH" \
            or uuid.UUID(bytes_le=region[16:32]) != SYSTEM_FV_GUID:
        raise SafetyError("Region is not a system variable-store firmware volume")
    (header_length,) = struct.unpack_from("<H", region, 48)
    store = region[header_length:]
    if uuid.UUID(bytes_le=store[:16]) != AUTH_VARSTORE_GUID \
            or store[20] != STORE_FORMATTED or store[21] != STORE_HEALTHY:
        raise SafetyError("Variable store is not formatted and healthy")
    (store_size,) = struct.unpack_from("<I", store, 16)
    if store_size != VARSTORE_SIZE - FV_HEADER_BYTES or len(region) < VARSTORE_SIZE:
        raise SafetyError("Variable-store size does not follow the payload's "
                          "64 KiB variable-store convention")
    position, end, variables = header_length + VARSTORE_HEADER_BYTES, \
        header_length + store_size, []
    while position + VARIABLE_HEADER_BYTES <= end:
        (start_id, state) = struct.unpack_from("<HB", region, position)
        if start_id != VARIABLE_DATA:
            if any(byte != 0xFF for byte in region[position:end]):
                raise SafetyError("Variable store ends in non-erased garbage")
            break
        attributes = struct.unpack_from("<I", region, position + 4)[0]
        _, name_size, data_size = struct.unpack_from("<III", region, position + 32)
        guid = uuid.UUID(bytes_le=region[position + 44:position + 60])
        data_start = position + VARIABLE_HEADER_BYTES + name_size
        if data_start + data_size > end:
            raise SafetyError("Variable entry declares sizes beyond the store")
        name = region[position + VARIABLE_HEADER_BYTES:data_start] \
            .decode("utf-16-le", "replace").rstrip("\x00")
        variables.append({"name": name, "guid": str(guid), "state": state,
                          "attributes": attributes,
                          "data": bytes(region[data_start:data_start + data_size])})
        position = (data_start + data_size + 3) & ~3
    return variables


def construct_region(region_size, variables):
    """A complete variable-store region: headers, aligned entries, erased tail."""
    pieces = [fv_header(region_size), varstore_header(region_size)]
    position = FV_HEADER_BYTES + VARSTORE_HEADER_BYTES
    for variable in variables:
        record = entry(variable["name"], uuid.UUID(variable["guid"]),
                       variable["attributes"], variable["data"],
                       variable.get("timestamp", b"\x00" * 16))
        aligned = (position + 3) & ~3
        pieces.append(b"\xff" * (aligned - position))
        position = aligned + len(record)
        pieces.append(record)
    if position > VARSTORE_SIZE:
        raise SafetyError(f"Enrollment ({position} bytes) does not fit the "
                          f"{VARSTORE_SIZE}-byte variable store")
    return b"".join(pieces) + b"\xff" * (region_size - position)


def variables(root):
    """The enrollment content derived from the generated hierarchy."""
    status, directory = keys.state(root)
    if status != "complete":
        raise SafetyError("Development signing hierarchy absent; run just keys first")
    prepared = [{
        "name": "certdb", "guid": str(CERT_DB_GUID), "attributes": ATTR_NV_BS_RT_AT,
        "data": struct.pack("<I", 4),  # empty certificate database, as the payload writes it
        "timestamp": b"\x00" * 16,
    }]
    for name, guid in (("PK", GLOBAL_VARIABLE_GUID), ("KEK", GLOBAL_VARIABLE_GUID),
                       ("db", SECURITY_DATABASE_GUID)):
        prepared.append({
            "name": name, "guid": str(guid), "attributes": ATTR_NV_BS_RT_AT,
            "data": regular_file(directory, f"{name.lower()}.esl").read_bytes(),
            "timestamp": timestamp_of(regular_file(directory, f"{name.lower()}.auth")),
        })
    for name, value in MODE_FLAGS:
        prepared.append({"name": name, "guid": str(GLOBAL_VARIABLE_GUID),
                         "attributes": ATTR_NV_BS_RT, "data": value})
    return prepared


def build(root, firmware_label, label):
    """Produce the enrolled firmware image from the verified pristine ROM."""
    _, rom, _ = firmware_layout.verified_rom(root, firmware_label)
    image = bytearray(rom.read_bytes())
    fmap = firmware_layout.parse_fmap(bytes(image))
    area = next((item for item in fmap["areas"]
                 if item["name"] == firmware_layout.VARIABLE_STORE_AREA), None)
    if area is None:
        raise SafetyError("Pristine ROM has no variable-store region to enroll")
    offset, size = area["offset"], area["size"]
    if any(byte != 0xFF for byte in image[offset:offset + size]):
        raise SafetyError("Pristine variable-store region is not fully erased; "
                          "refusing to overwrite existing variables")

    enrolled_variables = variables(root)
    # Deterministic construction: build twice, require byte identity.
    region = construct_region(size, enrolled_variables)
    if region != construct_region(size, enrolled_variables):
        raise SafetyError("Variable-store construction is not byte-deterministic")
    parsed = parse_store(region)
    intended = [{"name": v["name"], "guid": v["guid"], "state": VAR_ADDED,
                 "attributes": v["attributes"], "data": v["data"]}
                for v in enrolled_variables]
    if parsed != intended:
        raise SafetyError("Constructed store does not re-parse to the "
                          "intended enrollment")

    work = private_directory(Path(root) / "build/images") / label
    work.mkdir(mode=0o700)
    output = work / "output"
    output.mkdir(mode=0o700)
    try:
        pristine = rom.read_bytes()
        image[offset:offset + size] = region
        if len(image) != len(pristine) or bytes(image[:offset]) != pristine[:offset] \
                or bytes(image[offset + size:]) != pristine[offset + size:]:
            raise SafetyError("Enrollment changed bytes outside the variable store")
        custody = read_json(regular_file(Path(root) / "secrets", "manifest.json"))
        (output / "enrolled.rom").write_bytes(image)
        (output / "enrolled.rom").chmod(0o600)
        write_json(work / "enroll.json", {
            "schema": 1,
            "firmware": {"label": firmware_label, "rom_sha256": sha256(rom),
                         "region": {"name": firmware_layout.VARIABLE_STORE_AREA,
                                    "offset": offset, "size": size}},
            "variables": [{"name": v["name"], "guid": v["guid"],
                           "attributes": v["attributes"],
                           "data_sha256": hashlib.sha256(v["data"]).hexdigest(),
                           "data_bytes": len(v["data"])} for v in enrolled_variables],
            "signer_fingerprints": {name: value["sha256_fingerprint"]
                                    for name, value in custody["certificates"].items()},
            "store_format": {"source": "pinned EDK II VariableFormat.h / "
                                       "AuthVariableLib of the firmware build",
                             "fv_header_bytes": FV_HEADER_BYTES,
                             "varstore_header_bytes": VARSTORE_HEADER_BYTES,
                             "variable_header_bytes": VARIABLE_HEADER_BYTES,
                             "alignment": 4, "name_data_padding": "none (ALIGNMENT 1)"},
            "verification": {"pristine_region_erased": True,
                             "double_build_byte_identical": True,
                             "parsed_roundtrip_matches": True,
                             "confined_to_variable_store": True,
                             "rom_bytes": len(image)},
            "scope": "Offline variable-store enrollment with development keys "
                     "(ADR 0006); boot-time enforcement is proven separately; "
                     "dbx policy and production custody remain open",
        })
        write_json(work / "result.json", {
            "passed": True,
            "artifacts": {"enrolled.rom": sha256(output / "enrolled.rom")},
            "enrolled": ["PK", "KEK", "db", "SecureBoot", "SetupMode"],
            "boot_chain_qualified": False,
            "scope": "Variable store enrolled; Secure Boot enforcement and "
                     "rejection behavior not yet proven by a boot",
        })
    except Exception as error:
        write_json(work / "result.json", {"passed": False, "error": str(error),
                                          "boot_chain_qualified": False})
        raise
    return {"passed": True, "evidence": str(work),
            "scope": "Enrolled firmware image (development hierarchy)"}
