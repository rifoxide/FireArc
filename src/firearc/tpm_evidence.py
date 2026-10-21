"""TCG event-log extraction and PCR replay for the Phase 5 investigation.

The development harness cannot read PCR values through sysfs under QEMU: the
kernel's tpm_tis driver deadlocks on the second per-PCR sysfs read in this
environment (observed 2026-10-21; one read succeeds, the next never returns).
The boot marker unit therefore dumps the firmware's TCG event log from
securityfs (``od -An -v -tx1`` to the serial device), which needs no TPM
command at all, and this module reconstructs the measurement state on the
host: hex extraction from the serial transcript, TCG "PC Client" log parsing
(both the fixed-SHA-1 first event and the crypto-agile records that follow),
and PCR replay per bank. Replayed values are only as trustworthy as the log;
they are cross-checked against observed boot behavior in the investigation
document, not treated as TPM-attested truth.
"""

import hashlib
import re
import struct

from .integrity import SafetyError

DUMP_BEGIN = "FIREARC_PCR_DUMP_BEGIN"
DUMP_END = "FIREARC_PCR_DUMP_END"
_HEX_LINE = re.compile(r"^(?:[0-9a-f]{2})+$", re.ASCII)

# TCG event types that appear in PC-client logs (subset; unknown values are
# preserved numerically). Used for producer mapping, not verification.
EVENT_TYPES = {
    0x00000001: "EV_POST_CODE",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_DEPRECATION",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT",
    0x00000008: "EV_SCRTM_VERSION",
    0x0000000C: "EV_COMPACT_HASH",
    0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA",
    0x00DA0000: "coreboot-config",    # coreboot vendor range (observed)
    0x80000000: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000001: "EV_EFI_VARIABLE_BOOT",
    0x80000002: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000003: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000004: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION",
    0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EDK II firmware blob (unassigned type, observed)",
    0x8000000E: "EV_EFI_VARIABLE_AUTHORITY",
}

EFI_ACTION_STRINGS = {
    b"Calling EFI Application from Boot Option":
        "EDK II boot manager launching the next boot option",
    b"Exit Boot Services Invocation":
        "EDK II invoked exit boot services",
    b"Exit Boot Services Returned with Success":
        "EDK II exited boot services into the UKI stub",
    b"Ready to Boot": "EDK II ready-to-boot event",
}

ALGORITHM_IDS = {0x0004: ("sha1", 20), 0x000B: ("sha256", 32),
                 0x000C: ("sha384", 48), 0x000D: ("sha512", 64)}


def hex_from_serial(text):
    """Extract the od-hex event-log dump between the bracket markers.

    The serial console can interleave unrelated kernel or service lines with
    the dump; only well-formed hex lines inside the brackets are accepted and
    anything else inside the window is skipped (interleaved whole lines), but
    a missing bracket fails closed.
    """
    if text.count(DUMP_BEGIN) != 1 or text.count(DUMP_END) != 1:
        raise SafetyError("Serial transcript must contain exactly one dump window")
    window = text.split(DUMP_BEGIN, 1)[1].split(DUMP_END, 1)[0]
    payload = bytearray()
    for line in window.splitlines():
        stripped = "".join(line.split())
        if not stripped:
            continue
        if len(stripped) % 2 or not _HEX_LINE.match(stripped):
            continue  # interleaved console line, not dump payload
        payload.extend(bytes.fromhex(stripped))
    if len(payload) < 64:
        raise SafetyError(f"Event-log dump is implausibly small ({len(payload)} bytes)")
    return bytes(payload)


class LogEvent:
    """One parsed TCG log record."""

    def __init__(self, index, pcr, event_type, digests, event):
        self.index = index
        self.pcr = pcr
        self.event_type = event_type
        self.digests = digests  # {algorithm-name: bytes}
        self.event = event

    def describe(self):
        name = EVENT_TYPES.get(self.event_type, hex(self.event_type))
        detail = ""
        if self.event_type == 0x80000007:
            detail = f" [{EFI_ACTION_STRINGS.get(self.event, 'unknown action')}]"
        elif self.event_type in (0x00000003, 0x00000001) and self.event:
            text = self.event.split(b"\x00", 1)[0][:60]
            detail = f" [{text.decode(errors='replace')}]"
        elif self.event_type in (0x80000000, 0x80000001, 0x8000000E) and self.event:
            # UEFI_VARIABLE_DATA: VarName GUID (16), UnicodeNameLength u64,
            # VariableDataLength u64, UnicodeName (UTF-16), VariableData.
            try:
                name_len, data_len = struct.unpack_from("<QQ", self.event, 16)
                uni = self.event[32:32 + 2 * name_len].decode("utf-16-le", errors="replace")
                detail = f" [var {uni[:40]!r} data {data_len}B]"
            except struct.error:
                pass
        elif self.event_type == 0x80000002 and self.event:
            # UEFI_IMAGE_LOAD_EVENT: the payload is the device path itself.
            tail = self.event[-6:-4] if len(self.event) >= 6 else b""
            detail = f" [device path {len(self.event)}B]"
            if tail == b"\\f":
                detail = " [device path ends in .efi]"
        return name + detail

    def as_dict(self):
        return {"index": self.index, "pcr": self.pcr,
                "type": hex(self.event_type), "producer": self.describe(),
                "digests": {name: digest.hex() for name, digest in self.digests.items()},
                "event_bytes": len(self.event)}


def parse_tcg2_log(data):
    """Parse a TCG PC-Client event log (crypto-agile after the Spec ID event)."""
    events = []
    offset = 0

    def take(size, what):
        nonlocal offset
        if offset + size > len(data):
            raise SafetyError(f"Truncated TCG log while reading {what}")
        piece = data[offset:offset + size]
        offset += size
        return piece

    # First record: fixed SHA-1 digest field, event = TCG_EfiSpecIDEventStruct.
    pcr, event_type = struct.unpack("<II", take(8, "spec-id header"))
    digest = take(20, "spec-id sha1 digest")
    (event_size,) = struct.unpack("<I", take(4, "spec-id size"))
    spec = take(event_size, "spec-id event")
    if spec[:16] != b"Spec ID Event03\x00":
        raise SafetyError("Log does not start with a TCG EfiSpecIDEvent")
    events.append(LogEvent(0, pcr, event_type, {"sha1": digest}, spec))
    # Parse the algorithm inventory from the spec-id event. Layout after the
    # 16-byte signature: platformClass u32 (16), specVersion minor/major/
    # errata + uintnSize (20..23), numberOfAlgorithms u32 (24), then the
    # algorithm entries (algorithmId u16, digestSize u16) from offset 28.
    number_of_algorithms, = struct.unpack_from("<I", spec, 24)
    algorithms = {}
    for index in range(number_of_algorithms):
        algorithm_id, digest_size = struct.unpack_from("<HH", spec, 28 + 4 * index)
        if algorithm_id not in ALGORITHM_IDS:
            raise SafetyError(f"Unknown log algorithm id {algorithm_id:#x}")
        name, expected = ALGORITHM_IDS[algorithm_id]
        if digest_size != expected:
            raise SafetyError(f"Unexpected digest size for {name}")
        algorithms[name] = digest_size

    index = 1
    while offset < len(data):
        pcr, event_type = struct.unpack("<II", take(8, "event header"))
        if index == 1 and event_type == 0x00000008:
            # Some producers write the separator still in the legacy layout;
            # handle only the agile layout and fail loudly otherwise.
            pass
        (digest_count,) = struct.unpack("<I", take(4, "digest count"))
        digests = {}
        for _ in range(digest_count):
            (algorithm_id,) = struct.unpack("<H", take(2, "algorithm id"))
            name = next((algorithm_name for known_id, (algorithm_name, _size)
                         in ALGORITHM_IDS.items() if known_id == algorithm_id), None)
            if name is None:
                raise SafetyError(f"Unknown digest algorithm {algorithm_id:#x}")
            digests[name] = take(algorithms[name], "digest")
        (event_size,) = struct.unpack("<I", take(4, "event size"))
        event = take(event_size, "event")
        events.append(LogEvent(index, pcr, event_type, digests, event))
        index += 1
    return events


def replay(events, bank="sha256", pcr_count=24):
    """Replay a bank's digests into final PCR values (extend semantics)."""
    sizes = {"sha256": 32, "sha1": 20}
    if bank not in sizes:
        raise SafetyError(f"Unsupported replay bank {bank!r}")
    hasher = hashlib.sha256 if bank == "sha256" else hashlib.sha1
    values = {index: bytes(sizes[bank]) for index in range(pcr_count)}
    for event in events:
        if bank not in event.digests:
            continue
        current = values.get(event.pcr)
        if current is None:
            raise SafetyError(f"Event references out-of-range PCR {event.pcr}")
        values[event.pcr] = hasher(current + event.digests[bank]).digest()
    return {index: value.hex() for index, value in values.items()}


def summarize(events):
    """Per-PCR producer inventory for the investigation document."""
    summary = {}
    for event in events:
        entry = summary.setdefault(event.pcr, {"extends": 0, "producers": []})
        entry["extends"] += 1
        entry["producers"].append(event.describe())
    for entry in summary.values():
        seen, unique = set(), []
        for producer in entry["producers"]:
            if producer not in seen:
                seen.add(producer)
                unique.append(producer)
        entry["producers"] = unique
    return summary
