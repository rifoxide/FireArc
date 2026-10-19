"""Small synchronous QMP client. Only local Unix sockets are supported."""

import json
from pathlib import Path
import socket
import stat
import uuid

from .integrity import SafetyError


def request(path, command):
    if command not in {"query-status", "system_reset", "system_powerdown", "quit"}:
        raise SafetyError("QMP command is not allowlisted")
    path = Path(path)
    if not stat.S_ISSOCK(path.lstat().st_mode):
        raise SafetyError("QMP endpoint is not a Unix socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        with connection.makefile("rwb", buffering=0) as stream:
            def read_message():
                line = stream.readline(1024 * 1024)
                if not line.endswith(b"\n"):
                    raise SafetyError("Missing or oversized QMP response")
                return json.loads(line)

            def exchange(operation):
                token = uuid.uuid4().hex
                stream.write(json.dumps({"execute": operation, "id": token}).encode() + b"\r\n")
                # QMP events may arrive between the request and its response.
                for _ in range(100):
                    reply = read_message()
                    if reply.get("id") == token:
                        if "error" in reply or "return" not in reply:
                            raise SafetyError(f"QMP rejected {operation}")
                        return reply["return"]
                raise SafetyError("Too many unrelated QMP messages")

            if "QMP" not in read_message():
                raise SafetyError("Missing QMP greeting")
            exchange("qmp_capabilities")
            return exchange(command)
