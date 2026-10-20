"""Minimal strict QMP client for the local device-control socket.

The harness speaks only what it needs — the capabilities handshake and the
system_reset/system_powerdown/quit commands — over a unix socket QEMU owns
inside a 0700 evidence directory (never a TCP socket). Anything unexpected —
a missing greeting, a server error, a closed socket, a malformed message —
fails closed with SafetyError.
"""

import json
import socket

from .integrity import SafetyError


class QmpControl:
    """One client connection to QEMU's QMP unix socket."""

    def __init__(self, path, *, timeout=60):
        self.path = path
        self.timeout = timeout
        self.socket = None
        self.stream = None

    def connect(self):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.socket.connect(str(self.path))
        self.stream = self.socket.makefile("rw", encoding="utf-8", newline="\n")
        greeting = self._read()
        if "QMP" not in greeting:
            raise SafetyError(f"QMP greeting missing on {self.path.name}")
        self.command("qmp_capabilities")
        return self

    def _read(self):
        line = self.stream.readline()
        if not line:
            raise SafetyError(f"QMP socket {self.path.name} closed unexpectedly")
        try:
            return json.loads(line)
        except ValueError as error:
            raise SafetyError(f"Malformed QMP message: {line[:200]!r}") from error

    def command(self, name, **arguments):
        request = {"execute": name}
        if arguments:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request) + "\n")
        self.stream.flush()
        while True:
            message = self._read()
            if "return" in message:
                return message["return"]
            if "error" in message:
                raise SafetyError(f"QMP command {name} failed: {message['error']}")
            # Asynchronous events (RESET, SHUTDOWN, ...) are skipped: the
            # harness drives the machine and reads outcomes from the serial
            # log and process state instead.

    def close(self):
        for handle in (self.stream, self.socket):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
        self.stream = self.socket = None
