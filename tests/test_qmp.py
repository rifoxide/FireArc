"""Offline tests for the strict minimal QMP client."""

from pathlib import Path
import json
import socket
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from firearc import qmp
from firearc.integrity import SafetyError
from support import temporary


class FakeQmpServer(threading.Thread):
    """Speaks just enough QMP to exercise the client, one line at a time."""

    def __init__(self, path, *, script):
        super().__init__(daemon=True)
        self.path = path
        self.script = script  # {execute: list of reply messages, or "close"}

    def run(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        listener.listen(1)
        try:
            connection, _ = listener.accept()
            with connection, connection.makefile("rw", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps({"QMP": {"version": {"qemu": "9.0.0"}}}) + "\n")
                stream.flush()
                for line in stream:
                    request = json.loads(line)
                    action = self.script.get(request.get("execute"))
                    if action == "close":
                        return
                    for message in action:
                        stream.write(json.dumps(message) + "\n")
                    stream.flush()
        finally:
            listener.close()


def serve(path, script):
    server = FakeQmpServer(path, script=script)
    server.start()
    deadline = time.monotonic() + 10
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError("fake QMP server never bound its socket")
        time.sleep(0.01)
    return server


class QmpControlTests(unittest.TestCase):
    def test_handshake_and_commands_skip_events(self):
        with temporary() as work:
            path = work / "qmp.sock"
            serve(path, {"qmp_capabilities": [{"return": {}}],
                         "system_reset": [{"event": "RESET", "timestamp": {}},
                                          {"return": {}}],
                         "system_powerdown": [{"return": {}}]})
            control = qmp.QmpControl(path).connect()
            self.assertEqual(control.command("system_reset"), {})
            control.command("system_powerdown")
            control.close()

    def test_server_errors_fail_closed(self):
        with temporary() as work:
            path = work / "qmp.sock"
            serve(path, {"qmp_capabilities": [{"return": {}}],
                         "quit": [{"error": {"class": "GenericError", "desc": "no"}}]})
            control = qmp.QmpControl(path).connect()
            with self.assertRaises(SafetyError) as raised:
                control.command("quit")
            self.assertIn("quit", str(raised.exception))
            control.close()

    def test_missing_greeting_or_closed_socket_fails(self):
        with temporary() as work:
            path = work / "qmp.sock"
            serve(path, {"qmp_capabilities": [{"return": {}}],
                         "quit": [{"return": {}}]})
            control = qmp.QmpControl(path).connect()
            control.command("quit")
            # The server hangs up after quit; further commands must fail closed.
            with self.assertRaises(SafetyError):
                control.command("system_reset")
            control.close()
            control.close()  # idempotent
        with temporary() as work:
            control = qmp.QmpControl(work / "absent.sock")
            with self.assertRaises(OSError):
                control.connect()

    def test_malformed_greeting_fails_closed(self):
        with temporary() as work:
            path = work / "qmp.sock"

            class Raw(threading.Thread):
                def run(self):
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    listener.bind(str(path))
                    listener.listen(1)
                    connection, _ = listener.accept()
                    with connection, connection.makefile("rw", encoding="utf-8", newline="\n") as stream:
                        stream.write("not json at all\n")
                        stream.flush()
                        stream.readline()
                    listener.close()

            raw = Raw(daemon=True)
            raw.start()
            deadline = time.monotonic() + 10
            while not path.exists():
                if time.monotonic() > deadline:
                    raise AssertionError("raw server never bound its socket")
                time.sleep(0.01)
            with self.assertRaises(SafetyError):
                qmp.QmpControl(path).connect()


if __name__ == "__main__":
    unittest.main()
