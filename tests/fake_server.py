"""Local fake server speaking the v2 protocol (one request per connection)."""
import base64
import json
import socketserver
import struct
import threading
import time

from labclient import crypto
from labclient.protocol import recv_exact

KEY = bytes(range(32))


def frame(header: dict, payload: bytes = b"") -> bytes:
    hb = json.dumps(dict(header, payload_len=len(payload))).encode()
    return struct.pack(">I", len(hb)) + hb + payload


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        mode = srv.mode
        if mode == "hang":
            time.sleep(srv.hang_seconds)
            return
        try:
            (n,) = struct.unpack(">I", recv_exact(self.request, 4))
            hdr = json.loads(recv_exact(self.request, n))
            payload = recv_exact(self.request, hdr.get("payload_len", 0))
        except Exception:
            return
        srv.requests.append((hdr, payload))
        if mode == "error":
            out = frame({"type": "error", "detail": "error processing request"})
        elif mode == "garbage":
            out = struct.pack(">I", 5) + b"{not}"
        elif mode == "truncate":
            out = frame({"type": "decrypt_result"}, b"abc")[:-2] if False else \
                struct.pack(">I", 40) + b'{"type":"key_result"'
        elif mode == "wrongtype":
            out = frame({"type": "verify_result", "result": "VERIFIED"})
        elif mode == "badkey":
            out = frame({"type": "key_result", "key": "AAAA"})
        else:
            out = self.respond(hdr, payload)
        if mode == "fragment":
            for i in range(0, len(out), 3):
                self.request.sendall(out[i:i + 3])
                time.sleep(0.001)
        else:
            self.request.sendall(out)

    def respond(self, hdr, payload):
        t = hdr["type"]
        if t == "get_key":
            return frame({"type": "key_result", "key": base64.b64encode(KEY).decode()})
        key = base64.b64decode(hdr["key"])
        if t == "decrypt":
            try:
                if self.server.mode == "badplain":
                    return frame({"type": "decrypt_result"}, b"WRONG" + b"\0" * (len(payload) - 33))
                return frame({"type": "decrypt_result"}, crypto.aes_decrypt(key, payload))
            except Exception:
                return frame({"type": "error", "detail": "error processing request"})
        if t == "verify_hmac":
            tag = base64.b64decode(hdr["hmac"])
            ok = tag == crypto.custom_hmac(key, payload)
            return frame({"type": "verify_result", "result": "VERIFIED" if ok else "FAILED"})
        return frame({"type": "error", "detail": "error processing request"})


class FakeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, mode="ok"):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode = mode
        self.hang_seconds = 3
        self.requests = []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]

    def stop(self):
        self.shutdown()
        self.server_close()
