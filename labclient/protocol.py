"""Framing and transport. One TCP connection per request."""
import base64
import binascii
import json
import re
import socket
import struct
import time

MAX_HEADER = 1000
MAX_PAYLOAD = 1_048_576
MAX_AES_PLAINTEXT = MAX_PAYLOAD - 28
MIN_AES_BLOB = 28
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")


class ProtocolError(Exception):
    """Malformed, truncated or unexpected data on the wire."""


class ServerError(Exception):
    """Server replied with type=error."""


class TransportError(Exception):
    """Connect/timeout/IO failure."""


def validate_username(u: str) -> str:
    if not isinstance(u, str) or not USERNAME_RE.match(u):
        raise ValueError("username must be 1-32 chars of A-Z a-z 0-9 _ . -")
    return u


def validate_port(p) -> int:
    try:
        n = int(str(p).strip())
    except ValueError:
        raise ValueError("port must be an integer 1-65535") from None
    if not 1 <= n <= 65535:
        raise ValueError("port must be an integer 1-65535")
    return n


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d_strict(s, expected_len: int | None = None) -> bytes:
    if not isinstance(s, str):
        raise ProtocolError("expected base64 string")
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ProtocolError("invalid base64") from None
    if expected_len is not None and len(raw) != expected_len:
        raise ProtocolError(f"decoded length {len(raw)}, expected {expected_len}")
    return raw


def encode_message(header: dict, payload: bytes = b"") -> bytes:
    h = dict(header, payload_len=len(payload))
    hb = json.dumps(h, separators=(",", ":")).encode("utf-8")
    if len(hb) > MAX_HEADER:
        raise ProtocolError("header exceeds 1000 bytes")
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError("payload exceeds 1 MiB")
    return struct.pack(">I", len(hb)) + hb + payload


def recv_exact(sock, n: int, deadline: float | None = None, timeout: float | None = None) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError("request deadline exceeded")
            sock.settimeout(min(remaining, timeout) if timeout else remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed before full message received")
        buf += chunk
    return bytes(buf)


def read_message(sock, deadline: float | None = None, timeout: float | None = None):
    (hlen,) = struct.unpack(">I", recv_exact(sock, 4, deadline, timeout))
    if not 1 <= hlen <= MAX_HEADER:
        raise ProtocolError(f"invalid reply header length {hlen}")
    try:
        header = json.loads(recv_exact(sock, hlen, deadline, timeout).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("reply header is not valid UTF-8 JSON") from None
    if not isinstance(header, dict):
        raise ProtocolError("reply header is not a JSON object")
    plen = header.get("payload_len", 0)
    if isinstance(plen, bool) or not isinstance(plen, int) or plen < 0 or plen > MAX_PAYLOAD:
        raise ProtocolError("invalid payload_len in reply")
    payload = recv_exact(sock, plen, deadline, timeout) if plen else b""
    return header, payload


def exchange(host: str, port: int, header: dict, payload: bytes = b"",
             timeout: float = 30.0, overall: float = 120.0):
    """Send one request, read one reply, close. No retries."""
    msg = encode_message(header, payload)
    deadline = time.monotonic() + overall
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(msg)
            return read_message(s, deadline, timeout)
    except socket.timeout:
        raise TransportError(f"timed out (I/O timeout {timeout:g}s)") from None
    except OSError as e:
        raise TransportError(f"network error: {e}") from None


def _check(reply: dict, expected: str):
    t = reply.get("type")
    if t == "error":
        raise ServerError(str(reply.get("detail", "server reported an error")))
    if t != expected:
        raise ProtocolError(f"unexpected reply type {t!r}, expected {expected!r}")


class Client:
    def __init__(self, host, port, username, timeout=30.0, overall=120.0):
        self.host = host.strip()
        if not self.host:
            raise ValueError("server address is empty")
        self.port = validate_port(port)
        self.username = validate_username(username)
        self.timeout, self.overall = timeout, overall

    def _x(self, header, payload=b""):
        header = dict(header, username=self.username)
        return exchange(self.host, self.port, header, payload, self.timeout, self.overall)

    def get_key(self) -> bytes:
        reply, payload = self._x({"type": "get_key"})
        _check(reply, "key_result")
        if payload:
            raise ProtocolError("unexpected payload in key_result")
        return b64d_strict(reply.get("key"), 32)

    def decrypt(self, key: bytes, blob: bytes) -> bytes:
        if len(blob) < MIN_AES_BLOB or len(blob) > MAX_PAYLOAD:
            raise ValueError("encrypted file size out of range")
        reply, payload = self._x({"type": "decrypt", "key": b64e(key)}, blob)
        _check(reply, "decrypt_result")
        if len(payload) != len(blob) - 28:
            raise ProtocolError("decrypted length does not equal encrypted length minus 28")
        return payload

    def verify_hmac(self, key: bytes, tag: bytes, data: bytes) -> bool:
        if len(data) > MAX_PAYLOAD:
            raise ValueError("file exceeds 1 MiB")
        reply, payload = self._x(
            {"type": "verify_hmac", "key": b64e(key), "hmac": b64e(tag)}, data)
        _check(reply, "verify_result")
        if payload:
            raise ProtocolError("unexpected payload in verify_result")
        result = reply.get("result")
        if result == "VERIFIED":
            return True
        if result == "FAILED":
            return False
        raise ProtocolError(f"unexpected verify result {result!r}")
