"""File handling: sidecars, snapshots, staged atomic writes."""
import base64
import binascii
import os
import uuid

from .protocol import MAX_PAYLOAD


class FileProblem(Exception):
    """User-facing file error (missing, unreadable, invalid sidecar, ...)."""


def decrypted_name(base: str) -> str:
    """photo.jpg -> photo.decrypted.jpg; no extension -> name.decrypted."""
    root, ext = os.path.splitext(base)
    if not root or root.endswith(os.sep):  # dotfile or bare extension
        return base + ".decrypted"
    return root + ".decrypted" + ext


def companions(base: str) -> dict:
    return {
        "enc": base + ".enc",
        "key": base + ".key",
        "decrypted": decrypted_name(base),
        "hmac": base + ".hmac",
        "hmackey": base + ".hmackey",
    }


def base_from_enc(enc_path: str) -> str:
    if not enc_path.lower().endswith(".enc"):
        raise FileProblem("encrypted file must end in .enc")
    return enc_path[:-4]


def same_file(a: str, b: str) -> bool:
    if os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b)):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def read_snapshot(path: str, limit: int = MAX_PAYLOAD) -> bytes:
    """Read the file once in binary mode; refuse anything over `limit` bytes."""
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except FileNotFoundError:
        raise FileProblem(f"file not found: {path}") from None
    except OSError as e:
        raise FileProblem(f"cannot read {path}: {e.strerror or e}") from None
    if len(data) > limit:
        raise FileProblem(f"{os.path.basename(path)} exceeds the {limit}-byte limit")
    return data


def parse_b64_sidecar(text: bytes, expected_len: int = 32) -> bytes:
    try:
        s = text.decode("ascii").strip("\r\n")
    except UnicodeDecodeError:
        raise FileProblem("sidecar is not ASCII text") from None
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise FileProblem("sidecar is not valid base64") from None
    if len(s) != 44 or len(raw) != expected_len:
        raise FileProblem(f"sidecar must decode to exactly {expected_len} bytes")
    return raw


def load_sidecar(path: str) -> bytes:
    if not os.path.isfile(path):
        raise FileProblem(f"missing companion file: {path}")
    return parse_b64_sidecar(read_snapshot(path, 4096))


def encode_sidecar(raw: bytes) -> bytes:
    return base64.b64encode(raw)  # ASCII, standard padded base64


def existing(paths) -> list:
    return [p for p in paths if os.path.exists(p)]


def write_group(items: list, replace: bool = False) -> None:
    """Write several (path, bytes) pairs all-or-nothing.

    Data goes to temp files first; existing targets are moved aside and are
    restored if any later step fails, so a ciphertext/key pair is never mixed.
    """
    paths = [p for p, _ in items]
    if len(set(os.path.normcase(os.path.abspath(p)) for p in paths)) != len(paths):
        raise FileProblem("output paths collide")
    clash = existing(paths)
    if clash and not replace:
        raise FileExistsError(clash)
    tag = uuid.uuid4().hex[:8]
    temps, backups, placed = [], [], []
    try:
        for p, data in items:
            t = f"{p}.tmp{tag}"
            temps.append(t)
            with open(t, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        for p, _ in items:
            if os.path.exists(p):
                b = f"{p}.bak{tag}"
                os.replace(p, b)
                backups.append((p, b))
        for (p, _), t in zip(items, temps):
            os.replace(t, p)
            placed.append(p)
    except OSError as e:
        for p in placed:
            try:
                os.remove(p)
            except OSError:
                pass
        for p, b in backups:
            try:
                os.replace(b, p)
            except OSError:
                pass
        for t in temps:
            try:
                os.remove(t)
            except OSError:
                pass
        raise FileProblem(f"write failed, existing files left unchanged: {e.strerror or e}") from None
    for _, b in backups:
        try:
            os.remove(b)
        except OSError:
            pass
