"""Workflow coordination (no GUI). Each function returns a small result object."""
from dataclasses import dataclass

from . import crypto
from .files import (FileProblem, base_from_enc, companions, encode_sidecar,
                    load_sidecar, read_snapshot, same_file, write_group)
from .protocol import MAX_AES_PLAINTEXT, MAX_PAYLOAD, MIN_AES_BLOB


@dataclass
class EncryptResult:
    enc_path: str
    key_path: str
    size: int


@dataclass
class DecryptResult:
    out_path: str
    status: str  # "match" | "mismatch" | "not_compared"


@dataclass
class HmacResult:
    hmac_path: str
    key_path: str


def encrypt_file(src: str, enc_path: str, key: bytes, replace: bool = False) -> EncryptResult:
    if same_file(src, enc_path):
        raise FileProblem("output path is the same as the source file")
    data = read_snapshot(src, MAX_AES_PLAINTEXT)
    blob = crypto.aes_encrypt(key, data)
    key_path = enc_path[:-4] + ".key" if enc_path.lower().endswith(".enc") else enc_path + ".key"
    if same_file(src, key_path):
        raise FileProblem("key path is the same as the source file")
    write_group([(enc_path, blob), (key_path, encode_sidecar(key))], replace)
    return EncryptResult(enc_path, key_path, len(blob))


def decrypt_via_server(client, enc_path: str, out_path: str, original: str | None = None,
                       replace: bool = False) -> DecryptResult:
    base = base_from_enc(enc_path)
    key = load_sidecar(companions(base)["key"])
    blob = read_snapshot(enc_path, MAX_PAYLOAD)
    if len(blob) < MIN_AES_BLOB:
        raise FileProblem("encrypted file is shorter than 28 bytes")
    if same_file(out_path, enc_path) or (original and same_file(out_path, original)):
        raise FileProblem("output path would overwrite the source")
    plain = client.decrypt(key, blob)
    write_group([(out_path, plain)], replace)
    if original is None:
        return DecryptResult(out_path, "not_compared")
    orig = read_snapshot(original, MAX_PAYLOAD)
    return DecryptResult(out_path, "match" if orig == plain else "mismatch")


def compute_hmac_file(src: str, key: bytes, replace: bool = False) -> HmacResult:
    data = read_snapshot(src, MAX_PAYLOAD)
    tag = crypto.custom_hmac(key, data)
    c = companions(src)
    write_group([(c["hmac"], encode_sidecar(tag)), (c["hmackey"], encode_sidecar(key))], replace)
    return HmacResult(c["hmac"], c["hmackey"])


def verify_hmac_file(client, src: str) -> bool:
    c = companions(src)
    key = load_sidecar(c["hmackey"])
    tag = load_sidecar(c["hmac"])
    data = read_snapshot(src, MAX_PAYLOAD)
    return client.verify_hmac(key, tag, data)  # saved tag, never recomputed
