import base64
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag

from labclient import crypto, files, workflow
from labclient.files import FileProblem
from labclient.protocol import (Client, ProtocolError, ServerError, TransportError,
                                encode_message, validate_port, validate_username,
                                MAX_AES_PLAINTEXT, MAX_PAYLOAD)
from tests.fake_server import FakeServer, KEY

K = bytes(range(32))


def rd(path):
    with open(path, "rb") as f:
        return f.read()
HW = b"hello world"


class VectorTests(unittest.TestCase):
    def test_hmac_vectors(self):
        self.assertEqual(crypto.sha256(bytes(b ^ 0x36 for b in K), HW).hex(),
                         "05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac")
        self.assertEqual(crypto.custom_hmac(K, HW).hex(),
                         "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e")
        self.assertEqual(crypto.custom_hmac(K, b"").hex(),
                         "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3")
        self.assertEqual(base64.b64encode(crypto.custom_hmac(K, HW)).decode(),
                         "WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4=")

    def test_not_standard_hmac(self):
        import hmac, hashlib
        std = hmac.new(K, HW, hashlib.sha256).hexdigest()
        self.assertEqual(std, "411b9a51e8565e1fc79643b2a6c4672f4a3c3e573c33d0995a08748cb6128e8e")
        self.assertNotEqual(crypto.custom_hmac(K, HW).hex(), std)

    def test_aes_vector(self):
        blob = crypto.aes_encrypt(K, HW, nonce=bytes(range(12)))
        self.assertEqual(blob.hex(), "000102030405060708090a0b2f67ba77aac5b574ff2df305301c56437e2377b98ef3961c271928")
        self.assertEqual(len(blob), 39)

    def test_framing_vector(self):
        msg = encode_message({"type": "get_key", "username": "student01"})
        self.assertEqual(msg.hex(), "000000397b2274797065223a226765745f6b6579222c22757365726e616d65223a2273747564656e743031222c227061796c6f61645f6c656e223a307d")

    def test_lengths_and_boundaries(self):
        for n in (0, 1, 15, 16, 17, 31, 32, 55, 56, 63, 64, 65, 119, 120, 128, 1000):
            data = os.urandom(n)
            blob = crypto.aes_encrypt(K, data)
            self.assertEqual(len(blob), n + 28)
            self.assertEqual(crypto.aes_decrypt(K, blob), data)
            self.assertEqual(len(crypto.custom_hmac(K, data)), 32)

    def test_fresh_nonce(self):
        self.assertNotEqual(crypto.aes_encrypt(K, b"x")[:12], crypto.aes_encrypt(K, b"x")[:12])

    def test_tamper_detected(self):
        blob = crypto.aes_encrypt(K, HW)
        for i in (0, 12, len(blob) - 1):  # nonce, ciphertext, tag
            bad = bytearray(blob)
            bad[i] ^= 1
            with self.assertRaises(InvalidTag):
                crypto.aes_decrypt(K, bytes(bad))
        with self.assertRaises(InvalidTag):
            crypto.aes_decrypt(bytes(32), blob)


class NamingTests(unittest.TestCase):
    def test_decrypted_name(self):
        d = files.decrypted_name
        self.assertEqual(d("photo.jpg"), "photo.decrypted.jpg")
        self.assertEqual(d("a.tar.gz"), "a.tar.decrypted.gz")
        self.assertEqual(d("notes"), "notes.decrypted")
        self.assertEqual(d(".hidden"), ".hidden.decrypted")
        self.assertEqual(d(os.path.join("dir.v1", "noext")), os.path.join("dir.v1", "noext.decrypted"))
        self.assertNotEqual(d("x.jpg"), "x.jpg")
        self.assertEqual(files.companions("x.jpg")["decrypted"], "x.decrypted.jpg")


class ValidationTests(unittest.TestCase):
    def test_username_port(self):
        validate_username("a.b_c-1")
        for bad in ("", "a b", "x" * 33, "a\n"):
            with self.assertRaises(ValueError):
                validate_username(bad)
        self.assertEqual(validate_port("8080"), 8080)
        for bad in ("0", "65536", "abc", ""):
            with self.assertRaises(ValueError):
                validate_port(bad)


class NetTests(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer()
        self.addCleanup(self.srv.stop)

    def client(self, **kw):
        return Client("127.0.0.1", self.srv.port, "student01", **kw)

    def test_get_key_decrypt_verify(self):
        c = self.client()
        self.assertEqual(c.get_key(), KEY)
        blob = crypto.aes_encrypt(KEY, HW)
        self.assertEqual(c.decrypt(KEY, blob), HW)
        tag = crypto.custom_hmac(KEY, HW)
        self.assertTrue(c.verify_hmac(KEY, tag, HW))
        self.assertFalse(c.verify_hmac(KEY, tag, b"hello worle"))
        hdr, _ = self.srv.requests[-1]
        self.assertEqual(hdr["payload_len"], 11)

    def test_fragmented(self):
        self.srv.mode = "fragment"
        self.assertEqual(self.client().get_key(), KEY)

    def test_error_reply(self):
        self.srv.mode = "error"
        with self.assertRaises(ServerError):
            self.client().get_key()

    def test_bad_replies(self):
        for mode in ("garbage", "truncate", "badkey"):
            self.srv.mode = mode
            with self.assertRaises(ProtocolError, msg=mode):
                self.client().get_key()
        self.srv.mode = "wrongtype"
        with self.assertRaises(ProtocolError):
            self.client().get_key()

    def test_timeout(self):
        self.srv.mode = "hang"
        with self.assertRaises(TransportError):
            self.client(timeout=0.3).get_key()

    def test_connection_refused(self):
        self.srv.stop()
        with self.assertRaises(TransportError):
            self.client(timeout=1).get_key()
        self.srv = FakeServer()  # for cleanup

    def test_size_limits_before_send(self):
        c = self.client()
        n = len(self.srv.requests)
        with self.assertRaises(ValueError):
            c.verify_hmac(KEY, bytes(32), bytes(MAX_PAYLOAD + 1))
        with self.assertRaises(ValueError):
            c.decrypt(KEY, bytes(MAX_PAYLOAD + 1))
        self.assertEqual(len(self.srv.requests), n)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="lab ünï ")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.srv = FakeServer()
        self.addCleanup(self.srv.stop)
        self.c = Client("127.0.0.1", self.srv.port, "student01")

    def p(self, name):
        return os.path.join(self.d, name)

    def write(self, name, data):
        with open(self.p(name), "wb") as f:
            f.write(data)
        return self.p(name)

    def test_aes_round_trip_variants(self):
        for name, data in (("empty.bin", b""), ("nul ü.bin", b"\0\xff\xfe\x00abc"),
                           ("big.bin", os.urandom(MAX_AES_PLAINTEXT))):
            src = self.write(name, data)
            r = workflow.encrypt_file(src, src + ".enc", KEY)
            self.assertEqual(os.path.getsize(r.enc_path), len(data) + 28)
            self.assertEqual(rd(src + ".key"), base64.b64encode(KEY))
            d = workflow.decrypt_via_server(self.c, src + ".enc", src + ".decrypted", src)
            self.assertEqual(d.status, "match")
            self.assertEqual(rd(d.out_path), data)

    def test_over_limit_rejected(self):
        src = self.write("big", bytes(MAX_AES_PLAINTEXT + 1))
        with self.assertRaises(FileProblem):
            workflow.encrypt_file(src, src + ".enc", KEY)
        self.assertFalse(os.path.exists(src + ".enc"))

    def test_not_compared_and_mismatch(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", KEY)
        self.assertEqual(workflow.decrypt_via_server(self.c, src + ".enc", self.p("o1"), None).status,
                         "not_compared")
        other = self.write("b.txt", b"different")
        self.assertEqual(workflow.decrypt_via_server(self.c, src + ".enc", self.p("o2"), other).status,
                         "mismatch")

    def test_reload_uses_saved_key_after_new_fetch(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", KEY)
        # a newly fetched, different key must not touch existing sidecars
        self.assertEqual(rd(src + ".key"), base64.b64encode(KEY))
        d = workflow.decrypt_via_server(self.c, src + ".enc", self.p("out"), src)
        self.assertEqual(d.status, "match")

    def test_missing_and_invalid_sidecars(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", KEY)
        os.remove(src + ".key")
        with self.assertRaises(FileProblem):
            workflow.decrypt_via_server(self.c, src + ".enc", self.p("o"), src)
        for bad in (b"not base64!!", base64.b64encode(b"short"), base64.b64encode(KEY)[:-1]):
            self.write("a.txt.key", bad)
            with self.assertRaises(FileProblem):
                workflow.decrypt_via_server(self.c, src + ".enc", self.p("o"), src)
        self.write("a.txt.key", base64.b64encode(KEY) + b"\r\n")  # trailing newline allowed
        self.assertEqual(workflow.decrypt_via_server(self.c, src + ".enc", self.p("o"), src).status, "match")

    def test_wrong_key_server_error(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", os.urandom(32))
        self.write("a.txt.key", base64.b64encode(os.urandom(32)))
        with self.assertRaises(ServerError):
            workflow.decrypt_via_server(self.c, src + ".enc", self.p("o"), src)
        self.assertFalse(os.path.exists(self.p("o")))

    def test_server_returns_wrong_plaintext(self):
        src = self.write("a.txt", HW * 10)
        workflow.encrypt_file(src, src + ".enc", KEY)
        self.srv.mode = "badplain"
        r = workflow.decrypt_via_server(self.c, src + ".enc", self.p("o"), src)
        self.assertEqual(r.status, "mismatch")

    def test_overwrite_protection_and_same_file(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", KEY)
        old = rd(src + ".enc")
        with self.assertRaises(FileExistsError):
            workflow.encrypt_file(src, src + ".enc", KEY)
        self.assertEqual(rd(src + ".enc"), old)
        with self.assertRaises(FileProblem):
            workflow.encrypt_file(src, src, KEY, replace=True)
        with self.assertRaises(FileProblem):
            workflow.decrypt_via_server(self.c, src + ".enc", src + ".enc", None, True)
        workflow.encrypt_file(src, src + ".enc", KEY, replace=True)  # confirmed replace

    def test_failed_write_keeps_pair_consistent(self):
        src = self.write("a.txt", HW)
        workflow.encrypt_file(src, src + ".enc", KEY)
        enc, key = rd(src + ".enc"), rd(src + ".key")
        real = os.replace
        calls = {"n": 0}

        def flaky(a, b):
            calls["n"] += 1
            if calls["n"] == 4:  # fail while installing the second new file
                raise OSError(5, "boom")
            return real(a, b)
        with mock.patch("labclient.files.os.replace", flaky):
            with self.assertRaises(FileProblem):
                workflow.encrypt_file(src, src + ".enc", os.urandom(32), replace=True)
        self.assertEqual(rd(src + ".enc"), enc)
        self.assertEqual(rd(src + ".key"), key)
        self.assertEqual([f for f in os.listdir(self.d) if ".tmp" in f or ".bak" in f], [])

    def test_hmac_flow_and_negative(self):
        src = self.write("r.bin", b"\0\1\2 data")
        workflow.compute_hmac_file(src, KEY)
        self.assertEqual(rd(src + ".hmac"),
                         base64.b64encode(crypto.custom_hmac(KEY, b"\0\1\2 data")))
        self.assertTrue(workflow.verify_hmac_file(self.c, src))
        copy = self.write("copy.bin", b"\0\1\2 datb")
        shutil.copy(src + ".hmac", copy + ".hmac")
        shutil.copy(src + ".hmackey", copy + ".hmackey")
        self.assertFalse(workflow.verify_hmac_file(self.c, copy))  # old tag retained
        # changed tag / key
        self.write("r.bin.hmac", base64.b64encode(bytes(32)))
        self.assertFalse(workflow.verify_hmac_file(self.c, src))
        self.write("r.bin.hmackey", base64.b64encode(bytes(range(1, 33))))
        self.assertFalse(workflow.verify_hmac_file(self.c, src))

    def test_hmac_empty_file(self):
        src = self.write("e", b"")
        workflow.compute_hmac_file(src, K)
        self.assertTrue(workflow.verify_hmac_file(self.c, src))

    def test_hmac_missing_sidecar(self):
        src = self.write("r", b"x")
        with self.assertRaises(FileProblem):
            workflow.verify_hmac_file(self.c, src)

    def test_hmac_does_not_recompute(self):
        src = self.write("r", b"x")
        workflow.compute_hmac_file(src, K)
        self.write("r", b"y")
        self.assertFalse(workflow.verify_hmac_file(self.c, src))


if __name__ == "__main__":
    unittest.main()

