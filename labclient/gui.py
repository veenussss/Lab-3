"""Tkinter GUI. Network/file work runs on a worker thread; results return via a queue."""
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import config, workflow
from .files import FileProblem, companions, decrypted_name, existing, read_snapshot, same_file
from .protocol import (Client, ProtocolError, ServerError, TransportError,
                       MAX_PAYLOAD)

COLORS = {"ok": "#116611", "bad": "#aa1111", "warn": "#996600", "info": "#000000"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Client")
        self.resizable(False, False)
        cfg = config.load()
        self.q = queue.Queue()
        self.busy = False
        self.aes_key = None
        self.hmac_key = None
        self.v = {n: tk.StringVar() for n in (
            "host", "port", "user", "src", "enc", "encfile", "orig", "dec",
            "hsrc", "status", "aes_state", "hmac_state")}
        self.v["host"].set(cfg["host"])
        self.v["port"].set(str(cfg["port"]))
        self.v["user"].set(cfg["username"])
        self.v["aes_state"].set("No AES key fetched yet.")
        self.v["hmac_state"].set("No HMAC key fetched yet.")
        self.v["status"].set("Ready.")
        self.timeout = float(cfg.get("timeout", 30))
        self.buttons = {}
        self._build()
        for n in ("src", "enc", "encfile", "orig", "dec", "hsrc"):
            self.v[n].trace_add("write", lambda *a: self._refresh())
        self._refresh()
        self.after(100, self._poll)

    # ---- layout ----
    def _row(self, parent, r, label, var=None, browse=None, width=48):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=4, pady=2)
        if var is not None:
            ttk.Entry(parent, textvariable=var, width=width).grid(row=r, column=1, padx=4)
        if browse:
            ttk.Button(parent, text="Browse...", command=browse).grid(row=r, column=2, padx=4)

    def _btn(self, parent, key, text, cmd, r, c=0):
        b = ttk.Button(parent, text=text, command=cmd)
        b.grid(row=r, column=c, sticky="w", padx=4, pady=3)
        self.buttons[key] = b
        return b

    def _build(self):
        conn = ttk.LabelFrame(self, text="Connection")
        conn.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        self._row(conn, 0, "Server IP", self.v["host"])
        self._row(conn, 1, "Port", self.v["port"], width=10)
        self._row(conn, 2, "Username", self.v["user"], width=24)
        ttk.Label(conn, text="(no password is used by this protocol)").grid(row=2, column=1, sticky="e")

        aes = ttk.LabelFrame(self, text="AES-GCM round trip")
        aes.grid(row=1, column=0, sticky="ew", padx=6, pady=4)
        self._btn(aes, "aes_get", "Get AES Key", lambda: self._start("aes_get"), 0)
        ttk.Label(aes, textvariable=self.v["aes_state"]).grid(row=0, column=1, sticky="w")
        self._row(aes, 1, "File to encrypt", self.v["src"], self._b_src)
        self._row(aes, 2, "Save encrypted as", self.v["enc"], self._b_enc)
        self._btn(aes, "encrypt", "Encrypt", lambda: self._start("encrypt"), 3)
        self._row(aes, 4, "Encrypted file (.enc)", self.v["encfile"], self._b_encfile)
        self._row(aes, 5, "Original (for compare)", self.v["orig"], self._b_orig)
        self._row(aes, 6, "Save decrypted as", self.v["dec"], self._b_dec)
        self._btn(aes, "decrypt", "Decrypt via Server", lambda: self._start("decrypt"), 7)
        self._btn(aes, "compare", "Compare Files", lambda: self._start("compare"), 7, 1)

        hm = ttk.LabelFrame(self, text="Custom HMAC (SHA-256)")
        hm.grid(row=2, column=0, sticky="ew", padx=6, pady=4)
        self._btn(hm, "hmac_get", "Get HMAC Key", lambda: self._start("hmac_get"), 0)
        ttk.Label(hm, textvariable=self.v["hmac_state"]).grid(row=0, column=1, sticky="w")
        self._row(hm, 1, "File", self.v["hsrc"], self._b_hsrc)
        self._btn(hm, "hmac_calc", "Compute HMAC", lambda: self._start("hmac_calc"), 2)
        self._btn(hm, "hmac_verify", "Verify HMAC", lambda: self._start("hmac_verify"), 2, 1)

        self.bar = ttk.Progressbar(self, mode="indeterminate", length=420)
        self.bar.grid(row=3, column=0, pady=4)
        self.status = tk.Label(self, textvariable=self.v["status"], anchor="w",
                               justify="left", wraplength=560)
        self.status.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 6))

    # ---- browsers ----
    def _open(self, var, title):
        p = filedialog.askopenfilename(title=title)
        if p:
            var.set(os.path.normpath(p))
            return p

    def _b_src(self):
        p = self._open(self.v["src"], "File to encrypt")
        if p:
            self.v["enc"].set(os.path.normpath(p) + ".enc")
            self.v["encfile"].set(os.path.normpath(p) + ".enc")
            self.v["orig"].set(os.path.normpath(p))
            self.v["dec"].set(decrypted_name(os.path.normpath(p)))

    def _b_enc(self):
        p = filedialog.asksaveasfilename(title="Save encrypted as", defaultextension=".enc",
                                         initialfile=os.path.basename(self.v["src"].get()) + ".enc",
                                         confirmoverwrite=False)
        if p:
            self.v["enc"].set(os.path.normpath(p))
            self.v["encfile"].set(os.path.normpath(p))

    def _b_encfile(self):
        p = self._open(self.v["encfile"], "Encrypted file")
        if p and p.lower().endswith(".enc"):
            base = os.path.normpath(p)[:-4]
            self.v["dec"].set(decrypted_name(base))
            if not self.v["orig"].get() and os.path.isfile(base):
                self.v["orig"].set(base)

    def _b_orig(self):
        self._open(self.v["orig"], "Original file")

    def _b_dec(self):
        p = filedialog.asksaveasfilename(title="Save decrypted as", confirmoverwrite=False)
        if p:
            self.v["dec"].set(os.path.normpath(p))

    def _b_hsrc(self):
        self._open(self.v["hsrc"], "File for HMAC")

    # ---- state ----
    def _refresh(self):
        g = lambda n: self.v[n].get().strip()
        ok = {
            "aes_get": True, "hmac_get": True,
            "encrypt": bool(self.aes_key and g("src") and g("enc")),
            "decrypt": bool(g("encfile") and g("dec")),
            "compare": bool(g("orig") and g("dec")),
            "hmac_calc": bool(self.hmac_key and g("hsrc")),
            "hmac_verify": bool(g("hsrc")),
        }
        for k, b in self.buttons.items():
            b.state(["!disabled"] if ok[k] and not self.busy else ["disabled"])

    def _say(self, kind, msg):
        self.v["status"].set(msg)
        self.status.config(fg=COLORS[kind])

    def _set_busy(self, busy, msg=None):
        self.busy = busy
        if busy:
            self.bar.start(12)
            self._say("info", msg or "Working...")
        else:
            self.bar.stop()
        self._refresh()

    def _client(self):
        c = Client(self.v["host"].get(), self.v["port"].get(), self.v["user"].get(),
                   timeout=self.timeout)
        config.save({"host": c.host, "port": c.port, "username": c.username,
                     "timeout": self.timeout})
        return c

    def _confirm_replace(self, paths):
        clash = existing(paths)
        if not clash:
            return False
        names = "\n".join(clash)
        if not messagebox.askyesno("Replace files?", f"These files already exist:\n{names}\n\nReplace them?"):
            raise _Cancelled()
        return True

    # ---- actions ----
    def _start(self, action):
        if self.busy:
            return
        g = lambda n: self.v[n].get().strip()
        try:
            job = self._prepare(action, g)
        except _Cancelled:
            self._say("warn", "Cancelled; no files were changed.")
            return
        except (ValueError, FileProblem) as e:
            self._say("bad", f"Error: {e}")
            return
        fn, msg = job
        self._set_busy(True, msg)

        def run():
            try:
                self.q.put((action, True, fn()))
            except BaseException as e:  # reported to the GUI, never swallowed
                self.q.put((action, False, e))
        threading.Thread(target=run, daemon=True).start()

    def _prepare(self, action, g):
        if action in ("aes_get", "hmac_get"):
            c = self._client()
            return c.get_key, "Fetching key..."
        if action == "encrypt":
            enc, src, key = g("enc"), g("src"), self.aes_key
            rep = self._confirm_replace([enc, enc[:-4] + ".key" if enc.lower().endswith(".enc") else enc + ".key"])
            return (lambda: workflow.encrypt_file(src, enc, key, rep)), "Encrypting..."
        if action == "decrypt":
            c = self._client()
            enc, out, orig = g("encfile"), g("dec"), g("orig") or None
            rep = self._confirm_replace([out])
            return (lambda: workflow.decrypt_via_server(c, enc, out, orig, rep)), "Decrypting on server..."
        if action == "compare":
            a, b = g("orig"), g("dec")
            return (lambda: read_snapshot(a, MAX_PAYLOAD) == read_snapshot(b, MAX_PAYLOAD)), "Comparing..."
        if action == "hmac_calc":
            src, key = g("hsrc"), self.hmac_key
            rep = self._confirm_replace([companions(src)["hmac"], companions(src)["hmackey"]])
            return (lambda: workflow.compute_hmac_file(src, key, rep)), "Computing HMAC..."
        if action == "hmac_verify":
            c = self._client()
            src = g("hsrc")
            return (lambda: workflow.verify_hmac_file(c, src)), "Verifying on server..."
        raise ValueError("unknown action")

    def _poll(self):
        try:
            while True:
                self._done(*self.q.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _done(self, action, ok, res):
        self._set_busy(False)
        if not ok:
            self._fail(res)
            return
        if action == "aes_get":
            self.aes_key = res
            self.v["aes_state"].set("AES key fetched (held in memory, not shown).")
            self._say("ok", "AES key fetched.")
        elif action == "hmac_get":
            self.hmac_key = res
            self.v["hmac_state"].set("HMAC key fetched (held in memory, not shown).")
            self._say("ok", "HMAC key fetched.")
        elif action == "encrypt":
            self.v["encfile"].set(res.enc_path)
            self._say("ok", f"Encrypted ({res.size} bytes) -> {res.enc_path}\nKey saved to {res.key_path}")
        elif action == "decrypt":
            if res.status == "match":
                self._say("ok", f"SUCCESS: decrypted file is byte-identical to the original.\nSaved to {res.out_path}")
            elif res.status == "mismatch":
                self._say("bad", f"MISMATCH: decrypted file differs from the original.\nSaved to {res.out_path}")
            else:
                self._say("warn", f"Decrypted to {res.out_path}. Comparison NOT performed (no original given).")
        elif action == "compare":
            if res:
                self._say("ok", "SUCCESS: files are byte-identical.")
            else:
                self._say("bad", "MISMATCH: files differ.")
        elif action == "hmac_calc":
            self._say("ok", f"HMAC saved to {res.hmac_path}\nKey saved to {res.key_path}")
        elif action == "hmac_verify":
            if res:
                self._say("ok", "VERIFIED: server's calculation matches the saved tag.")
            else:
                self._say("bad", "NOT VERIFIED: the server says the file/key/tag do not match.")

    def _fail(self, e):
        if isinstance(e, ServerError):
            self._say("bad", f"Server error: {e}")
        elif isinstance(e, TransportError):
            self._say("bad", f"Network error: {e}")
        elif isinstance(e, ProtocolError):
            self._say("bad", f"Protocol error: {e}")
        elif isinstance(e, FileExistsError):
            self._say("bad", "Output file already exists; nothing was written.")
        elif isinstance(e, (FileProblem, ValueError)):
            self._say("bad", f"Error: {e}")
        else:
            self._say("bad", f"Unexpected error: {type(e).__name__}: {e}")


class _Cancelled(Exception):
    pass


def main():
    App().mainloop()
