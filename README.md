# Crypto Lab Client (AES-GCM round trip + course HMAC)

Tkinter client for the crypto server described in `crypto_message_spec_v2.md`.

## Setup

```
pip install cryptography          # Python 3.10+, Tkinter included with python.org builds
```

Connection settings live in `config.local.json` (git-ignored; created on first
connection). Copy the shape from the file or just type values in the GUI:

```json
{"host": "<server ip>", "port": 8080, "username": "<your username>", "timeout": 30}
```

## Launch

```
python main.py
```

## Layout

| Module | Role |
| --- | --- |
| `labclient/crypto.py` | AES-GCM blob format, custom HMAC (hand-built, **not** the `hmac` module) |
| `labclient/protocol.py` | Framing, exact-read loops, timeouts, request/reply validation |
| `labclient/files.py` | Sidecar parsing, snapshots, all-or-nothing staged writes |
| `labclient/workflow.py` | Encrypt / decrypt / HMAC / verify coordination |
| `labclient/gui.py` | Tk UI; work runs on a worker thread, one action at a time |

## Offline tests

```
python -m unittest discover -s tests -t .
```

Uses a local fake TCP server and temp files; checks the spec's fixed AES, HMAC and
framing vectors independently of client/server agreement.

## Live acceptance test (needs the real server)

1. Enter IP, port, username. **Get AES Key**, pick a file, **Encrypt**.
2. **Decrypt via Server**: status must say byte-identical (SUCCESS).
3. **Get HMAC Key**, pick a file, **Compute HMAC**, then **Verify HMAC**: expect `VERIFIED`.
4. Copy the file *and* its `.hmac`/`.hmackey` to a test copy, change one byte of the copy,
   **Verify HMAC** on it: expect `NOT VERIFIED`. Never modify your original.

Offline tests do not prove live interoperability; record the live result separately.

## Notes

- The protocol is plain TCP and sends keys unencrypted. A `VERIFIED` result is not proof of identity.
- Keys are never displayed or logged. Existing files are never overwritten without confirmation.

