# Software Specification: Crypto Lab Client

Assignment: Homework 3 (AES Encryption and Hashing). Wire details are defined by `crypto_message_spec_v2.md`; product requirements by `requirements_v2.md`. This document specifies the software that satisfies them, one section per problem.

| ID | Problem | Section |
| --- | --- | --- |
| P1 | Fetch an AES key, encrypt a file, have the server decrypt it, get the file back | 2 |
| P2 | Fetch an HMAC key, compute the course HMAC, have the server verify it | 3 |
| P3 | Client interface (fields, state, responsiveness) | 4 |
| P4 | Message exchange with the server (shared by P1 and P2) | 5 |

Module map: `labclient/crypto.py` (pure crypto), `protocol.py` (framing and transport), `files.py` (sidecars, atomic writes), `workflow.py` (use cases), `gui.py` (Tkinter), `config.py` (local settings).

---

## 1. Common conventions

- Python 3.10+, Tkinter, `cryptography`. Runs on Windows.
- Keys are 32 bytes. On disk and on the wire they are standard padded base64 (44 ASCII characters).
- All files are read in binary mode, once per operation (a snapshot).
- Limits: JSON header 1000 bytes; payload and HMAC input file 1,048,576 bytes; AES plaintext 1,048,548 bytes; minimum AES blob 28 bytes. Empty files are valid.
- Companion files use the full original filename:

| File | Contents |
| --- | --- |
| `x.ext` | Original, never overwritten implicitly |
| `x.ext.enc` | `nonce(12) \|\| ciphertext \|\| tag(16)` |
| `x.ext.key` | AES key, base64 |
| `x.decrypted.ext` | Server-returned plaintext (default name) |
| `x.ext.hmac` | Custom HMAC tag, base64 |
| `x.ext.hmackey` | HMAC key, base64 |

---

## 2. P1: AES encryption round trip

### 2.1 Goal
Show that a file encrypted locally with a server-issued key comes back identical after the server decrypts it.

### 2.2 Inputs and outputs

| | |
| --- | --- |
| Inputs | Source file, destination `.enc` path, connection settings |
| Outputs | `.enc` blob, `.key` sidecar, decrypted file, comparison verdict |

### 2.3 Behaviour
1. **Get key.** Send `get_key`. Accept only a `key_result` whose `key` is valid base64 decoding to exactly 32 bytes. Hold the key in memory only; it is written to disk only by a successful Encrypt.
2. **Encrypt (local).**
   - Reject source files over 1,048,548 bytes before doing any work.
   - `nonce = os.urandom(12)`; `blob = nonce || AESGCM(key).encrypt(nonce, plaintext, None)`. No AAD, no padding. Blob length is plaintext length + 28.
   - Write `.enc` and `.key` as one all-or-nothing group. For a destination `chosen.bin.enc` the key goes to `chosen.bin.key`.
3. **Decrypt (server).**
   - Load the `.key` saved beside the `.enc`; never use a freshly fetched key.
   - Send `decrypt` with the key in the header and the blob as payload.
   - Accept only `decrypt_result` whose payload length is exactly `len(blob) - 28`.
   - Save the payload to the chosen output path (default `x.decrypted.ext`).
4. **Compare.** Compare the saved plaintext byte for byte with the original. Three outcomes: `match` (success), `mismatch`, `not_compared` (no original given). Only `match` may be reported as a successful round trip.

### 2.4 Acceptance criteria
- Reproduces the section 9 AES vector: key `00..1f`, nonce `00..0b`, plaintext `hello world` gives the 39-byte blob in the message spec.
- Round trip is byte-exact for empty, NUL-containing, non-UTF-8, and maximum-size files.
- Changing the nonce, ciphertext, tag, or key causes authentication failure.
- A file one byte over the limit is rejected before any file write or network traffic.
- Fetching a new key never alters existing `.key` files.

### 2.5 Failure handling

| Condition | Result |
| --- | --- |
| Missing or malformed `.key` | File error; nothing sent; no replacement key generated |
| Wrong key or modified blob | Server `error` shown as a server error |
| Output equals a source path | Refused |
| Output exists | User must confirm replacement; otherwise nothing is written |
| Write failure mid-group | Earlier files restored; no ciphertext/key mismatch left behind |

---

## 3. P2: Custom HMAC

### 3.1 Goal
Compute the course-specific HMAC locally and have the server confirm it matches its own calculation.

### 3.2 Algorithm (normative)
```
Ki = K XOR 0x36 (each of 32 bytes)
Ko = K XOR 0x5c (each of 32 bytes)
inner = SHA256(Ki || x)        # 32 raw bytes
tag   = SHA256(Ko || inner)    # 32 bytes
```
- SHA-256 comes from `cryptography.hazmat.primitives.hashes.Hash`, a fresh context per hash.
- This is deliberately not standard HMAC: no 64-byte key padding, no pre-hashing of K, and the `hmac` module is never used.

### 3.3 Behaviour
1. **Get key.** Same `get_key` call as P1, giving an independent key held in memory.
2. **Compute.** Read the file (at most 1 MiB), compute the tag, and write `.hmac` and `.hmackey` as one all-or-nothing group.
3. **Verify.** Load the saved key and tag, read the current file, send `verify_hmac` with key and tag in the header and the file as payload. The tag is **not** recomputed at this step.
4. **Result.** `VERIFIED` is success; `FAILED` is displayed as `NOT VERIFIED`. Both are valid replies. A server `error` or network failure is a different, operational-error state.

### 3.4 Acceptance criteria
- For K = `00..1f` and `hello world`: inner `05001c1f...deac`, tag `585c65e6...ff2e` (base64 `WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4=`). Empty file: `bb7a30c4...a5b3`.
- The standard HMAC value `411b9a51...8e8e` must not be produced.
- Changing one byte of a copy while keeping its old tag and key yields `NOT VERIFIED`.
- Changing the saved tag or key also yields `NOT VERIFIED`.
- Works for empty files and for sizes around 55, 56, 63, 64, 65 bytes (SHA-256 padding boundaries).

### 3.5 Failure handling
Missing or malformed `.hmac` or `.hmackey` gives a file error and nothing is sent. Files over 1 MiB are refused before sending.

---

## 4. P3: Client interface

| Area | Requirement |
| --- | --- |
| Connection | Server IP, port (default 8080, validated 1-65535), username (validated `[A-Za-z0-9_.-]{1,32}`). No password field. |
| AES section | Get AES Key, file to encrypt, save-encrypted-as, Encrypt, encrypted file, original for comparison, save-decrypted-as, Decrypt via Server, Compare Files |
| HMAC section | Get HMAC Key, file, Compute HMAC, Verify HMAC |
| Feedback | Key state ("fetched", never the key), indeterminate progress bar, coloured status line naming output locations |
| Outcomes | Distinct messages for success, mismatch, `NOT VERIFIED`, server error, network error, protocol error, file error |

Behaviour rules:
- A button is enabled only when its prerequisites exist (for example Encrypt needs a fetched key, a source and a destination).
- One action at a time. All file and network work runs on a worker thread; results return to the UI thread through a queue polled every 100 ms.
- Overwrite confirmation is asked on the UI thread before work starts. Declining cancels with no changes.
- Connection settings persist in `config.local.json` (git-ignored). Source defaults are blank.
- Keys, credentials and plaintext are never displayed or logged.

---

## 5. P4: Server message exchange

### 5.1 Framing
`[4-byte big-endian header length][UTF-8 JSON header][payload_len raw bytes]`, one TCP connection per request, closed afterwards.

### 5.2 Requests

| Command | Header fields (plus `username`, `payload_len`) | Payload |
| --- | --- | --- |
| `get_key` | none | none |
| `decrypt` | `key` | encrypted blob |
| `verify_hmac` | `key`, `hmac` | file bytes |

### 5.3 Replies

| `type` | Fields | Payload |
| --- | --- | --- |
| `key_result` | `key` | none |
| `decrypt_result` | none | plaintext |
| `verify_result` | `result` = `VERIFIED` or `FAILED` | none |
| `error` | `detail` | none |

### 5.4 Client rules
- `header_len` and `payload_len` come from actual encoded bytes. Header is checked against 1000 bytes before sending.
- Send with `sendall`. Receive with exact-read loops; an early EOF is a protocol error.
- Reject replies that are not a JSON object, have an unexpected `type`, a bad or wrong-length base64 field, or a `payload_len` that is negative, boolean, non-integer, or above 1 MiB. A missing `payload_len` means zero.
- 30-second connect/I/O timeout (configurable) plus an overall request deadline. No retries.
- A server `error` is shown with the server's own text. The client does not guess a cause, because the server gives one generic message for every failure (including an unrecognised username).

### 5.5 Test strategy
- Offline: unit tests with a local fake TCP server (`tests/fake_server.py`) covering fragmented, truncated, malformed and error replies, timeouts, and refused connections.
- Fixed vectors are checked independently of the fake server, because the fake server reuses client crypto code and therefore cannot prove correctness.
- Live: AES round trip, `VERIFIED`, and `NOT VERIFIED` on a modified test copy, reported separately from offline results.
