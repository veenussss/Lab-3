# Crypto Lab Client: Requirements (v2)

Refined from `requirements_v1.md`. The normative protocol reference is `crypto_message_spec_v2.md`; if the two disagree on wire details, the spec wins.

## 1. Objective and scope

Build a Windows desktop client in Python 3.10+ with Tkinter and the `cryptography` package. It implements two independent workflows:

1. **AES round trip.** Fetch a key, encrypt a chosen file locally, send the ciphertext and key to the server, save the returned plaintext as a separate file, and compare it byte for byte with the original.
2. **Custom HMAC.** Fetch a separate key, compute and save the tag defined in section 3, submit the file with its saved key and tag, and display the server's verdict.

## 2. Inputs and interface

- Editable connection fields: server IP, TCP port (default `8080`), username. Real values come from a git-ignored local config, never from shared source.
- Validate the port as an integer 1-65535 and the username against `[A-Za-z0-9_.-]{1,32}`. The protocol has no password: do not ask for, transmit, or derive keys from credentials.
- Controls: browsers for source and destination files, and actions to fetch each key, encrypt, decrypt via server, compare files, compute HMAC, and verify HMAC.
- Display: key availability (never the key), progress, output locations, and four distinct outcomes: success, mismatch, verification failure (`NOT VERIFIED`), and operational error (network, protocol, server, or file).
- Responsiveness: file and network work runs off the UI thread. Only one action runs at a time, and actions whose prerequisites are missing are disabled.

## 3. Cryptographic requirements

### 3.1 AES-GCM encryption

- Fetch a 32-byte key with `get_key`. Encrypt with `AESGCM`, a fresh random 12-byte nonce per encryption, no associated data, and a 16-byte tag. No plaintext padding.
- Saved blob, raw bytes: `nonce (12) || ciphertext || tag (16)`. `AESGCM.encrypt` already returns `ciphertext || tag`, so only prepend the nonce. Blob length is plaintext length + 28, including for empty files.
- Decrypt by sending the saved blob and its saved key with `decrypt`. Save the reply as a separate file.
- Report a round-trip success only after an exact byte comparison with the original. If no original is available, report "comparison not performed".
- Fixed nonces are allowed in tests only.

### 3.2 Custom HMAC (not standard HMAC)

The key K is the 32-byte result of a separate `get_key` call (there is no HMAC-key command). Let x be the unchanged file bytes.

```text
Ki = K XOR 0x36 (each byte)        Ko = K XOR 0x5c (each byte)
inner = SHA256(Ki || x)
tag   = SHA256(Ko || inner)
```

- `||` is plain byte concatenation. Ki and Ko stay 32 bytes: no padding to 64 bytes, and K is never hashed first.
- `inner` is the 32 raw digest bytes, not hex or base64. The outer hash input is therefore 64 bytes and the tag is 32 bytes.
- Use a fresh `hashes.Hash(hashes.SHA256())` from `cryptography` for each hash. Do not use the `hmac` module, a library HMAC helper, `SHA256(K || x)`, or the AES-GCM tag.
- An empty file uses the same formula with x of zero bytes.
- Verification sends the current file bytes with the **saved** key and tag. Never regenerate the tag at verification time, since that would hide file changes.
- Show `VERIFIED` as success and `FAILED` as `NOT VERIFIED`. Both are valid server answers and must look different from a server `error` or a network failure.

## 4. Files and state

| File | Contents |
| --- | --- |
| `report.txt` | Original bytes; never implicitly overwritten |
| `report.txt.enc` | Raw AES blob |
| `report.txt.key` | AES key, standard padded base64 (44 chars) |
| `report.decrypted.txt` | Plaintext returned by the server (default name) |
| `report.txt.hmac` | Custom tag, standard padded base64 |
| `report.txt.hmackey` | HMAC key, standard padded base64 |

- The default name for the decrypted file puts `.decrypted` before the original extension so the file still opens with the right program: `photo.jpg` gives `photo.decrypted.jpg`. A name with no extension gives `name.decrypted`. The user can still choose any other name, and the default never equals the original's path.
- Sidecars are ASCII text. When loading, accept a trailing line ending, then validate base64 and the decoded length (32 bytes) strictly.
- Selecting a base file locates its companions automatically. Opening a `.enc` file directly locates its `.key`. For a custom destination such as `chosen.bin.enc`, save `chosen.bin.key` beside it.
- Reopened artifacts work after an app restart and always use their saved keys, never a newly fetched one. Fetching a new key must not change existing files.
- Read files in binary mode, one snapshot per operation. Reject missing or unreadable files, invalid sidecars, and output paths that resolve to a source file.
- Ask before replacing generated files. Write related files all-or-nothing: a failure must leave no mismatched ciphertext/key pair and no partial output reported as success.
- Never silently create replacement keys for missing sidecars.
- Never log keys, credentials, plaintext, or headers containing keys.

## 5. Transport and error handling

- Plain TCP, one connection per request, closed on success and on failure.
- Frame: 4-byte unsigned big-endian header length, UTF-8 JSON header, then the raw payload. Lengths come from the actual encoded bytes.
- Requests carry `type`, `username`, and an integer `payload_len`. Key and tag fields use standard padded base64.
- Use `sendall` and exact-read loops. Fragmented reads are normal; premature EOF is an error.
- Validate each reply before use: JSON object, expected `type`, required fields, base64, and lengths. Reject negative, boolean, non-integer, or oversized lengths. A missing `payload_len` means zero.
- `key_result`, `verify_result`, and `error` replies carry no payload. The `decrypt_result` payload length must equal the encrypted length minus 28.
- Use a configurable 30-second connection/I/O timeout and a bounded overall request deadline. No silent retries. For the generic server `error`, show the server's text without inventing a cause.

| Limit | Bytes |
| --- | ---: |
| JSON header | 1000 |
| Any payload / HMAC input file | 1,048,576 |
| AES plaintext | 1,048,548 |
| Minimum AES blob | 28 |

Check limits against actual bytes before encrypting or sending. Empty files are valid. The protocol sends keys over plain TCP, so never describe the exchange as confidential or `VERIFIED` as proof of identity.

## 6. Tests and completion criteria

Automated tests run offline by default, using temporary files and a local fake TCP server. Fixed vectors are checked independently of client/server agreement.

For K = bytes `00 01 ... 1f` and x = ASCII `hello world` (no newline):

```text
Inner SHA-256: 05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac
Custom HMAC:   585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e
Empty x, same K: bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3
```

Also pass the AES and framing vectors in `crypto_message_spec_v2.md`, section 9.

Required coverage:

- Empty files; binary, NUL, and non-UTF-8 content; Unicode and spaced filenames; sizes around AES and SHA-256 block and padding boundaries.
- Exact size limits accepted; one byte over rejected before transmission.
- Changed AES nonce, ciphertext, tag, or wrong key fails authentication. Changed HMAC file, tag, or key gives a negative result without recomputing the tag.
- Fragmented frames, truncated replies, malformed JSON or base64, invalid lengths, unexpected reply types, server errors, and timeouts each give a clear failure and never freeze the GUI.
- Missing sidecars, failed writes, cancelled selections, declined overwrite, restart/reload, and fetching a new key all preserve existing files and correct key associations.
- A mismatched or unverifiable returned plaintext never yields a success claim.

Deliverables: source code, offline tests, and a README with setup (including the dependency on `cryptography`), launch, and live-test instructions. Keep crypto, transport, file handling, and GUI coordination separately testable.

**Live acceptance:** an AES byte-exact round trip, HMAC `VERIFIED`, and `NOT VERIFIED` after changing one byte of a test copy while keeping its old tag and key. Never alter the user's original for negative tests. Report offline and live results separately; if the server is unreachable, mark live interoperability as unverified.
