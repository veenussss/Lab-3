## 1. Objective and scope

Build a Windows desktop client in Python 3 with Tkinter and `cryptography`. Implement two independent workflows:

1. Fetch an AES key, encrypt a selected file locally, send ciphertext and key to the server, save the returned plaintext separately, and compare it byte-for-byte with the original.
2. Fetch a separate HMAC key, compute and save the custom tag defined below, submit the file with its saved key/tag, and display the server's verification result.

Read `crypto_message_spec_v2.md` from the working folder for exact message schemas and protocol test vectors.

## 2. Inputs and interface

- Editable connection defaults: IP `18.225.10.8`, TCP port `8080`, username `vkanobay`.
- Validate port 1-65535 and username against `[A-Za-z0-9_.-]{1,32}`. The protocol does not use a password; do not transmit one or derive keys from credentials.
- Provide file/destination browsers and actions to fetch each key, encrypt, request server decryption, compare files, compute HMAC, and verify HMAC.
- Show key availability without revealing keys, operation progress, output locations, and distinct success, mismatch, verification-failure, and operational-error states.
- Keep the GUI responsive during file/network work. Prevent overlapping actions and disable actions whose prerequisites are missing.
- Keep personal connection settings in local configuration excluded from shared source.

## 3. Cryptographic requirements

### AES encryption

Fetch a 32-byte key using `get_key`. Use `cryptography`'s `AESGCM` with a fresh cryptographically random 12-byte nonce for every encryption, no associated data, and a 16-byte tag. Do not add plaintext padding.

Save raw bytes in this exact order:

```text
nonce (12 bytes) || ciphertext || authentication tag (16 bytes)
```

`AESGCM.encrypt` already returns ciphertext followed by the tag; prepend only the nonce. Output length is plaintext length + 28, including for empty files. Submit the saved blob and its matching saved key using `decrypt`. Save returned plaintext separately. Claim round-trip success only after exact byte comparison with the encryption input. When reopening old artifacts, require an original file for comparison or report that comparison was not performed.

### Custom HMAC: exact algorithm

Fetch an independent 32-byte key using `get_key`; there is no separate HMAC-key command. Let K be the decoded key bytes and x be the unchanged file bytes.

```text
Ki[j] = K[j] XOR 0x36, for j = 0..31
Ko[j] = K[j] XOR 0x5c, for j = 0..31
inner = SHA256(Ki || x)
tag   = SHA256(Ko || inner)
```

Requirements:

- `||` means byte concatenation without separators, metadata, or encoding conversions.
- XOR each key byte with the single-byte constant: `0x36` is decimal 54; `0x5c` is decimal 92.
- Ki and Ko remain **32 bytes**. Do not pad them to 64 bytes or hash K first.
- Each SHA-256 call uses a fresh `cryptography.hazmat.primitives.hashes.Hash(hashes.SHA256())` context. Feed the listed inputs in order and call `finalize()`.
- `inner` is **32 raw digest bytes**, not hexadecimal or base64 text. The outer input is therefore 64 bytes; the final tag is 32 bytes.
- The library performs SHA-256's internal padding. Add no application padding.
- This is **not standard HMAC-SHA256**. Do not use a standard HMAC helper, a single `SHA256(K || x)`, or the AES-GCM tag.
- Empty files use the same calculation with x equal to zero bytes.

Submit `verify_hmac` with the current file bytes and its **saved** key/tag. Do not regenerate the tag during verification, because that would hide file changes. Display `VERIFIED` as success and `FAILED` as `NOT VERIFIED`; distinguish both from a server `error` or network failure.

## 4. Files and state

Default companion files preserve the full original filename:

| File | Contents |
| --- | --- |
| `report.txt` | Original bytes; never implicitly overwritten |
| `report.txt.enc` | Raw AES blob |
| `report.txt.key` | AES key as standard padded base64 |
| `report.txt.decrypted` | Returned plaintext |
| `report.txt.hmac` | Custom tag as standard padded base64 |
| `report.txt.hmackey` | HMAC key as standard padded base64 |

A 32-byte key/tag encodes to 44 base64 characters. Store sidecars as ASCII text; allow a trailing line ending when loading, then validate base64 and decoded length strictly.

Selecting a base file shall locate its companions automatically. Also support reopening `.enc` directly and locating its `.key`. For custom AES destination `chosen.bin.enc`, save `chosen.bin.key` beside it. Reopening artifacts must work after restarting the app; use their saved keys, not newly fetched keys.

Read files in binary mode and use one stable snapshot per operation. Reject missing/unreadable files, invalid sidecars, and output paths that resolve to the source. Ask before replacing generated files. Stage related writes and handle failures without leaving a mismatched ciphertext/key pair or reporting partial output as success. Never silently generate replacement keys for missing sidecars. Do not log keys, credentials, plaintext, or headers containing keys.

## 5. Transport and error handling

Follow `crypto_message_spec_v2.md` exactly:

- Plain TCP, one connection per request; close on success or failure.
- Frame: 4-byte unsigned big-endian header length, UTF-8 JSON header, then raw payload.
- Calculate lengths from actual encoded bytes. Requests include `type`, `username`, and integer `payload_len`; encode key/tag fields with standard padded base64.
- Use `sendall` and exact-read loops; fragmented reads are normal, premature EOF is an error.
- Validate reply structure, expected type, fields, base64, and lengths before allocation/use. Reject negative, boolean, non-integer, or oversized lengths. Missing `payload_len` means zero as specified by v2.
- Key, verification, and error replies have no payload. Decrypted payload length must equal encrypted length minus 28.
- Use a configurable 30-second connection/I/O timeout and a bounded overall request deadline. No silent retries or fabricated explanations for generic server errors.

| Limit | Bytes |
| --- | ---: |
| JSON header | 1000 |
| Any payload / HMAC input file | 1,048,576 |
| AES plaintext | 1,048,548 |
| Minimum AES blob | 28 |

Check limits against actual bytes before encryption/transmission. Empty files are valid. This teaching protocol sends keys over plain TCP; do not describe the complete exchange as confidential or `VERIFIED` as proof of identity.

## 6. Tests and completion criteria

Automated tests run offline by default, using temporary files and a fake TCP server. Check fixed vectors independently of client/server round-trip agreement.

For K = bytes `00 01 ... 1f`, x = ASCII `hello world` without a newline:

```text
Inner SHA-256:
05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac
Custom HMAC:
585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e
Custom HMAC for empty x, same K:
bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3
```

Also pass the AES and framing vectors in `crypto_message_spec_v2.md`. Fixed nonces are permitted only in tests.

Required test coverage:

- Empty files, binary/NUL/non-UTF-8 content, Unicode/spaced filenames, and lengths around AES and SHA-256 block/padding boundaries.
- Exact size limits accepted; one byte over rejected before transmission.
- Changed AES nonce/ciphertext/tag or wrong key causes authentication failure. Changed HMAC file/tag/key produces a negative verification, without recomputing the tag.
- Fragmented frames, truncated replies, malformed JSON/base64, invalid lengths, unexpected replies, server errors, and timeouts produce clear failures without freezing the GUI.
- Missing sidecars, failed writes, cancelled selections, declined overwrite, restart/reload, and fetching a new key preserve existing files and correct key associations.
- Returned plaintext mismatch or absent original never produces a successful round-trip claim.

Deliver source code, dependency declarations, offline tests, and a README with setup, launch, and live-test instructions. Keep crypto, transport, file handling, and GUI coordination separately testable.

Live acceptance requires an AES byte-exact round trip, HMAC `VERIFIED`, and `FAILED` after changing one byte of a test copy while retaining its old tag/key. Do not alter the user's original for negative tests. Report offline and live results separately; if the server is unavailable, mark live interoperability unverified.
