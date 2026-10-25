# Clipboard Courier: design notes

---

## 1. Components and trust boundaries

| Component | Holds | Trusted for |
|---|---|---|
| **CA tool** (`ca/`) | CA private key (encrypted), issued-cert index, revocation list, CRL number counter | Issuing and revoking certificates. Run separately from the relay; the relay never sees the CA key. |
| **Relay** (`relay/`) | Its own TLS key and cert, copies of enrolled device certs, latest CRL | Routing and presence only. Treated as **honest-but-curious and possibly malicious**: it must not be able to read, forge, alter or replay content undetected. It *can* delay, drop, hide devices and withhold CRL updates; these are documented limits (section 12). |
| **Client** (`client/`) | The device's three private keys (encrypted), trust anchor, latest accepted CRL and its number, replay store | Everything end-to-end: signing, encryption, verification, consent. |

**Trust anchor:** `ca.crt`, installed on each device at enrollment through a trusted channel and accepted only after an independent fingerprint check (section 4). Clients trust nothing that does not chain to it. **The relay can never install or replace the trust anchor**; any `ca.crt` arriving over the relay connection is ignored.

---

## 2. Identity

- Each certificate carries a SAN URI: `courier://user/<user>/device/<device>`
  e.g. `courier://user/alice/device/laptop1`.
- Allowed characters in `<user>` and `<device>`: `a-z 0-9 -`, max 32 each. Reject anything else at the CA.
- **Device ID** = the SAN URI string. All three certs for one device carry the same device ID.
- **Inside signed records**, identities are bound by **SHA-256 certificate fingerprints**, not names, so a display name or relay claim can never stand in for a key.
- Display names and IP addresses are never used for authorization.

**Certificate check rule (used everywhere):** a certificate is accepted for an operation only if **all** of these hold:
1. it chains to `ca.crt` and the signature is valid;
2. it is within its validity dates;
3. its **SAN equals the device ID it is being used for** (the selected recipient, or the record's `from`);
4. its **EKU matches the operation** (TLS, signing or encryption);
5. it is not revoked according to the latest accepted, fresh CRL (section 5).

Rule 3 matters because a malicious relay could otherwise return another *legitimately enrolled* device's certificate (for example Carol's) when Bob's was requested. A valid CA signature alone is not enough.

---

## 3. Keys and certificate profiles

Algorithm for all device and CA keys: **RSA-3072** (≈128-bit security, matches the proposal).

Every device has **three key pairs, three certificates**, enforcing key separation:

| Cert | keyUsage (critical) | extendedKeyUsage | Used for |
|---|---|---|---|
| **TLS** | digitalSignature | `clientAuth` (1.3.6.1.5.5.7.3.2) | mTLS to the relay |
| **Signing** | digitalSignature, contentCommitment | `courierSigning` (2.25.72588524155360460612940102899727988603) | RSA-PSS signatures on transfer records |
| **Encryption** | keyEncipherment | `courierContentEncryption` (2.25.313126030033596718424735362180916615048) | RSA-OAEP unwrapping of per-transfer AES keys |

Relay cert: keyUsage digitalSignature; EKU `serverAuth` (1.3.6.1.5.5.7.3.1); SAN `DNS:localhost`, plus `IP:<relay LAN IP>`.

CA cert: self-signed; basicConstraints `CA:TRUE, pathlen:0` (critical); keyUsage keyCertSign, cRLSign (critical).

The two `2.25.*` OIDs are private identifiers generated from random UUIDs (the standard way to mint an OID without registering one). Code must **reject a cert whose EKU does not match the job**, e.g. a TLS cert presented as a signing cert.

**Uniqueness rule:** at most **one active certificate per device ID and purpose**. In this version, replacing a certificate requires **revoking the old one first** (no overlapping replacement period).

Validity periods:
- CA: 2 years
- Device and relay certs: 180 days
- CRL: `nextUpdate` = `thisUpdate` + 24 h by default; set with `ca publish-crl --validity`. The demo uses **1 hour** to keep the withholding window short (section 5).

---

## 4. Enrollment and proof of possession

1. Device runs `courier enroll --user alice --device laptop1`.
2. It generates the three key pairs locally, saves them encrypted (section 9) and writes **one enrollment request file**:
   ```
   request = { "v": 1, "user": "alice", "device": "laptop1",
               "csr_tls": DER, "csr_sign": DER, "csr_enc": DER }
   ```
   Each CSR is signed by its own private key, which proves possession of that key. (The encryption key signs its CSR once for this purpose only.)
   The device prints a **request code**: the first 16 hex characters of SHA-256 over the request file.
3. Admin copies the request to the CA machine and runs `ca sign-request`. The tool prints the identity and the same request code; **the admin confirms the code matches the one shown on the device** (in person or by phone). The CA then checks:
   - every CSR self-signature is valid (proof of possession);
   - all three CSRs carry the **same SAN**, which matches `user` and `device`;
   - the three public keys are **distinct**, and each is RSA-3072;
   - the identity is well-formed;
   - no **active** certificate exists for this device ID and purpose (section 3 uniqueness rule).
   The CA **sets keyUsage and EKU itself**; it never copies extensions from a CSR.
4. The CA outputs a response bundle: the three certificates, `ca.crt`, and the **current CRL**.
5. **Trust anchor installation:** the device computes the SHA-256 fingerprint of the received `ca.crt` and displays it. The admin reads out the CA fingerprint (printed by `ca init` and `ca fingerprint`). Only if they match does the device save `ca.crt` as its trust anchor. The device then checks that each certificate chains to it and matches its own public keys, and stores the initial CRL (and its number).
6. The second proof of possession happens at every connection: the TLS 1.3 handshake requires the client to sign with its TLS private key.

The relay enrolls the same way with a `--relay` profile (one key, one serverAuth certificate).

---

## 5. Revocation

**Mechanism:** a CRL signed by the CA. No OCSP (more complexity, no benefit at this scale).

**CA side**
- `ca revoke <serial|device-id> --reason keyCompromise|superseded|cessationOfOperation`, then `ca publish-crl`.
- Revoking a device revokes **all three** of its certs.
- Every published CRL carries a **CRL Number** extension that increases by one each time. The CA persists the counter.

**Distribution**
- The admin copies the new `crl.pem` to the relay's config directory; the relay reloads it on file change and forwards it to clients. The relay cannot forge a CRL, because clients check the CA signature.
- The initial CRL is delivered **at enrollment** (section 4), so a device never starts with none.

**Client acceptance rules for a CRL** (all must hold):
1. issuer equals the trust anchor's subject, and the signature verifies with the CA key;
2. `thisUpdate ≤ now + skew`;
3. its CRL Number is **greater than** the highest number previously accepted (persisted in local state), or equal with identical bytes;
4. a CRL that fails these checks is ignored; the previous one is kept.

A CRL is **fresh** while `now ≤ nextUpdate`.

**Fail closed, without deadlock**
- If the latest accepted CRL is not fresh, the client **blocks sending and accepting**, and shows "revocation information expired".
- It **does not block fetching a new CRL**: the client may still connect to the relay and receive `CRL` messages. Therefore the client does not let OpenSSL enforce CRL freshness on the relay connection. It checks the relay's certificate chain and SAN during the TLS handshake, then checks the relay certificate against its latest accepted CRL in application code, and disconnects only if that CRL lists the relay certificate as revoked.
- **Recovery:** once a fresh, valid CRL arrives, transfers unblock automatically. If the relay never supplies one, the admin can import a CRL file directly with `courier import-crl <file>`, which applies the same acceptance rules.

**Relay side**
- New handshakes from revoked certs are refused: the relay loads each new CRL into a fresh `SSLContext` with `VERIFY_CRL_CHECK_LEAF`.
- **Live sessions of revoked devices are closed** when the CRL changes, since Python's `ssl` will not do that by itself.
- Because OpenSSL rejects every client once the relay's CRL is past `nextUpdate`, the relay **logs a warning from one hour before expiry** so the admin publishes a new CRL in time.

**Documented limitation:** a malicious relay cannot forge a CRL and cannot roll a client back to an older one it has already accepted, but it **can withhold a newer CRL**. A client then keeps trusting its last accepted CRL until that CRL's `nextUpdate`, so knowledge of a revocation can be delayed by up to the CRL validity period. CRL numbers detect rollback; they cannot reveal an update the client has never received. A shorter `nextUpdate` narrows this window at the cost of more frequent publishing.

---

## 6. Transfer record and envelope

Encoding everywhere: **deterministic CBOR** (`cbor2`, `canonical=True`). Integers for times (Unix seconds, UTC).

### 6.1 Strict decoding

`canonical=True` only controls how *we* encode. Receiving is enforced separately by one `strict_decode()` function used for every incoming structure:

1. Total input size within the relevant limit (section 7).
2. Decode, then **re-encode canonically and require the bytes to equal the input exactly**. This rejects non-canonical encodings, **trailing bytes**, and **duplicate map keys** (a decoder that keeps only one value re-encodes to different bytes), whatever the library's own behavior.
3. **No CBOR tags** (rejected via a tag hook), no floats, maximum nesting depth 4.
4. Schema check: the exact set of expected keys, no extras or missing ones; each value has the expected type.
5. Exact lengths: `tid` 16 bytes, `nonce` 12, `wk` 384, fingerprints 32.
6. Range checks: integers non-negative and within sane bounds; `0 < exp - iat ≤ 300`; `ctype` one of the allowed values; body within its type's limit; text is valid UTF-8.

Each rule gets its own negative test. The **original `record_bytes`** received are what the signature is verified over; they are never re-encoded for verification.

### 6.2 Record (what gets signed)

```
record = {
  "v":       1,
  "tid":     16 random bytes,            # transfer ID
  "from":    sender device ID,
  "from_fp": SHA-256 of sender SIGNING cert,
  "to":      recipient device ID,
  "to_fp":   SHA-256 of recipient ENCRYPTION cert,
  "iat":     created time,               # sender-asserted
  "exp":     expiry time,                # iat + 300
  "ctype":   "text/plain;charset=utf-8" | "image/png",
  "body":    payload bytes
}
record_bytes = cbor_canonical(record)
sig = RSA-PSS-SHA256(sign_key, b"courier-record-v1\x00" + record_bytes)
```

- PSS: MGF1-SHA256, salt length = 32 bytes.
- The `courier-record-v1\x00` prefix is **domain separation** between signature types: a signature on a transfer record can never be mistaken for a signature on any other kind of message the signing key might later sign (for example signed receipts, if added). Saved bundles do not create a new signature; they preserve this record signature (section 11).
- Signing `to_fp` blocks **surreptitious forwarding**: Bob cannot re-encrypt Alice's signed record to Carol, because Carol sees it was addressed to someone else.

### 6.3 Envelope (what travels)

```
header = {
  "v":     1,
  "tid":   same 16 bytes as record,
  "from":  sender device ID,
  "to":    recipient device ID,
  "nonce": 12 random bytes,
  "wk":    RSA-OAEP-SHA256(recipient enc key, cek)   # 384 bytes
}
aad        = cbor_canonical(header)
inner      = cbor_canonical({"rec": record_bytes, "sig": sig})
ciphertext = AES-256-GCM(cek, nonce, inner, aad)
envelope   = cbor_canonical({"h": header, "ct": ciphertext})
```

- `cek` = 32 bytes from `os.urandom`, **fresh per transfer**; nonce fresh per transfer. A key is used exactly once, so key/nonce reuse is impossible by construction.
- OAEP: MGF1-SHA256, label `b"courier-cek-v1"`.
- The header is authenticated as AES-GCM **associated data**, so any header change fails decryption.
- The relay sees only the header (routing metadata) and ciphertext.
- **Before sealing**, the sender selects the recipient's encryption cert and applies the full certificate check rule (section 2), including SAN = selected device ID and EKU = `courierContentEncryption`.

### 6.4 Receiver checks, in this order

Order matters: the replay ID is only recorded **after** the transfer is authenticated, otherwise an attacker could poison the replay store with fake IDs.

1. Envelope size ≤ limit; `strict_decode` the envelope and header.
2. `header.to` is me; I am unlocked; my CRL is fresh.
3. Unwrap `cek` with my encryption key (OAEP).
4. AES-GCM decrypt with the header as AAD. Failure → reject.
5. `strict_decode` the inner structure and the record.
6. Header fields (`v`, `tid`, `from`, `to`) equal the record's.
7. Find the sender's signing cert for `record.from` and apply the **certificate check rule** (section 2): chain, dates, **SAN = `from`**, EKU = `courierSigning`, not revoked. Its fingerprint must equal `from_fp`.
8. Verify the signature over the original `record_bytes`.
9. `to_fp` equals the fingerprint of **my** encryption cert.
10. Time: `iat ≤ now + skew`, `now ≤ exp + skew`, and `0 < exp - iat ≤ 300`.
11. Sender is allowed by local policy (section 8).
12. Atomically insert `tid` into the replay store; already present → reject.
13. Only now: decode/display (image decoded with pixel limits, section 7).

All rejections produce a generic user-facing message and a diagnostic log line with a reason code, never plaintext.

The five-minute expiry and the replay store apply to **live transfer acceptance only**. Saved bundles are handled separately (section 11).

---

## 7. Limits

| Limit | Value |
|---|---|
| Max frame (whole protocol message) | 10 MiB |
| Max envelope | 9 MiB (leaves room for the `DELIVER` wrapper inside the frame) |
| Max body: image | 8 MiB PNG; ≤ 50 megapixels; each side ≤ 16384 px |
| Max body: text | 1 MiB, valid UTF-8 |
| Expiry window | `0 < exp - iat ≤ 300 s` |
| Clock-skew tolerance | 120 s |
| Replay-ID retention | 24 h (well above expiry + skew); purged on startup and hourly |

Images: verify first, decode second. Use `QImageReader` with `setAllocationLimit` and check `size()` before reading pixels.

---

## 8. Authorization policy

- Only devices with valid, unrevoked certs can connect or appear in the directory.
- Each client has a local `accept_from` setting: `all` (any enrolled device) or a list of device IDs. Transfers from others are rejected at check 11. This covers the proposal's "disallowed senders are blocked" test.
- The recipient must still press **Copy**, **Save** or **Discard**: verified does not mean auto-accepted.

---

## 9. Key storage and session

- Location: `~/.local/share/courier/` (dir `0700`, files `0600`), layout:
  ```
  keys/tls.key  keys/sign.key  keys/enc.key   # encrypted PKCS#8
  certs/tls.crt certs/sign.crt certs/enc.crt certs/ca.crt
  state/crl.pem  state/crl_number            # latest accepted CRL and its number
  state/replay.sqlite3
  logs/courier.log
  ```
- Private keys: PKCS#8 with `BestAvailableEncryption(passphrase)`. One passphrase unlocks all three. **To do during implementation:** record exactly which KDF and cipher the installed `cryptography` version uses, for the report.
- On startup the code refuses to load keys if file permissions are wider than `0600`.
- **Unlock** loads keys into memory for the session. **Lock** drops references, closes the relay connection and disables send/receive until re-unlock. Python cannot guarantee memory is wiped; this is a documented limitation.
- CA key: same encryption scheme, separate passphrase, separate directory (`ca-data/`, git-ignored).

---

## 10. Relay protocol

Transport: TLS 1.3 only, mutual authentication (`CERT_REQUIRED` both sides).
- Relay: `VERIFY_CRL_CHECK_LEAF` with its current CRL (section 5).
- Client: verifies the relay's chain and that its SAN matches the configured relay address during the handshake; checks relay revocation in application code (section 5).

Framing: 4-byte big-endian length, then one canonical-CBOR map with a `"t"` (type) field, decoded with `strict_decode`. Frames over 10 MiB close the connection.

| Type | Direction | Contents |
|---|---|---|
| `HELLO` | client → relay | protocol version |
| `WELCOME` | relay → client | your device ID (taken from your TLS cert), current CRL |
| `DIR` | relay → client | enrolled devices: their signing + encryption certs and online flag |
| `PRESENCE` | relay → client | device came online / went offline |
| `CRL` | relay → client | new CRL |
| `SEND` | client → relay | envelope |
| `DELIVER` | relay → client | envelope |
| `ACK` / `ERR` | relay → client | transfer ID + result or error code (e.g. `offline`, `too_large`) |
| `PING` / `PONG` | both | keep-alive every 30 s |

Relay rules:
- Identity comes **only** from the peer TLS certificate.
- On `SEND`, the relay checks `header.from` equals the sender's authenticated ID (defense in depth; the receiver checks again cryptographically).
- Online-only: if the recipient is offline, reply `ERR offline`; nothing is queued.
- The relay never logs ciphertext or bodies; it logs connection events and transfer IDs only.

**Meaning of `ACK`:** the relay accepted or forwarded the item. It does **not** prove that the recipient received, verified, displayed or accepted it, and a malicious relay can lie about delivery. The sender UI says "Sent to relay", not "Delivered". Signed receipts from the recipient remain a deferred extension.

**Directory certificates:** clients apply the certificate check rule (section 2) to every cert in `DIR`, including **SAN = the device ID it is listed under** and the correct EKU for each cert. A malicious relay can **hide** devices, but cannot substitute keys, including another enrolled device's genuine keys.

---

## 11. Saved signed bundles

When the recipient chooses **Save**, write `<name>.courier` (canonical CBOR):

```
{ "v": 1, "rec": record_bytes, "sig": sig, "chain": [sender signing cert DER] }
```

- A bundle **preserves the original record signature**; it is not newly signed by anyone.
- It contains the **content in plaintext** (the body inside `record_bytes`). It is not encrypted unless the user separately encrypts the file.

`courier verify <file>` reports results **separately**:
1. **Signature:** valid or invalid over the stored `record_bytes`, with the domain-separation prefix.
2. **Certificate trust now:** chain to `ca.crt`, SAN matches `from`, EKU `courierSigning`; revocation status against the latest accepted CRL, and whether that CRL is fresh. **Revoked or expired certificates are clearly flagged.**
3. **Details:** sender, recipient, content type, and creation time, labeled as **"sender-asserted time"**.

The tool **makes no claim that a signature predates a revocation or key compromise**. `iat` is chosen by the signer: someone holding a stolen key can sign a new record and backdate it. Proving when something was signed would need trusted timestamping, which is out of scope for this prototype.

Opening an archived bundle **does not resend it**, does not apply the five-minute expiry, and does not touch the replay store.

---

## 12. Threat model

| # | Attacker / threat | Mitigation | Test |
|---|---|---|---|
| T1 | Network eavesdropper reads content | TLS 1.3 + end-to-end AES-GCM | Capture traffic; no plaintext |
| T2 | Relay reads content | Content key wrapped to recipient only; relay never has decryption keys | Inspect relay memory/logs |
| T3 | Rogue client impersonates a user | mTLS with CA-issued certs; identity from cert | Self-signed / foreign-CA cert rejected |
| T4 | Stolen cert file without key | TLS handshake requires the private key | Copied cert fails to connect |
| T5 | Rogue relay (MITM) | Client verifies relay cert chain + SAN | Fake relay rejected |
| T6 | Tampering with ciphertext or header | AES-GCM tag over ciphertext + header AAD | Bit-flip tests rejected |
| T7 | Forged sender inside a valid envelope | RSA-PSS signature + sender cert check (SAN = `from`) | Wrong-key signature rejected |
| T8 | Malicious relay substitutes recipient keys with a forged cert | Directory certs validated against CA | Foreign-CA cert in `DIR` rejected |
| T9 | Malicious relay substitutes **another enrolled device's genuine cert** | SAN must equal the selected device ID | Carol's cert served for Bob is rejected |
| T10 | Replay of an old transfer | Unique `tid`, persistent replay store, expiry | Replay rejected, incl. after restart |
| T11 | Forwarding a signed record to someone else | `to_fp` inside signed record | Re-encrypted record rejected |
| T12 | Revoked/lost device keeps using access | CRL, fail-closed freshness, session drop | Revoked device disconnected and rejected |
| T13 | Relay serves an **older** CRL (rollback) | CRL Number persisted; lower numbers rejected | Older valid CRL rejected after newer seen |
| T14 | Relay **withholds** a newer CRL | Freshness limit (`nextUpdate`); direct `import-crl`; short demo validity | Documented: delay bounded by CRL validity |
| T15 | Trust anchor substituted at enrollment | Out-of-band CA fingerprint check; relay cannot install `ca.crt` | Wrong `ca.crt` refused at enrollment |
| T16 | Key used for the wrong purpose | Separate keys, EKU enforced | TLS cert as signing cert rejected |
| T17 | Malformed / huge input (DoS, decoder bugs) | Size limits, strict decoding, image limits after verification | Duplicate keys, trailing bytes, tags, oversize all rejected |
| T18 | Stolen key files at rest | Encrypted PKCS#8, file permissions | Wrong passphrase fails to load |
| T19 | Relay falsely reports delivery | `ACK` defined as relay-only; UI says "Sent to relay" | Documented; receipts deferred |
| T20 | Backdated bundle signed with a stolen key | Verify reports current cert status; time labeled sender-asserted | Revoked-signer bundle flagged |

**Out of scope (documented limitations):** compromised endpoints, relay seeing routing metadata, CRL withholding up to `nextUpdate`, OS clipboard history, accepted copies and saved bundles outliving expiry, no proof of signing time, no end-to-end forward secrecy (static RSA wrapping), no secure memory wipe in Python.

---

## 13. Open questions

- Is 180-day device validity right, or should the demo use short validity to show expiry? (Can issue one short-lived cert just for the expiry test.)
- Check during implementation how `cbor2` behaves on duplicate keys and trailing bytes, and confirm the round-trip rule in 6.1 catches both. Write the tests first.

