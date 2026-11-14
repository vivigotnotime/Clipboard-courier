# Clipboard Courier: roadmap

Tick items off as you finish them (`[x]`). Move the **YOU ARE HERE** marker as you go.
Week estimates assume roughly 10–12 working weeks in total; adjust once the deadline is confirmed.

---

## Phase 0: Planning ✅
- [x] Proposal written and approved
- [x] Feasibility and practicality assessed
- [x] "Why not LocalSend / KDE Connect" justification drafted

## Phase 1: Setup and feasibility spikes ✅
- [x] Git identity, SSH to GitHub, repo cloned
- [x] `.gitignore` excluding keys, certs, CRLs, databases, logs, venv
- [x] Project skeleton and venv, dependencies pinned
- [x] Spike: tray icon on Hyprland
- [x] Spike: text clipboard (`wl-copy` / `wl-paste`)
- [x] Spike: region capture (`slurp` + `grim`)
- [x] Spike: image clipboard
- [ ] Loose end: PySide6 slimmed to `PySide6-Essentials`, `requirements.txt` re-frozen
- [ ] Loose end: `docs/dev-log.md` started
- [ ] Loose end: submission deadline confirmed with module leader

## Phase 2: Design ✅
- [x] `docs/design-notes.md` written, reviewed, revised and committed

---

## Phase 3: PKI and key storage (Milestone 1) · about 1.5 weeks

- [x] **Piece 1: Foundations:** identity parsing, key purposes and OIDs, device paths, encrypted keystore (35 tests)
- [x] Key-file protection decided: **B**, scrypt + AES-256-GCM key files with bound labels
- [x] **Piece 2: `ca init` and `ca fingerprint`:** CA key and self-signed certificate (`CA:TRUE, pathlen:0`, keyCertSign + cRLSign), encrypted CA key in `ca-data/`, fingerprint printing (83 tests in total)

> ### ➡️ YOU ARE HERE
> - [ ] **Piece 3: `courier enroll`:** three key pairs, three CSRs, one enrollment request file, request code
- [ ] **Piece 4: `ca sign-request`:** request code confirmation, CSR self-signature checks, matching SANs, distinct RSA-3072 keys, one active cert per device ID and purpose, CA-set extensions, response bundle (certs + `ca.crt` + CRL)
- [ ] **Piece 5: Device install:** CA fingerprint confirmation, certs match own keys, store certs and initial CRL and its number
- [ ] **Piece 6: `ca revoke` / `ca publish-crl`:** revoke all three certs of a device, increasing CRL Number, configurable `nextUpdate`
- [ ] **Piece 7: Validation module:** the certificate check rule (chain, dates, SAN, EKU, revocation) and the CRL acceptance rules (signature, issuer, number rollback, freshness)
- [ ] Milestone 1 tests pass: expired cert, foreign CA, wrong purpose, SAN mismatch, revoked cert, stale CRL, rolled-back CRL number, duplicate active cert, mismatched CSR set, wrong passphrase, wrong CA fingerprint at install

## Phase 4: Envelope library (Milestone 2) · about 2 weeks · the heart of the project
- [ ] `strict_decode()`: size limit, canonical round-trip equality, no tags or floats, nesting depth, exact schema, lengths, ranges (+ one negative test per rule)
- [ ] Record building and RSA-PSS signing with the domain-separation prefix
- [ ] `seal()`: fresh CEK and nonce, header as AES-GCM AAD, RSA-OAEP key wrap with label
- [ ] `open()`: the 13 receiver checks, in order
- [ ] SQLite replay store: atomic insert, 24 h retention, purge on startup and hourly
- [ ] Milestone 2 tests pass: flipped ciphertext bit, modified header, swapped signature, wrong recipient, forwarded record (`to_fp`), expired and future-dated records, replay (including after restart), revoked sender, Carol's cert for Bob, truncated or garbage input

## Phase 5: Relay and CLI client (Milestone 3) · about 2 weeks
- [ ] Frame codec: 4-byte length prefix, 10 MiB limit, strict decoding, message types
- [ ] Relay: asyncio TLS 1.3 server, `CERT_REQUIRED`, identity from peer cert only, `VERIFY_CRL_CHECK_LEAF`
- [ ] Relay: directory, presence, `SEND` → `DELIVER` routing, `ERR offline`, `from` check, no-content logging
- [ ] Relay: CRL reload on file change, fresh `SSLContext`, drop live sessions of revoked devices, warning before CRL expiry
- [ ] Relay enrollment with the `--relay` profile
- [ ] CLI client: `courier send --to … --text …`, `courier listen`, `courier import-crl`
- [ ] Client: relay cert and SAN check, directory cert validation, CRL handling that blocks transfers but not CRL fetching
- [ ] Milestone 3 tests pass: untrusted client, untrusted relay, copied cert without key, revoked client disconnected, relay sees no plaintext, malicious relay tampering detected, CRL rollback rejected, `ACK` shown as "Sent to relay"

## Phase 6: Desktop client (Milestone 4) · about 2 weeks
- [ ] App structure: tray in a proper class (avoids the exit segfault), `qasync` event loop
- [ ] Unlock dialog, Lock and Quit; locked state disables send and receive
- [ ] Recipient list with online status
- [ ] Send text: preview, confirm, send
- [ ] Capture screenshot: `slurp` + `grim`, preview, send
- [ ] Receive dialog: verified sender, content type, preview; Copy / Save / Discard
- [ ] Image decoding only after verification, with `QImageReader` allocation and size limits
- [ ] `accept_from` setting and the security-status display (unlocked, CRL fresh, relay connected)
- [ ] Manual end-to-end test on two devices (or two user accounts) over the LAN

## Phase 7: Hardening and extras (Milestone 5) · about 1–1.5 weeks
- [ ] Saved signed bundles (`.courier`) and `courier verify` with separate signature / trust / sender-asserted-time reporting
- [ ] Diagnostic log with reason codes, never plaintext
- [ ] Robustness: oversized, malformed and disconnect cases; optional `hypothesis` fuzzing of the decoders
- [ ] GitHub Actions running `pytest` on every push
- [ ] Code cleanup: consistent errors, docstrings, no dead code
- [ ] Optional, only if time allows: redaction, signed receipts

## Phase 8: Packaging · about 1 week
- [ ] Setup script (venv, dependencies, data directories)
- [ ] README: what it is, install, CA setup, enrollment, running the relay and client, running tests
- [ ] Demo script: one valid transfer, then each attack being rejected
- [ ] Fresh-machine test: clone, follow the README exactly, fix whatever breaks

## Phase 9: Video, report and submission · about 1–2 weeks
- [ ] Record the demo video
- [ ] Write the report (about 2,500 words) from the design notes, dev log and test results
- [ ] Check every brief requirement and marking-scheme criterion against the code, report and video
- [ ] Final repo tidy, tag a release, submit
- [ ] Prepare for the lab assessment: be ready to explain and modify any part of the code

---

## Habits for every step
- Read each piece of code until you can explain it
- Run `pytest` before every commit
- Commit small, with meaningful messages
- Add a dated line to `docs/dev-log.md`
- Update `docs/design-notes.md` when a decision changes
