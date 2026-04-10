---
title: ShadowTLS V3 Protocol
date: 2023-02-06 11:00:00
updated: 2026-04-10 00:00:00
author: ihciah
---

# Version Evolution

In August 2022 the first version of ShadowTLS was implemented. V1 simply proxied the TLS handshake to evade traffic discrimination, assuming the middleman would only observe handshake traffic.

V2 added challenge-response client authentication and ApplicationData encapsulation. It works well and has not been blocked in practice. With multi-SNI support it can even operate as an SNI proxy, appearing indistinguishable from a normal TLS reverse proxy.

However, V2 still assumes the middleman will not perform traffic hijacking (see [issue #30](https://github.com/ihciah/shadow-tls/issues/30)). The [restls](https://github.com/3andne/restls) project (proposed in [issue #66](https://github.com/ihciah/shadow-tls/issues/66)) provided an innovative approach to covert server-side identity verification.

V3 addresses all known attack vectors: traffic signature detection, active probing, and traffic hijacking.

# V3 Protocol Goals

1. Defend against traffic signature detection, active probing, and traffic hijacking.
2. Easy to implement correctly.
3. Minimal awareness of TLS internals — implementers need not hack TLS libraries or implement TLS themselves.
4. Keep it simple: act only as a TCP stream proxy.

## TLS Version Support

V3 **requires TLS 1.3** from the handshake server. Test with: `openssl s_client -tls1_3 -connect example.com:443`.

BoringSSL cannot produce a valid TLS 1.2 Finished (wrong transcript hash due to patched session_id), so all modes bail on TLS 1.2. The client sends a fake encrypted request and drains the server response to complete a realistic traffic pattern before closing.

# Handshake

## Session ID Authentication

The client constructs a ClientHello with a custom 32-byte SessionID:

```
SessionID (32 bytes) = [28 random bytes] [4-byte HMAC-SHA1]
```

The HMAC is computed over the ClientHello record body (excluding the 5-byte TLS header) with the SessionID's last 4 bytes zeroed during computation. The HMAC key is the shared password.

The server verifies this HMAC to authenticate the client. On failure, the server falls back to plain TCP relay with the handshake server (indistinguishable from a real TLS reverse proxy to active probers).

## BoringSSL-Driven Handshake

The client uses **BoringSSL** (Chrome's TLS library) to drive an authentic TLS handshake, producing real TLS records:

### Normal Flow (TLS 1.3)

```
Client (boring)          Shadow-TLS Server          Handshake Server
     |                         |                         |
     |--- ClientHello -------->|--- ClientHello -------->|
     |   (session_id patched)  |   (HMAC verified)       |
     |                         |                         |
     |<-- ServerHello ---------|<-- ServerHello ----------|
     |   (session_id restored) |   (ServerRandom saved)  |
     |                         |                         |
     |   (boring processes server flight, produces CCS)  |
     |                         |                         |
     |--- CCS + fake Finished->|--- forwarded ---------->|
     |   (random AppData)      |                         |
     |                         |                         |
     |=== AEAD data phase ====>|===> Data Server =======>|
```

1. **ClientHello**: boring generates it; we save the original session_id, patch it with HMAC, and send.
2. **ServerHello**: restore original session_id (boring verifies the echo), extract ServerRandom, feed to boring.
3. **Client flight**: boring writes CCS. It then attempts to decrypt the server's encrypted extensions, which fails with BAD_DECRYPT (expected — different transcript hash). An ApplicationData record matching the exact size of a real encrypted Finished (53 bytes for SHA-256 ciphers, 69 bytes for SHA-384 ciphers) is appended as synthetic Finished.
4. **Data phase**: both sides derive AEAD keys from ServerRandom and begin authenticated relay.

### HelloRetryRequest (HRR)

If the handshake server sends a HelloRetryRequest (detected by the fixed synthetic ServerRandom defined in RFC 8446 §4.1.3), both client and server handle it:

**Client side:**
1. Feed HRR to boring → boring produces a new ClientHello (CH2).
2. CH2 must carry the **same** session_id as CH1 (RFC 8446 §4.1.2). We overwrite CH2's session_id with the patched value from CH1.
3. Save boring's new original session_id for restoring in the real ServerHello.
4. Read the real ServerHello, extract the real ServerRandom.

**Server side:**
1. Detect HRR by its synthetic ServerRandom.
2. Relay the retry ClientHello from the shadow-tls client to the handshake server.
3. Read the real ServerHello, extract the real ServerRandom for AEAD key derivation.

Double HRR is rejected as a protocol error.

### Alert Race Safety

The handshake server rejects the incorrect Finished and sends a fatal alert, but this requires a full network round trip (50–200 ms). The shadow-tls server's AEAD match happens locally in microseconds (the AEAD frame immediately follows the client flight in the TCP stream), so the handshake relay terminates before the alert arrives. During the AuthPending phase, all alerts from the handshake server are silently discarded.

Certificate verification is disabled in the BoringSSL context — boring is used only for authentic record generation, not security validation.

# Data Encapsulation

## Key Derivation

After the handshake, both sides derive initial per-direction keys using **HKDF-SHA256**:

```
okm = HKDF-SHA256(IKM=password, salt=ServerRandom, info=direction)  →  28 bytes
```

Where `direction` is `"c2s"` or `"s2c"`. Each 28-byte output is split into:
- **AES key** (first 16 bytes): AES-128-GCM encryption key
- **Base nonce** (last 12 bytes): base value for GCM nonce construction

Using ServerRandom as the HKDF salt binds keys to the specific TLS session, preventing cross-session replay.

## Perfect Forward Secrecy (PFS)

The initial key derivation depends only on the long-term `password` and the public `ServerRandom`. If the password is compromised in the future, an adversary who recorded historical traffic could decrypt all past sessions. To prevent this, ShadowTLS performs a post-handshake **X25519 ephemeral key exchange** over the authenticated AEAD channel.

### 0-RTT Design (Non-Mux)

The key exchange adds **zero additional RTT** to the data path. The client sends its ephemeral public key and immediately begins data relay; the server responds asynchronously.

```
Client                          Server
  |                               |
  |=== TLS handshake (relayed) ===|
  |                               |
  | Derive initial AEAD keys      | Derive initial AEAD keys
  |                               |
  |--- CMD_EPHEMERAL (pubkey) --->| (first AEAD frame)
  |--- preamble + data ---------->| Generate keypair, compute DH
  |                               |--- CMD_EPHEMERAL (pubkey) --->
  |                               | Rekey s2c immediately
  |                               | Install pending rekey on c2s
  | Receive CMD_EPHEMERAL         |
  | Compute DH, rekey both AEADs  |
  |--- data (new c2s key) ------->| Dual-key c2s detects transition
  |                               | Drop old c2s key permanently
```

During the brief transition window, the server maintains **dual-key decryption** on the c2s direction: it tries the current (old) key first, and on failure tries the pending (new) key. When the new key succeeds, the old key is permanently dropped. Failed decryption attempts do not advance the sequence counter, ensuring state consistency.

### 1-RTT Design (Mux)

For multiplexed sessions, the PFS exchange uses a blocking 1-RTT approach (client waits for server response before proceeding). This cost is amortized across all multiplexed connections sharing the session.

### CMD_EPHEMERAL Frame Format

```
CMD = 0x09  [32B X25519 public key]
```

### Rekeyed Key Derivation

After DH, both sides derive new AEAD keys:

```
shared_secret = X25519(my_ephemeral_secret, peer_ephemeral_public)
okm = HKDF-SHA256(IKM=shared_secret, salt=ServerRandom, info=direction)  →  28 bytes
```

The ephemeral private keys are discarded immediately after DH computation. Even if the password is compromised later, the shared secret cannot be recovered from recorded traffic.

### Security Properties

- **True PFS**: session keys depend on ephemeral DH, not just the long-term password
- **Authenticated exchange**: initial AEAD protects the key exchange — MITM requires knowing the password
- **Zero overhead for mux**: PFS exchange happens once per session, amortized across all streams
- **Backward compatible framing**: CMD_EPHEMERAL uses the same inner framing as existing commands

## Per-Frame AEAD (AES-128-GCM)

Each ApplicationData frame is independently encrypted and authenticated:

```
nonce       = base_nonce XOR (seq_be64 right-aligned to 12 bytes)
ciphertext || tag = AES-128-GCM(key, nonce, AAD=tls_header, plaintext)
```

Wire format:

```
[5B TLS header] [16B GCM tag] [encrypted: 1B CMD | 2B DATA_LEN | data | padding]
```

- **Sequence number**: 64-bit, big-endian, starts at 0, increments per frame per direction. XORed into the last 8 bytes of the base nonce.
- **AAD**: the 5-byte TLS record header, preventing header manipulation.
- **Strict sequence policy**: after authentication, any GCM failure = immediate disconnect.
- **AuthPending limits**: before first valid GCM frame, non-matching frames are discarded (max 64 KiB, max 10 seconds).

## TLS Record Compliance

All constructed ApplicationData frames **strictly respect the 16384-byte standard TLS fragment limit**:

```
TLS record payload = GCM tag(16) + inner header(3) + data + padding ≤ 16384
```

- **MAX_DATA_PER_FRAME** = 16384 − 16 − 3 = **16365 bytes**
- Each read is capped at MAX_DATA_PER_FRAME; padding is additionally clamped
- Mux mode: MAX_MUX_DATA = 16384 − 16 − 7 (mux frame header) = **16361 bytes**

**Why this matters**: TLS records exceeding 16384 bytes violate RFC 8446. Network middleboxes (firewalls, NAT, DPI) may silently truncate oversized records, causing frame misalignment and GCM verification failures. High-throughput scenarios (e.g., speedtest) are particularly sensitive.

## Inner Framing (Anti TLS-in-TLS)

Each encrypted payload carries a 3-byte inner header to prevent statistical fingerprinting of the inner protocol:

```
[CMD : 1B] [DATA_LEN : 2B big-endian] [user data : DATA_LEN bytes] [padding]
```

- `CMD = 0x01` (DATA): real user data followed by optional padding.
- `CMD = 0x00` (PADDING): pure waste frame, receiver discards entirely.

### Padding Strategy (Direction-Aware HTTP/2 Traffic Mimicry)

Real HTTP/2 over TLS has strongly asymmetric traffic patterns: clients send small frames (connection preface, SETTINGS, HEADERS), servers send large frames (DATA up to 16 KB). Using the same padding profile for both directions is a detectable fingerprint. ShadowTLS uses **direction-aware padding** inspired by [restls](https://github.com/3andne/restls)'s traffic script approach.

#### Post-Handshake Preamble Records

Before any real data flows, each side sends **1–3 padding-only AEAD records** (CMD_PADDING) to mimic the HTTP/2 connection establishment phase (SETTINGS exchange). The preamble count is randomized per connection (weighted: 50% 1 record, 35% 2, 15% 3) to prevent "data always at record N" fingerprinting.

| Role | Preamble record 0 | Subsequent preamble records |
|------|-------------------|-----------------------------|
| Client | 50 – 90 B (HTTP/2 preface + SETTINGS) | 25 – 60 B (SETTINGS_ACK, WINDOW_UPDATE) |
| Server | 40 – 90 B (SETTINGS + SETTINGS_ACK) | 30 – 70 B (control frames) |

The receiver's existing CMD_PADDING handling discards these transparently — no protocol change required. Cost: ~100–200 bytes total per connection, sent once.

#### Client → Server (C2S) Profile

| Packet | Target payload range | Mimics |
|--------|---------------------|--------|
| 0 | 50 – 100 B | HTTP/2 connection preface (24B) + SETTINGS (~24B) |
| 1 | 150 – 500 B | HTTP/2 HEADERS frame (GET/POST request) |
| 2 | 50 – 300 B | WINDOW_UPDATE, SETTINGS_ACK, small body |
| 3+ | 80 – 400 B (5%: 2000 – 8000) | Control frames / occasional large POST body |

**Tail padding (packets N+, N randomized per-connection in [4, 10]):** 5% probability of 0–512 B.

#### Server → Client (S2C) Profile

| Packet | Target payload range | Mimics |
|--------|---------------------|--------|
| 0 | 40 – 100 B | HTTP/2 SETTINGS + SETTINGS_ACK |
| 1 | 150 – 2000 B | Response HEADERS (+ possibly some DATA) |
| 2+ | 500 – 4000 B (12%: 12000 – 16000) | DATA frames / large file streaming |

**Tail padding (packets N+, N randomized per-connection in [5, 13]):** 8% probability of 0–1024 B.

Server tail padding is heavier (higher probability, wider range) because real servers produce more variable-sized frames than clients.

#### Comparison with Previous Padding

| Property | Previous | Current |
|----------|----------|---------|
| Direction awareness | Same profile both ways | Separate C2S / S2C |
| Initial sizes | 200–600 / 800–1400 | HTTP/2-realistic per direction |
| Preamble records | None | 1–3 padding-only AEAD records |
| Transition point | [5, 13] | C2S: [4, 10], S2C: [5, 13] |
| Tail probability | 5% / 0–512 B | C2S: 5% / 0–512 B, S2C: 8% / 0–1024 B |
| HTTP/2 mimicry | No | Yes (SETTINGS, HEADERS, DATA sizes) |

# Security Properties

| Attack | Defense |
|--------|---------|
| Traffic signature detection | BoringSSL produces Chrome-identical ClientHello (JA3/JA4, X25519Kyber768, GREASE) |
| Active probing | Failed session_id HMAC → transparent SNI proxy fallback |
| Traffic hijacking (data) | Per-frame AES-128-GCM with direction-separated keys |
| Password compromise (historical traffic) | X25519 ephemeral DH provides true perfect forward secrecy |
| Cross-session replay | HKDF salt = ServerRandom (unique per session) |
| In-session replay/reorder | 64-bit sequence number in GCM nonce |
| Header manipulation | TLS record header as GCM AAD |
| TLS-in-TLS fingerprinting | Direction-aware HTTP/2 padding + preamble records |
| Handshake-to-data transition fingerprint | 1–3 preamble padding records mimic HTTP/2 SETTINGS exchange |
| Traffic asymmetry fingerprint | Separate C2S (small) / S2C (large) padding profiles |
| "Data at fixed record N" fingerprint | Randomized preamble count (1–3) per connection |
| Inner payload inspection | AES-128-GCM encryption (confidentiality + integrity) |
| Oversized TLS record truncation | All frames strictly ≤ 16384-byte standard limit |
| Mux session hang | Dead session auto-detection + shutdown clears all streams |

# Multiplexing (Mux)

## Architecture

Mux allows multiple logical streams to share a single TLS tunnel, eliminating handshake overhead for subsequent connections (0 additional RTT):

```
sslocal conn 1 ──┐                              ┌── ssserver conn 1
sslocal conn 2 ──┼── shadow-tls client ═══ TLS ═══ shadow-tls server ──┼── ssserver conn 2
sslocal conn 3 ──┘     (mux write/read)          (mux dispatch)   └── ssserver conn 3
```

## Mux Frame Format (inside AEAD-encrypted inner payload)

```
CMD_MUX_SYN    = 0x02  [4B stream_id] [2B initial_window_kb]
CMD_MUX_DATA   = 0x03  [4B stream_id] [2B data_len] [data]
CMD_MUX_FIN    = 0x04  [4B stream_id]
CMD_MUX_RST    = 0x05  [4B stream_id]
```

Multiple mux frames may be coalesced into a single TLS record, up to MAX_INNER_PAYLOAD (16368 bytes).

## Session Lifecycle

1. **Creation**: first connection establishes TLS tunnel, creates MuxSession, starts read/write loops.
2. **Reuse**: subsequent connections obtain a live session from MuxPool via `open_stream()`.
3. **Health check**: `MuxSession.is_alive()` checks the `dead` flag; `has_capacity()` checks both liveness and stream count.
4. **Death & cleanup**: when read/write loop exits, `shutdown()` is called:
   - Sets `dead = true`
   - Clears all stream data channels (`streams.clear()`), causing blocked `data_rx.recv()` to return `None` immediately
   - `MuxPool.cleanup()` removes all dead sessions
5. **Recreation**: next connection finding no live session automatically establishes a new TLS tunnel.

## AuthPending (client-side)

The client mux read loop starts in AuthPending state, silently discarding handshake residue frames (NewSessionTickets, alerts) until the first valid AEAD frame arrives. Limits: 64 KiB / 10 seconds. The server side does not need this (handshake drain completes before mux dispatch).

# io_uring Safety

This implementation uses monoio (io_uring async runtime). io_uring's completion-based I/O does not support safely cancelling in-flight read operations (the buffer has been submitted to the kernel).

**Design principle**: never cancel in-flight reads via `select!`.

- **Encrypt write loops**: complete the read first, then check alert flag (not select! race)
- **Verbatim drain relay**: check stop signal and deadline after completing each read
- **Coalescing**: sleep before read (not cancel after read)

# Implementation Guide

## TLS Fingerprint

The client **MUST** produce a Chrome-identical ClientHello. This implementation uses **BoringSSL** via the `boring` crate:

- **GREASE**: Native BoringSSL (RFC 8701)
- **Cipher suites**: Chrome order (TLS 1.3 + TLS 1.2 ECDHE suites)
- **Key exchange**: X25519Kyber768Draft00 (post-quantum), X25519, P-256, P-384
- **ALPN**: `h2`, `http/1.1`
- **Signature algorithms**: Chrome order
- **Supported versions**: TLS 1.2, TLS 1.3

## Client Implementation

**Stage 1 — Handshake:**
1. Generate ClientHello via BoringSSL, save original session_id, patch with HMAC, send.
2. Read ServerHello (handle HRR if synthetic random detected), restore session_id, extract ServerRandom.
3. Continue handshake via BoringSSL until client flight is produced.
4. For TLS 1.3: append random ApplicationData as synthetic Finished.
5. Send client flight. If TLS 1.2: send fake request and bail.

**Stage 1.5 — PFS Key Exchange (0-RTT):**
1. Generate X25519 ephemeral keypair.
2. Send CMD_EPHEMERAL (0x09) + 32-byte public key as the first AEAD frame.
3. Immediately enter data relay (do not wait for server response).
4. When CMD_EPHEMERAL response arrives in the decrypt stream: compute DH shared secret, rekey both AEADs.

**Stage 2 — Data relay (no TLS library required):**
1. Derive initial `key_c2s` and `key_s2c` via HKDF-SHA256(password, ServerRandom, direction).
2. After PFS rekey: derive final keys via HKDF-SHA256(shared_secret, ServerRandom, direction).
3. **Reading from server**: parse ApplicationData, extract 16B GCM tag, decrypt with `key_s2c`. Parse inner frame, forward user data, discard padding. Handle CMD_EPHEMERAL for PFS rekey.
4. **Writing to server**: build inner frame (CMD + DATA_LEN + data + padding), encrypt with `key_c2s`, wrap in ApplicationData.

## Server Implementation

**Stage 1 — Handshake relay (no TLS library required):**
1. Read ClientHello, verify session_id HMAC. On failure: plain TCP relay (SNI proxy fallback).
2. Forward ClientHello to handshake server. Read ServerHello, extract ServerRandom. Handle HRR if detected.
3. Bidirectional relay until first AEAD-authenticated ApplicationData frame arrives from client.
4. On AEAD match: shutdown handshake server connection, signal verbatim relay to stop.

**Stage 1.5 — PFS Key Exchange:**
1. If first AEAD frame is CMD_EPHEMERAL: parse client's X25519 public key.
2. Generate server ephemeral keypair, send CMD_EPHEMERAL response.
3. Compute DH shared secret.
4. Non-mux (0-RTT): rekey `key_s2c` immediately, install pending rekey on `key_c2s` (dual-key transition).
5. Mux (1-RTT): rekey both directions, then read next data frame.

**Stage 2 — Data relay:**
1. Derive initial `key_c2s` and `key_s2c` via HKDF-SHA256(password, ServerRandom, direction).
2. After PFS: derive final keys via HKDF-SHA256(shared_secret, ServerRandom, direction).
3. **Client → Data Server**: decrypt with `key_c2s`, parse inner frame, forward user data.
4. **Data Server → Client**: encrypt with `key_s2c`, build inner frame, apply padding.
