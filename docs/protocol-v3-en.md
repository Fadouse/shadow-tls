---
title: ShadowTLS V3 Protocol
date: 2023-02-06 11:00:00
updated: 2026-04-09 00:00:00
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

After the handshake, both sides derive per-direction keys using **HKDF-SHA256**:

```
okm = HKDF-SHA256(IKM=password, salt=ServerRandom, info=direction)  →  28 bytes
```

Where `direction` is `"c2s"` or `"s2c"`. Each 28-byte output is split into:
- **AES key** (first 16 bytes): AES-128-GCM encryption key
- **Base nonce** (last 12 bytes): base value for GCM nonce construction

Using ServerRandom as the HKDF salt binds keys to the specific TLS session, preventing cross-session replay.

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

### Padding Strategy

**Phase 1 — Initial shaping (packets 0–7):**

| Packet | Target payload range | Mimics |
|--------|---------------------|--------|
| 0 | 200 – 600 B | HTTP request / small response |
| 1 | 800 – 1400 B (5%: 14000 – 16000) | HTTP headers / large file |
| 2–7 | 500 – 1400 B (5%: 14000 – 16000) | HTTP body chunks / large file |

**Phase 2 — Tail padding (packets N+, where N is randomized per-connection in [5, 13]):**

Each frame has a **5% probability** of 0–512 bytes of random padding, eliminating the abrupt statistical transition. The transition point N is randomized per-connection to prevent cross-connection fingerprinting of a fixed boundary.

# Security Properties

| Attack | Defense |
|--------|---------|
| Traffic signature detection | BoringSSL produces Chrome-identical ClientHello (JA3/JA4, X25519Kyber768, GREASE) |
| Active probing | Failed session_id HMAC → transparent SNI proxy fallback |
| Traffic hijacking (data) | Per-frame AES-128-GCM with direction-separated keys |
| Cross-session replay | HKDF salt = ServerRandom (unique per session) |
| In-session replay/reorder | 64-bit sequence number in GCM nonce |
| Header manipulation | TLS record header as GCM AAD |
| TLS-in-TLS fingerprinting | Two-phase padding with realistic traffic distribution |
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

**Stage 2 — Data relay (no TLS library required):**
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256(password, ServerRandom, direction).
2. **Reading from server**: parse ApplicationData, extract 16B GCM tag, decrypt with `key_s2c`. Parse inner frame, forward user data, discard padding.
3. **Writing to server**: build inner frame (CMD + DATA_LEN + data + padding), encrypt with `key_c2s`, wrap in ApplicationData.

## Server Implementation

**Stage 1 — Handshake relay (no TLS library required):**
1. Read ClientHello, verify session_id HMAC. On failure: plain TCP relay (SNI proxy fallback).
2. Forward ClientHello to handshake server. Read ServerHello, extract ServerRandom. Handle HRR if detected.
3. Bidirectional relay until first AEAD-authenticated ApplicationData frame arrives from client.
4. On AEAD match: shutdown handshake server connection, signal verbatim relay to stop.

**Stage 2 — Data relay:**
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256(password, ServerRandom, direction).
2. **Client → Data Server**: decrypt with `key_c2s`, parse inner frame, forward user data.
3. **Data Server → Client**: encrypt with `key_s2c`, build inner frame, apply padding.
