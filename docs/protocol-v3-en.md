---
title: ShadowTLS V3 Protocol
date: 2023-02-06 11:00:00
updated: 2026-04-08 00:00:00
author: ihciah
---

# Version Evolution
In August 2022 I implemented the first version of the ShadowTLS protocol. The goal of the V1 protocol was simple: to evade man-in-the-middle traffic discrimination by simply proxying the TLS handshake. v1 assumed that the man-in-the-middle would only observe handshake traffic, not subsequent traffic, not active probes, and not traffic hijacking.

However, this assumption does not hold true. In order to defend against active probing, the V2 version of the protocol added a mechanism to verify the identity of the client by challenge-response; and added Application Data encapsulation to better disguise the traffic.

The V2 version works well so far, and I have not encountered any problem of being blocked in daily use. After implementing support for multiple SNIs, it can even work as an SNI Proxy, which doesn't look like a proxy for data smuggling at all.

But the V2 protocol still assumes that the middleman will not do traffic hijacking (refer to [issue](https://github.com/ihciah/shadow-tls/issues/30)). The cost of traffic hijacking is relatively high, and it is not widely used at present. The means of man-in-the-middle are still mainly bypass observation and injection, and active detection. However, this does not mean that traffic hijacking will not be used on a large scale in the future, and protocols designed to resist traffic hijacking must be a better solution. One of the biggest problems faced is that it is difficult for the server side to identify itself covertly.

The [restls](https://github.com/3andne/restls) proposed in this [issue](https://github.com/ihciah/shadow-tls/issues/66) provides a very innovative idea. With this idea we can solve the server-side identity problem.

In addition, I also mentioned in [this blog](https://www.ihcblog.com/a-better-tls-obfs-proxy/) some possible hijacking attacks against data encapsulation, which must be addressed by the V3 protocol.


# V3 Protocol Principle
1. Capable of defending against traffic signature detection, active detection and traffic hijacking.
2. Easier to implement correctly.
3. Be as weakly aware of the TLS protocol itself as possible, so implementers do not need to hack the TLS library, let alone implement the TLS protocol themselves.
4. Keep it simple: only act as a TCP flow proxy, no duplicate wheel building.

## About support for TLS 1.2
The V3 protocol only supports handshake servers using TLS1.3 in strict mode. You can use `openssl s_client -tls1_3 -connect example.com:443` to detect whether a server supports TLS1.3.

If you want to support TLS1.2, you need to perceive more details of the TLS protocol, and the implementation will be more complicated; since TLS1.3 is already used by many manufacturers, we decided to only support TLS1.3 in strict mode.

Considering compatibility and some scenarios that require less protection against connection hijacking (such as using a specific SNI to bypass the billing system), TLS1.2 is allowed in non-strict mode.

# Handshake
This part of the protocol design is based on [restls](https://github.com/3andne/restls), but there are some differences: it is less aware of the details of TLS and easier to implement.

The client's TLS Client constructs the ClientHello, which generates a custom SessionID. The length of the SessionID must be 32, the first 28 bits are random values, and the last 4 bits are the HMAC signature data of the ClientHello frame (without the 5-byte header of the TLS frame, the 4 bytes after the SessionID are filled with 0). The HMAC instance is for one-time use only, and the instance is created directly using the password. A Read Wrapper is also needed to extract the ServerRandom from ServerHello and forward the subsequent streams. 2.
When the server receives the packet, it will authenticate the ClientHello, and if the authentication fails, it will continue the TCP relay with the handshake server. If the identification is successful, it will also forward it to the handshake server and continuously hijack the return stream from the handshake server. The server side will.
    1. log the ServerRandom in the forwarded ServerHello.
    2. do the following with the content portion of all ApplicationData frames.
        1. transform the data to XOR SHA256 (PreSharedKey + ServerRandom). 2.
        2. Add the 4 byte prefix `HMAC_ServerRandom(processed frame data)`, the HMAC instance should be filled with ServerRandom as the initial value, and this HMAC instance should be reused for subsequent ApplicationData forwarded from the handshake server. Note that the frame length needs to be + 4 at the same time. 3.
The client's ReadWrapper needs to parse the ApplicationData frame and determine the first 4 byte HMAC: 1.
    1. If `HMAC_ServerRandom(frame data)` is met, the server is proven to be reliable. These frames need to be filtered out after the handshake is complete. 2.
    2. If `HMAC_ServerRandomS(frame data)` is met, it proves that the data has finished switching. The content part needs to be forwarded to the user side.
    3. If none of them match, the traffic may have been hijacked and the handshake needs to be continued (or stopped if the handshake fails) and a random length HTTP request (muddled request) sent after a successful handshake and the connection closed properly after the response is read.

## Security Verification
1. When traffic is hijacked, Server will return data without doing XOR and Client will go straight to the muddling process.
2. ClientHello may be replayed but cannot use its correct handshake ([discussion of restls](https://github.com/3andne/restls/blob/main/Restls%3A%20%E5%AF%B9TLS%E6%8F%A1%E6%89%8B%E7%9A%84%E5%AE%8C%E7%BE%8E%E4%BC%AA%E8%A3%85.md)), so there is no way to identify whether the XOR data we return with a prefix is decodable.
2. If Client pretends the data is decrypted successfully and sends the data directly, it will not be able to pass because of the data frame checksum.

# Data Encapsulation

The V2 version of the data encapsulation protocol is in fact not resistant to traffic hijacking, e.g., the middleman may tamper with this part of the data after the handshake is completed, and we need to be able to respond to Alert; the middleman may also split one ApplicationData package into two as in the V2 protocol, which can also be used to identify the protocol if the connection is normal.

To deal with traffic hijacking, in addition to optimizing the handshake process, the data encapsulation part also needs to be redesigned. We need to be able to authenticate the data stream and resist attacks such as replay, data tampering, data slicing, and data disorder.

## Key Derivation

After the TLS handshake completes and ServerRandom is known, both sides derive per-direction keys using **HKDF-SHA256**:

```
okm_c2s = HKDF-SHA256(IKM=password, salt=ServerRandom, info="c2s")  →  28 bytes
okm_s2c = HKDF-SHA256(IKM=password, salt=ServerRandom, info="s2c")  →  28 bytes
```

Each 28-byte output is split into:
- **AES key** (first 16 bytes): AES-128-GCM encryption key
- **Base nonce** (last 12 bytes): base value for GCM nonce construction

The use of ServerRandom as the HKDF salt binds the data-phase keys to the specific TLS session, preventing cross-session replay attacks.

## Per-Frame AEAD (AES-128-GCM)

Each ApplicationData frame is independently encrypted and authenticated with **AES-128-GCM** (hardware-accelerated via AES-NI, ~10 GB/s throughput):

```
nonce       = base_nonce XOR (seq_be64 right-aligned to 12 bytes)
ciphertext || tag = AES-128-GCM(key, nonce, AAD=tls_header, plaintext=inner_payload)
```

- `seq_be64`: 64-bit frame sequence number (big-endian), starts at 0 and increments per frame per direction. The 64-bit counter eliminates nonce overflow risk (u32 would overflow at ~64 TB of data). The sequence number is XORed into the last 8 bytes of the base nonce.
- `tls_header`: the 5-byte TLS record header (`type || major || minor || len_hi || len_lo`), used as Additional Authenticated Data (AAD). This prevents header manipulation (e.g., length field tampering).
- `inner_payload`: the plaintext inner frame (inner header + data + padding), encrypted in-place to ciphertext.

The 16-byte GCM authentication tag provides both integrity and authenticity. The inner payload is also encrypted, adding confidentiality on top of the outer TLS encryption.

The encapsulated frame format is:

```
(5B TLS record header)(16B GCM tag)(encrypted: 1B CMD | 2B DATA_LEN | user data | optional padding)
```

**Strict sequence policy**: once a connection has been authenticated (first valid GCM frame received), any subsequent GCM verification failure results in immediate disconnection without retrying. This eliminates oracle attacks on the sequence counter.

**AuthPending resource limits**: while waiting for the first authenticated frame (e.g., during NewSessionTicket drain), non-matching ApplicationData frames are discarded silently. This state has two hard limits: 64 KiB of discarded bytes and 10 seconds of elapsed time. Exceeding either limit triggers disconnection.

## Frame Coalescing

When the sender reads a small amount of data from the upstream, it attempts a second read to coalesce more data into a single TLS record (up to ~16 KB). This reduces the number of AES-GCM operations and TLS records for small-packet workloads (e.g., web browsing), improving throughput without adding latency for large transfers.

## Inner Framing (Anti TLS-in-TLS)

To prevent statistical detection of inner-protocol traffic fingerprints (e.g., Shadowsocks's characteristic first-packet sizes), each ApplicationData payload carries a 3-byte inner header:

```
[CMD : 1 byte][DATA_LEN : 2 bytes big-endian][user data : DATA_LEN bytes][padding : variable]
```

- `CMD = 0x01` (DATA): the frame carries `DATA_LEN` bytes of real user data, followed by zero or more padding bytes. The receiver writes only `DATA_LEN` bytes to the downstream.
- `CMD = 0x00` (PADDING): pure waste frame, receiver discards the entire payload.

Padding is **inside** the HMAC-authenticated region, so it is authenticated along with the user data.

### Padding Strategy

Padding operates in two phases to produce a realistic traffic distribution and avoid detectable cutoff points.

**Phase 1 — Initial shaping (packets 0–7):**

For the first **8** data packets sent in each direction, the sender targets a random TLS record payload size chosen from traffic-profile-aware ranges:

| Packet index | Target payload range | Mimics |
|---|---|---|
| 0 (first) | 200 – 600 bytes | HTTP request / small response |
| 1 | 800 – 1 400 bytes (5% chance: 14 000 – 16 000) | HTTP response headers / large file |
| 2 – 7 | 500 – 1 400 bytes (5% chance: 14 000 – 16 000) | HTTP response body chunks / large file |

Packets 1–7 have a 5% probability of producing a near-full-size frame (14–16 KB), mimicking real HTTPS large file downloads that produce maximum-size TLS records.

If the actual user data is already larger than the target, no padding is added (data is never truncated).

**Phase 2 — Tail padding (packets 8+):**

After the initial 8 packets, each frame has a **2% probability** of receiving 0–256 bytes of random padding. This eliminates the abrupt statistical transition at the packet-8 boundary, which would otherwise serve as a detectable fingerprint.

## Security Verification

1. For man-in-the-middle data tampering, the per-frame AES-128-GCM authentication tag immediately detects it and the connection is closed with a TLS Alert.
2. For replay attacks across connections, the HKDF-derived key is bound to `ServerRandom`, making keys unique per TLS session.
3. For replay or reorder attacks within a connection, the 64-bit sequence number in the GCM nonce ensures any out-of-order delivery fails decryption and triggers strict disconnect.
4. For header manipulation (e.g., TLS record length tampering), the TLS record header is included as AAD in GCM, covering this attack surface.
5. For TLS-in-TLS fingerprinting, the two-phase padding system randomises packet sizes across the entire connection lifetime, eliminating inner-protocol statistical signatures.
6. For deep packet inspection of the inner payload, AES-128-GCM encryption ensures the inner framing (CMD, DATA_LEN, user data) is not visible even if the outer TLS encryption were somehow compromised.

# Implementation Guide

## TLS Fingerprint Requirements

The client **MUST** produce a TLS ClientHello that closely matches a modern browser (Chrome 131+). This is a protocol requirement, not optional:

- **Cipher suites**: Chrome order (GREASE + AES-128-GCM first, CHACHA20 last, SCSV at end)
- **Key exchange groups**: X25519, P-256, P-384
- **ALPN**: `h2`, `http/1.1` (mandatory)
- **Extensions**: Chrome-order with GREASE extensions (RFC 8701), `compress_certificate` (brotli), `renegotiation_info`, and `padding` (align to 512 bytes)
- **Signature algorithms**: Chrome order (ecdsa_p256_sha256, rsa_pss_sha256, rsa_pkcs1_sha256, ecdsa_p384_sha384, rsa_pss_sha384, rsa_pkcs1_sha384, rsa_pss_sha512, rsa_pkcs1_sha512)
- **Supported versions**: GREASE version + TLS 1.3 + TLS 1.2

## Muddling Request

When V3 strict mode detects traffic hijacking (ServerRandom extraction failure or authorization failure), the client sends a realistic fake HTTP request mimicking Chrome 131:

- Proper `User-Agent` matching the TLS fingerprint's browser version
- Standard Chrome headers: `Accept`, `Accept-Language`, `Accept-Encoding` (gzip, deflate, br, zstd), `Sec-Fetch-*`, `Upgrade-Insecure-Requests`
- Proper HTTP/1.1 line endings (`\r\n`)

## Client
The client is responsible for TLS handshaking, switching and doing data encapsulation and decapsulation after the switch.

The client needs to have a built-in TLS Client and a Read Wrapper on the read side of the network stream: TLSClient <- ReadWrapper <- TCPStream; similarly, a Write Wrapper needs to be attached to the write data link: TLSClient -> WriteWrapper --> TCPStream.

Stage1: TLS handshake
Construct and sign a custom SessionID from the TLS library. 2.
ReadWrapper. 1:
    1. Extract ServerRandom from ServerHello; create `HMAC_ServerRandom`. 2.
    2. Use `HMAC_ServerRandom` for ApplicationData to determine if the HMAC of the frame content (without the 4byte HMAC) matches the first 4 bytes. If it matches, rewrite the data frame content to its XOR SHA256(PreSharedKey + ServerRandom) and remove the first 4 byte HMAC value. If it does not match, no changes are made and the connection is marked as hijacked and a muddled request is sent after a successful handshake; if the handshake fails, no processing is done.

Stage2: Data forwarding (this process does not rely on TLS library)
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256 using ServerRandom as salt (28 bytes each: 16-byte AES key + 12-byte base nonce).
2. Parse ApplicationData frames when reading from the server connection. Extract the 16-byte GCM tag and decrypt the ciphertext using `key_s2c`, constructing the nonce as `base_nonce XOR seq_be64`.
    1. If GCM passes (state = AuthPending): transition to Authenticated, parse the decrypted inner frame, extract `DATA_LEN` bytes of user data (discard padding), forward to user.
    2. If GCM passes (state = Authenticated): same as above. Pure padding frames (`CMD=0x00`) are silently discarded.
    3. If GCM fails (state = AuthPending): this may be a residual handshake frame (NewSessionTicket etc.); discard silently. Resource limits apply (64 KiB / 10 s).
    4. If GCM fails (state = Authenticated): strict disconnect — send TLS Alert and close.
    Note: The Server is allowed to send residual TLS frames after the Client has switched; the Client filters them during the AuthPending state.
3. When writing to the server connection, build the inner frame (CMD + DATA_LEN + data + padding), encrypt with AES-128-GCM using `key_c2s` and `base_nonce XOR seq_be64`, wrap in ApplicationData with the GCM tag. Apply two-phase padding. Use frame coalescing for small reads.

## Server-side
The server is responsible for forwarding the TLS handshake, determining the timing of the switch, and encapsulating and decapsulating the data after the switch, without relying on the TLS library.

Stage1: Forwarding the TLS handshake
1. Read ClientHello: extract and identify the SessionID in ClientHello, if it does not pass, mark it as active detection traffic and start TCP forwarding directly (if it implements multiple SNIs, it also needs to resolve the SNIs and do the corresponding splitting and forwarding); if it passes, it also forwards the data frame and continues to the second step.
2. Read ServerHello from the other side: extract ServerRandom.
Start two-way forwarding (with Handshake Server).
    1. Create `HMAC_ServerRandomC` and `HMAC_ServerRandom`.
    2. ShadowTLS Client -> Handshake Server: Forward directly until a frame matching the first 4 bytes of ApplicationData matches the `HMAC_ServerRandomC` signature is encountered, then stop forwarding in both directions (but ensure the integrity of the frames remaining in transit).
    3. Handshake Server -> ShadowTLS Client: modify the Application Data frame by doing XOR SHA256 (PreSharedKey + ServerRandom) on the data and adding 4 byte HMAC in the header (calculated by `HMAC_ ServerRandom`).

Stage2: Data forwarding (with Data Server)
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256 using ServerRandom as salt (28 bytes each: 16-byte AES key + 12-byte base nonce).
2. ShadowTLS Client → Data Server: Parse ApplicationData, extract 16-byte GCM tag, decrypt ciphertext using `key_c2s` and `base_nonce XOR seq_be64`. Any authentication failure is treated as Alert bad_record_mac. On success, parse the decrypted inner frame, extract the real user data bytes (discarding padding), and forward to the Data Server.
3. Data Server → ShadowTLS Client: Build inner frame, encrypt with AES-128-GCM using `key_s2c`, wrap in ApplicationData with GCM tag. Apply two-phase padding to all frames. Use frame coalescing for small reads.