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
key_c2s = HKDF-SHA256(IKM=password, salt=ServerRandom, info="c2s")
key_s2c = HKDF-SHA256(IKM=password, salt=ServerRandom, info="s2c")
```

Each key is 256 bits. The use of ServerRandom as the HKDF salt binds the data-phase keys to the specific TLS session, preventing cross-session replay attacks.

## Per-Frame Authentication

Each ApplicationData frame is independently authenticated with **HMAC-SHA256** (truncated to 16 bytes):

```
tag = HMAC-SHA256(key, seq_be32 || tls_header || inner_payload)[..16]
```

- `seq_be32`: 32-bit frame sequence number (big-endian), starts at 0 and increments per frame per direction. This provides strict ordering — any out-of-order or replayed frame will fail verification.
- `tls_header`: the 5-byte TLS record header (`type || major || minor || len_hi || len_lo`). Including the header in the MAC prevents header manipulation (e.g., length field tampering).
- `inner_payload`: the frame body after the HMAC tag (inner header + data + padding).

The encapsulated frame format is:

```
(5B TLS record header)(16B HMAC-SHA256 tag)(1B CMD)(2B DATA_LEN)(user data)(optional padding)
```

**Strict sequence policy**: once a connection has been authenticated (first valid HMAC frame received), any subsequent HMAC verification failure results in immediate disconnection without retrying. This eliminates oracle attacks on the sequence counter.

**AuthPending resource limits**: while waiting for the first authenticated frame (e.g., during NewSessionTicket drain), non-matching ApplicationData frames are discarded silently. This state has two hard limits: 64 KiB of discarded bytes and 10 seconds of elapsed time. Exceeding either limit triggers disconnection.

## Inner Framing (Anti TLS-in-TLS)

To prevent statistical detection of inner-protocol traffic fingerprints (e.g., Shadowsocks's characteristic first-packet sizes), each ApplicationData payload carries a 3-byte inner header:

```
[CMD : 1 byte][DATA_LEN : 2 bytes big-endian][user data : DATA_LEN bytes][padding : variable]
```

- `CMD = 0x01` (DATA): the frame carries `DATA_LEN` bytes of real user data, followed by zero or more padding bytes. The receiver writes only `DATA_LEN` bytes to the downstream.
- `CMD = 0x00` (PADDING): pure waste frame, receiver discards the entire payload.

Padding is **inside** the HMAC-authenticated region, so it is authenticated along with the user data.

### Padding Strategy

For the first **8** data packets sent in each direction, the sender targets a random TLS record payload size chosen from traffic-profile-aware ranges:

| Packet index | Target payload range | Mimics |
|---|---|---|
| 0 (first) | 200 – 600 bytes | HTTP request / small response |
| 1 | 800 – 1 400 bytes | HTTP response headers |
| 2 – 7 | 500 – 1 400 bytes | HTTP response body chunks |

If the actual user data is already larger than the target, no padding is added (data is never truncated). After the 8th packet, no padding is inserted and the raw data length is used.

## Security Verification

1. For man-in-the-middle data tampering, the per-frame HMAC will immediately detect it and the connection is closed with a TLS Alert.
2. For replay attacks across connections, the HKDF-derived key is bound to `ServerRandom`, making keys unique per TLS session.
3. For replay or reorder attacks within a connection, the 32-bit sequence number in the HMAC input ensures any out-of-order delivery fails verification and triggers strict disconnect.
4. For header manipulation (e.g., TLS record length tampering), including the TLS record header in the HMAC covers this attack surface.
5. For TLS-in-TLS fingerprinting, the padding system randomises the first 8 packet sizes to match typical HTTPS traffic, eliminating inner-protocol statistical signatures.

# Implementation Guide
## Client
The client is responsible for TLS handshaking, switching and doing data encapsulation and decapsulation after the switch.

The client needs to have a built-in TLS Client and a Read Wrapper on the read side of the network stream: TLSClient <- ReadWrapper <- TCPStream; similarly, a Write Wrapper needs to be attached to the write data link: TLSClient -> WriteWrapper --> TCPStream.

Stage1: TLS handshake
Construct and sign a custom SessionID from the TLS library. 2.
ReadWrapper. 1:
    1. Extract ServerRandom from ServerHello; create `HMAC_ServerRandom`. 2.
    2. Use `HMAC_ServerRandom` for ApplicationData to determine if the HMAC of the frame content (without the 4byte HMAC) matches the first 4 bytes. If it matches, rewrite the data frame content to its XOR SHA256(PreSharedKey + ServerRandom) and remove the first 4 byte HMAC value. If it does not match, no changes are made and the connection is marked as hijacked and a muddled request is sent after a successful handshake; if the handshake fails, no processing is done.

Stage2: Data forwarding (this process does not rely on TLS library)
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256 using ServerRandom as salt.
2. Parse ApplicationData frames when reading from the server connection and verify the 16-byte HMAC tag using `key_s2c` and the current `seq_s2c` counter.
    1. If HMAC passes (state = AuthPending): transition to Authenticated, parse the inner frame, extract `DATA_LEN` bytes of user data (discard padding), forward to user.
    2. If HMAC passes (state = Authenticated): same as above. Pure padding frames (`CMD=0x00`) are silently discarded.
    3. If HMAC fails (state = AuthPending): this may be a residual handshake frame (NewSessionTicket etc.); discard silently. Resource limits apply (64 KiB / 10 s).
    4. If HMAC fails (state = Authenticated): strict disconnect — send TLS Alert and close.
    Note: The Server is allowed to send residual TLS frames after the Client has switched; the Client filters them during the AuthPending state.
3. When writing to the server connection, wrap user data in ApplicationData with inner framing and HMAC using `key_c2s`, incrementing `seq_c2s`. Apply padding for the first 8 frames.

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
1. Derive `key_c2s` and `key_s2c` via HKDF-SHA256 using ServerRandom as salt.
2. ShadowTLS Client → Data Server: Parse ApplicationData encapsulation, verify the 16-byte HMAC tag using `key_c2s` and `seq_c2s`. Any mismatch is treated as Alert bad_record_mac. On success, parse the inner frame, extract the real user data bytes (discarding padding), and forward to the Data Server.
3. Data Server → ShadowTLS Client: Wrap data in ApplicationData with inner framing and HMAC using `key_s2c`, incrementing `seq_s2c`. Apply padding to the first 8 frames.