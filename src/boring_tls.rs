use std::collections::VecDeque;
use std::io::{self, Read, Write};

use boring::ssl::{
    HandshakeError, MidHandshakeSslStream, SslConnector, SslConnectorBuilder, SslMethod,
    SslStream, SslVersion,
};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use rand::Rng;
use tracing;

use crate::util::prelude::*;
use crate::util::Hmac;

// ---------------------------------------------------------------------------
// Chrome TLS Configuration
// ---------------------------------------------------------------------------

/// Build an SslConnector configured to produce Chrome-identical ClientHello.
///
/// BoringSSL IS Chrome's TLS library, so with the right config the fingerprint
/// (JA3/JA4, extension order, key shares) is authentic, not simulated.
pub(crate) fn build_chrome_ssl_connector(
    alpn: &[Vec<u8>],
) -> Result<SslConnector, boring::error::ErrorStack> {
    let mut builder: SslConnectorBuilder = SslConnector::builder(SslMethod::tls())?;

    // --- GREASE (RFC 8701) — native BoringSSL, identical to Chrome ---
    builder.set_grease_enabled(true);

    // --- Cipher suites in Chrome order ---
    // TLS 1.3 ciphers are configured separately by BoringSSL (always enabled).
    // This sets the TLS 1.2 cipher preference:
    builder.set_cipher_list(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\
         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    )?;

    // --- Key exchange groups: X25519Kyber768 (post-quantum!) + X25519 + P-256 + P-384 ---
    // X25519Kyber768 is the critical addition: Chrome sends a ~1200-byte key share.
    // Without it, the ClientHello is ~1000 bytes shorter than real Chrome.
    builder.set_curves_list("X25519Kyber768Draft00:X25519:P-256:P-384")?;

    // --- Signature algorithms matching Chrome ---
    builder.set_sigalgs_list(
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:\
         RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512",
    )?;

    // --- ALPN: h2 + http/1.1 (Chrome default) ---
    let alpn_wire = if alpn.is_empty() {
        // Default Chrome ALPN
        b"\x02h2\x08http/1.1".to_vec()
    } else {
        let mut wire = Vec::new();
        for proto in alpn {
            wire.push(proto.len() as u8);
            wire.extend_from_slice(proto);
        }
        wire
    };
    builder.set_alpn_protos(&alpn_wire)?;

    // --- Protocol versions ---
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    Ok(builder.build())
}

// ---------------------------------------------------------------------------
// SyncBridge: in-memory buffer pair for driving boring's sync I/O from async
// ---------------------------------------------------------------------------

/// An in-memory buffer pair that implements `Read + Write` for boring's SslStream.
///
/// The async handshake driver pumps data between this bridge and the real TcpStream.
/// boring writes outgoing TLS data to `write_buf`, we flush it to TCP asynchronously.
/// We read from TCP asynchronously into `read_buf`, boring reads from it synchronously.
struct SyncBridge {
    /// Data from network, consumed by SSL (network → SSL)
    read_buf: VecDeque<u8>,
    /// Data from SSL, to be sent to network (SSL → network)
    write_buf: Vec<u8>,
}

impl SyncBridge {
    fn new() -> Self {
        Self {
            read_buf: VecDeque::with_capacity(16384),
            write_buf: Vec::with_capacity(4096),
        }
    }

    /// Feed data from the network into the read buffer.
    fn feed_read(&mut self, data: &[u8]) {
        self.read_buf.extend(data);
    }

    /// Take all pending write data (SSL → network).
    fn take_write_buf(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.write_buf, Vec::with_capacity(4096))
    }

    /// Check if there's pending data to write to the network.
    fn has_pending_write(&self) -> bool {
        !self.write_buf.is_empty()
    }
}

impl Read for SyncBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "need more data"));
        }
        let (front, back) = self.read_buf.as_slices();
        let n = buf.len().min(front.len());
        if n > 0 {
            buf[..n].copy_from_slice(&front[..n]);
            self.read_buf.drain(..n);
            Ok(n)
        } else {
            let n = buf.len().min(back.len());
            buf[..n].copy_from_slice(&back[..n]);
            self.read_buf.drain(..n);
            Ok(n)
        }
    }
}

impl Write for SyncBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Session ID Patching
// ---------------------------------------------------------------------------

/// Patch the session_id in a ClientHello TLS record to embed our HMAC authentication.
///
/// The frame is the complete TLS record: [type:1][version:2][length:2][body...].
/// Returns true if patching succeeded.
fn patch_session_id(frame: &mut [u8], password: &str) -> bool {
    // TLS record header: 5 bytes
    // ClientHello body layout:
    //   msg_type:1 + length:3 + client_version:2 + random:32 + session_id_len:1
    //   = 39 bytes after TLS header
    // So session_id_len is at offset 5+39 = 44, but let's use the canonical constants.
    const BODY_START: usize = TLS_HEADER_SIZE; // 5
    // Inside body: 1(type) + 3(len) + 2(version) + 32(random) + 1(session_id_len) = 39
    const SESSION_ID_LEN_OFFSET: usize = BODY_START + 1 + 3 + 2 + TLS_RANDOM_SIZE; // 5+39 = 44
    const SESSION_ID_OFFSET: usize = SESSION_ID_LEN_OFFSET + 1; // 45

    if frame.len() < SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE {
        tracing::warn!("ClientHello too short for session ID patching");
        return false;
    }

    // Verify this is a handshake record and it's a ClientHello
    if frame[0] != HANDSHAKE {
        return false;
    }
    if frame[BODY_START] != CLIENT_HELLO {
        return false;
    }

    // Check session_id_len == 32 (BoringSSL generates 32-byte legacy session IDs)
    let sid_len = frame[SESSION_ID_LEN_OFFSET] as usize;
    if sid_len != TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected session_id length: {sid_len}");
        return false;
    }

    // Fill first 28 bytes of session_id with random
    let session_id_start = SESSION_ID_OFFSET;
    let session_id_end = session_id_start + TLS_SESSION_ID_SIZE;
    let hmac_offset = session_id_end - SESSION_HMAC_SIZE;

    rand::thread_rng().fill(&mut frame[session_id_start..hmac_offset]);

    // Zero the HMAC region for computation
    frame[hmac_offset..session_id_end].fill(0);

    // Compute HMAC-SHA1 over the body (excluding TLS header, matching server verification)
    // Server's verified_extract_sni computes:
    //   hmac.update(&frame[TLS_HEADER_SIZE..HMAC_IDX]);
    //   hmac.update(&ZERO4B);
    //   hmac.update(&frame[HMAC_IDX + SESSION_HMAC_SIZE..]);
    // Where HMAC_IDX = SESSION_ID_LEN_OFFSET + 1 + TLS_SESSION_ID_SIZE - SESSION_HMAC_SIZE
    //               = 44 + 1 + 32 - 4 = 73
    // This is exactly hmac_offset (session_id_end - 4 = 45 + 32 - 4 = 73).
    // Since we already zeroed the HMAC region, computing over the full body is equivalent.
    let mut hmac = Hmac::new(password, (&[], &[]));
    hmac.update(&frame[TLS_HEADER_SIZE..hmac_offset]);
    hmac.update(&[0u8; SESSION_HMAC_SIZE]);
    hmac.update(&frame[hmac_offset + SESSION_HMAC_SIZE..]);
    let hmac_val = hmac.finalize();

    // Write HMAC into session_id
    frame[hmac_offset..session_id_end].copy_from_slice(&hmac_val);

    tracing::debug!(
        "ClientHello session_id patched (frame_len={}, session_id=[{}..{}])",
        frame.len(),
        session_id_start,
        session_id_end,
    );
    true
}

/// Check if a buffer starts with a TLS Handshake record (likely ClientHello).
fn is_handshake_record(data: &[u8]) -> bool {
    data.len() >= TLS_HEADER_SIZE && data[0] == HANDSHAKE
}

// ---------------------------------------------------------------------------
// Async Handshake Driver
// ---------------------------------------------------------------------------

/// Perform V3 TLS handshake with boring (BoringSSL).
///
/// Returns the ServerRandom (32 bytes) and whether TLS 1.3 was negotiated.
/// After this function returns, `tcp` is still usable for the data phase.
///
/// The handshake is driven via an in-memory SyncBridge: boring writes/reads
/// to the bridge synchronously, while we pump data between the bridge and
/// the real TcpStream asynchronously.
pub(crate) async fn perform_v3_handshake(
    tcp: &mut TcpStream,
    connector: &SslConnector,
    sni: &str,
    password: &str,
) -> io::Result<([u8; 32], bool)> {
    let bridge = SyncBridge::new();

    // Create SSL instance configured for this connection
    let ssl = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL configure: {e}")))?
        .into_ssl(sni)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL create: {e}")))?;

    // Build SslStreamBuilder with connect state
    let mut builder = boring::ssl::SslStreamBuilder::new(ssl, bridge);
    builder.set_connect_state();

    // Attempt initial handshake — this will return WouldBlock since bridge is empty
    let mut mid: MidHandshakeSslStream<SyncBridge> = match builder.handshake() {
        Ok(stream) => {
            // Handshake completed in one shot (shouldn't happen with empty bridge)
            return flush_and_extract(stream, tcp).await;
        }
        Err(HandshakeError::WouldBlock(mid)) => mid,
        Err(HandshakeError::Failure(mid)) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("TLS handshake failed: {}", mid.error()),
            ));
        }
        Err(HandshakeError::SetupFailure(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("TLS setup failed: {e}"),
            ));
        }
    };

    let mut first_write = true;

    loop {
        // Step 1: Flush any pending writes from SSL to network
        {
            let bridge = mid.get_mut();
            if bridge.has_pending_write() {
                let mut data = bridge.take_write_buf();

                // On the first write (ClientHello), patch the session ID
                if first_write && is_handshake_record(&data) {
                    patch_session_id(&mut data, password);
                    first_write = false;
                    tracing::debug!(
                        "ClientHello before sign: {:?}, session_id {:?}",
                        &data[..data.len().min(80)],
                        &data[45..45 + 32]
                    );
                }

                let (res, _) = tcp.write_all(data).await;
                res?;
            }
        }

        // Step 2: Read from network into bridge
        {
            let buf = vec![0u8; 16384];
            let (res, buf) = tcp.read(buf).await;
            let n = res?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during handshake",
                ));
            }
            mid.get_mut().feed_read(&buf[..n]);
        }

        // Step 3: Continue handshake
        mid = match mid.handshake() {
            Ok(stream) => {
                return flush_and_extract(stream, tcp).await;
            }
            Err(HandshakeError::WouldBlock(mid)) => mid,
            Err(HandshakeError::Failure(mid)) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("TLS handshake failed: {}", mid.error()),
                ));
            }
            Err(HandshakeError::SetupFailure(e)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("TLS setup failed: {e}"),
                ));
            }
        };
    }
}

/// Extract ServerRandom and TLS version from a completed SslStream.
/// Also flushes any remaining write data to the TCP stream.
async fn flush_and_extract(
    mut stream: SslStream<SyncBridge>,
    tcp: &mut TcpStream,
) -> io::Result<([u8; 32], bool)> {
    // Flush any remaining writes from the handshake completion
    let bridge = stream.get_mut();
    if bridge.has_pending_write() {
        let data = bridge.take_write_buf();
        let (res, _) = tcp.write_all(data).await;
        res?;
    }

    let ssl = stream.ssl();

    // Extract ServerRandom
    let mut server_random = [0u8; 32];
    let sr_len = ssl.server_random(&mut server_random);
    if sr_len != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected ServerRandom length: {sr_len}"),
        ));
    }

    // Detect TLS 1.3
    let tls13 = ssl.version2() == Some(SslVersion::TLS1_3);

    tracing::debug!("handshake success (tls1.3={tls13}), ServerRandom: {server_random:?}");
    Ok((server_random, tls13))
}

// ---------------------------------------------------------------------------
// Fake Request (V3 strict fallback)
// ---------------------------------------------------------------------------

/// Perform a fake HTTP request through a TLS connection for V3 strict mode fallback.
///
/// This is used when the handshake was hijacked or TLS 1.3 is not supported.
/// It sends a realistic Chrome HTTP request to make the connection look normal.
pub(crate) async fn perform_fake_request(
    tcp: &mut TcpStream,
    connector: &SslConnector,
    sni: &str,
) -> io::Result<()> {
    // Do a full TLS handshake (no session ID patching needed)
    let bridge = SyncBridge::new();
    let ssl = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL configure: {e}")))?
        .into_ssl(sni)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL create: {e}")))?;

    let mut builder = boring::ssl::SslStreamBuilder::new(ssl, bridge);
    builder.set_connect_state();

    let mut mid = match builder.handshake() {
        Ok(_stream) => {
            // Completed immediately - send fake request through stream
            // This path is unlikely
            return Ok(());
        }
        Err(HandshakeError::WouldBlock(mid)) => mid,
        Err(_) => return Ok(()), // Best effort
    };

    // Drive handshake to completion
    let stream = loop {
        {
            let bridge = mid.get_mut();
            if bridge.has_pending_write() {
                let data = bridge.take_write_buf();
                let (res, _) = tcp.write_all(data).await;
                res?;
            }
        }
        {
            let buf = vec![0u8; 16384];
            let (res, buf) = tcp.read(buf).await;
            let n = res?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF during fake handshake"));
            }
            mid.get_mut().feed_read(&buf[..n]);
        }
        mid = match mid.handshake() {
            Ok(stream) => break stream,
            Err(HandshakeError::WouldBlock(m)) => m,
            Err(_) => return Ok(()),
        };
    };

    // Send a fake Chrome HTTP request through the TLS stream
    let fake_http = format!(
        "GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n",
        sni = sni,
    );

    // Write through SslStream (encrypts the data) → SyncBridge write_buf
    let mut stream = stream;
    let _ = stream.write_all(fake_http.as_bytes());

    // Flush bridge → TCP
    let bridge = stream.get_mut();
    if bridge.has_pending_write() {
        let data = bridge.take_write_buf();
        let (res, _) = tcp.write_all(data).await;
        let _ = res; // Best effort
    }

    Ok(())
}
