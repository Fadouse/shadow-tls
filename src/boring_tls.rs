use std::io::{self, Read, Write};

use boring::ssl::{
    HandshakeError, MidHandshakeSslStream, SslConnector, SslConnectorBuilder, SslMethod,
    SslVerifyMode, SslVersion,
};
use monoio::buf::IoBufMut;
use monoio::io::{AsyncReadRentExt, AsyncWriteRentExt};
use monoio::net::TcpStream;
use rand::Rng;
use std::time::Duration;

use crate::util::prelude::*;
use crate::util::Hmac;

// ---------------------------------------------------------------------------
// TLS 1.3 Cipher Suite Classification
// ---------------------------------------------------------------------------

/// TLS 1.3 cipher suite type — determines the correct Finished record size.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Tls13Cipher {
    /// TLS_AES_128_GCM_SHA256 (0x1301) — verify_data = 32 bytes
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302) — verify_data = 48 bytes
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303) — verify_data = 32 bytes
    Chacha20Poly1305Sha256,
}

impl Tls13Cipher {
    /// Encrypted Finished record body length in TLS 1.3.
    ///
    /// Layout: Handshake header(4) + verify_data(32|48) + content_type(1) + AEAD tag(16)
    ///   SHA-256 ciphers: 4 + 32 + 1 + 16 = 53
    ///   SHA-384 ciphers: 4 + 48 + 1 + 16 = 69
    fn finished_record_body_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 69,
            _ => 53,
        }
    }

    fn from_cipher_suite(cs: u16) -> Self {
        match cs {
            0x1302 => Self::Aes256GcmSha384,
            0x1303 => Self::Chacha20Poly1305Sha256,
            _ => Self::Aes128GcmSha256,
        }
    }
}

/// Overall timeout for the entire handshake phase.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// TLS 1.3 HelloRetryRequest uses this fixed synthetic ServerRandom (RFC 8446 §4.1.3).
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

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
    builder.set_curves_list("X25519Kyber768Draft00:X25519:P-256:P-384")?;

    // --- Signature algorithms matching Chrome ---
    builder.set_sigalgs_list(
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:\
         RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512",
    )?;

    // --- ALPN: h2 + http/1.1 (Chrome default) ---
    let alpn_wire = if alpn.is_empty() {
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
// SyncBridge: in-memory buffer pair for boring's sync I/O
// ---------------------------------------------------------------------------

/// Bidirectional sync I/O buffer for boring's SslStream.
///
/// - `write_buf`: captures bytes boring wants to send (ClientHello, CCS, Finished, etc.)
/// - `read_buf`: provides server bytes for boring to process (ServerHello, Certificate, etc.)
///
/// Returns `WouldBlock` when `read_buf` is exhausted, signaling boring to yield
/// control so we can read more frames from TCP.
struct SyncBridge {
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
}

impl SyncBridge {
    fn new() -> Self {
        Self {
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::with_capacity(4096),
        }
    }

    /// Feed server data for boring to read.
    fn feed(&mut self, data: &[u8]) {
        if self.read_pos == self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
        }
        self.read_buf.extend_from_slice(data);
    }

    /// Take all bytes boring has written (client flight records).
    fn take_write_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.write_buf)
    }
}

impl Read for SyncBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.read_buf.len() - self.read_pos;
        if available == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "need more data"));
        }
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
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
// Handshake Initiation
// ---------------------------------------------------------------------------

/// Start a TLS handshake with boring, producing the ClientHello and returning
/// the mid-handshake stream for continuation.
///
/// Certificate verification is disabled — we use boring only for generating
/// authentic TLS records, not for security validation. This allows boring to
/// process the server's Certificate without failing on untrusted CAs.
fn start_handshake(
    connector: &SslConnector,
    sni: &str,
) -> io::Result<(MidHandshakeSslStream<SyncBridge>, Vec<u8>)> {
    let bridge = SyncBridge::new();
    let mut ssl = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL configure: {e}")))?
        .into_ssl(sni)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSL create: {e}")))?;

    // Disable cert verification — we only need authentic TLS record generation.
    ssl.set_verify(SslVerifyMode::NONE);

    let mut builder = boring::ssl::SslStreamBuilder::new(ssl, bridge);
    builder.set_connect_state();

    match builder.handshake() {
        Err(HandshakeError::WouldBlock(mut mid)) => {
            let client_hello = mid.get_mut().take_write_buf();
            Ok((mid, client_hello))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::Other,
            "handshake completed unexpectedly with empty bridge",
        )),
        Err(HandshakeError::Failure(mid)) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("ClientHello generation failed: {}", mid.error()),
        )),
        Err(HandshakeError::SetupFailure(e)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("TLS setup failed: {e}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Session ID Operations
// ---------------------------------------------------------------------------

/// Session ID offset within a ClientHello/ServerHello TLS record frame.
const SESSION_ID_OFFSET: usize = SESSION_ID_LEN_IDX + 1; // 44

/// Save the original session_id from a ClientHello before HMAC patching.
fn save_session_id(frame: &[u8]) -> Option<[u8; TLS_SESSION_ID_SIZE]> {
    if frame.len() < SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE {
        return None;
    }
    let mut sid = [0u8; TLS_SESSION_ID_SIZE];
    sid.copy_from_slice(&frame[SESSION_ID_OFFSET..SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE]);
    Some(sid)
}

/// Restore the original session_id in a ServerHello frame.
///
/// The handshake server echoes back our patched session_id, but boring expects
/// the original one it generated. Restoring it allows boring to continue the
/// handshake without a DECODE_ERROR.
fn restore_server_hello_session_id(frame: &mut [u8], original_sid: &[u8; TLS_SESSION_ID_SIZE]) {
    if frame.len() >= SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE
        && frame[SESSION_ID_LEN_IDX] == TLS_SESSION_ID_SIZE as u8
    {
        frame[SESSION_ID_OFFSET..SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE]
            .copy_from_slice(original_sid);
    }
}

/// Patch the session_id in a ClientHello TLS record to embed our HMAC authentication.
///
/// The frame is the complete TLS record(s) from boring's write buffer.
/// Returns true if patching succeeded.
fn patch_session_id(frame: &mut [u8], password: &str) -> bool {
    const BODY_START: usize = TLS_HEADER_SIZE; // 5

    if frame.len() < SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE {
        tracing::warn!("ClientHello too short for session ID patching");
        return false;
    }

    if frame[0] != HANDSHAKE || frame[BODY_START] != CLIENT_HELLO {
        return false;
    }

    // Parse the TLS record length to find the exact end of this record.
    let record_body_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    let record_end = TLS_HEADER_SIZE + record_body_len;
    if frame.len() < record_end {
        tracing::warn!("ClientHello record truncated");
        return false;
    }

    let sid_len = frame[SESSION_ID_LEN_IDX] as usize;
    if sid_len != TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected session_id length: {sid_len}");
        return false;
    }

    let session_id_end = SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE;
    let hmac_offset = session_id_end - SESSION_HMAC_SIZE;

    // Fill first 28 bytes of session_id with random
    rand::thread_rng().fill(&mut frame[SESSION_ID_OFFSET..hmac_offset]);

    // Zero the HMAC region for computation
    frame[hmac_offset..session_id_end].fill(0);

    // Compute HMAC-SHA1 over the ClientHello record body only.
    let mut hmac = Hmac::new(password, (&[], &[]));
    hmac.update(&frame[TLS_HEADER_SIZE..hmac_offset]);
    hmac.update(&[0u8; SESSION_HMAC_SIZE]);
    hmac.update(&frame[hmac_offset + SESSION_HMAC_SIZE..record_end]);
    let hmac_val = hmac.finalize();

    // Write HMAC into session_id
    frame[hmac_offset..session_id_end].copy_from_slice(&hmac_val);

    tracing::debug!(
        "ClientHello session_id patched (frame_len={}, record_end={})",
        frame.len(),
        record_end,
    );
    true
}

// ---------------------------------------------------------------------------
// Raw ServerHello Parsing
// ---------------------------------------------------------------------------

/// Extract ServerRandom from a raw ServerHello frame.
fn extract_server_random_raw(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    if frame.len() < MIN_LEN || frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != SERVER_HELLO {
        return None;
    }
    let mut sr = [0u8; TLS_RANDOM_SIZE];
    sr.copy_from_slice(&frame[SERVER_RANDOM_IDX..SERVER_RANDOM_IDX + TLS_RANDOM_SIZE]);
    Some(sr)
}

/// Extract the negotiated cipher suite from a raw ServerHello frame.
///
/// ServerHello layout after TLS header:
///   HandshakeType(1) + Length(3) + ProtocolVersion(2) + Random(32) + SessionIDLen(1) + SessionID(var) + CipherSuite(2)
fn extract_cipher_suite_raw(frame: &[u8]) -> Tls13Cipher {
    if frame.len() > SESSION_ID_LEN_IDX {
        let sid_len = frame[SESSION_ID_LEN_IDX] as usize;
        let cs_offset = SESSION_ID_LEN_IDX + 1 + sid_len;
        if frame.len() >= cs_offset + 2 {
            let cs = u16::from_be_bytes([frame[cs_offset], frame[cs_offset + 1]]);
            return Tls13Cipher::from_cipher_suite(cs);
        }
    }
    // Default to the most common cipher suite
    Tls13Cipher::Aes128GcmSha256
}

/// Read exactly one TLS record from TCP with a timeout.
async fn read_tls_frame_timeout(tcp: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    match monoio::time::timeout(timeout, read_tls_frame(tcp)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "handshake read timed out",
        )),
    }
}

/// Read exactly one TLS record from TCP (header + body).
async fn read_tls_frame(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let header = vec![0u8; TLS_HEADER_SIZE];
    let (res, header) = tcp.read_exact(header).await;
    res?;

    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    let mut frame = header;
    frame.reserve(body_len);
    let (res, frame_slice) = tcp
        .read_exact(frame.slice_mut(TLS_HEADER_SIZE..TLS_HEADER_SIZE + body_len))
        .await;
    res?;

    Ok(frame_slice.into_inner())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if raw TLS data contains an ApplicationData (0x17) record.
fn contains_application_data(data: &[u8]) -> bool {
    let mut pos = 0;
    while pos + TLS_HEADER_SIZE <= data.len() {
        if data[pos] == APPLICATION_DATA {
            return true;
        }
        if pos + 4 >= data.len() {
            break;
        }
        let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        pos += TLS_HEADER_SIZE + record_len;
    }
    false
}

/// Append a random ApplicationData record simulating an encrypted Finished.
///
/// Uses the EXACT record body length of a real TLS 1.3 encrypted Finished:
///   53 bytes for SHA-256 ciphers (AES_128_GCM, CHACHA20_POLY1305)
///   69 bytes for SHA-384 ciphers (AES_256_GCM)
///
/// Previous implementation used random 36-51 bytes which is a trivially
/// detectable fingerprint — real Finished is NEVER that size.
fn append_random_finished(data: &mut Vec<u8>, cipher: Tls13Cipher) {
    let payload_len = cipher.finished_record_body_len();
    let start = data.len();
    data.resize(start + TLS_HEADER_SIZE + payload_len, 0);
    data[start] = APPLICATION_DATA;
    data[start + 1] = TLS_MAJOR;
    data[start + 2] = TLS_MINOR.0;
    data[start + 3] = (payload_len >> 8) as u8;
    data[start + 4] = payload_len as u8;
    rand::Rng::fill(&mut rand::thread_rng(), &mut data[start + TLS_HEADER_SIZE..]);
}

// ---------------------------------------------------------------------------
// V3 Handshake (boring-driven with real TLS records)
// ---------------------------------------------------------------------------

/// Perform V3 handshake using boring (BoringSSL) to drive an authentic TLS session.
///
/// Flow:
/// 1. boring generates ClientHello → we patch session_id with HMAC → send
/// 2. Read ServerHello → restore original session_id → feed to boring
/// 3. Read more server frames, feed to boring, let boring produce the client's
///    second flight (CCS + Finished for TLS 1.3, or CKE + CCS + Finished for 1.2)
/// 4. Send boring's output over TCP
///
/// For TLS 1.3: boring produces real CCS but can't produce encrypted Finished
/// (server's encrypted flight uses different keys due to transcript hash mismatch).
/// A random ApplicationData record is appended — indistinguishable from real
/// encrypted data to passive observers.
///
/// For TLS 1.2: boring produces the full authentic client flight (ClientKeyExchange +
/// CCS + encrypted Finished). The Finished hash will be wrong (different transcript),
/// but the wire traffic is 100% authentic BoringSSL output.
pub(crate) async fn perform_v3_handshake(
    tcp: &mut TcpStream,
    connector: &SslConnector,
    sni: &str,
    password: &str,
) -> io::Result<([u8; 32], bool)> {
    // Phase 1: Generate ClientHello with boring, keep mid-handshake stream
    let (mut mid, mut client_hello) = start_handshake(connector, sni)?;

    // Phase 2: Save original session_id, then patch with HMAC
    let original_sid = save_session_id(&client_hello).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "cannot extract session_id")
    })?;
    if !patch_session_id(&mut client_hello, password) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to patch ClientHello session_id",
        ));
    }
    // Save the patched session_id for HRR reuse (RFC 8446 §4.1.2:
    // "The client MUST use the same legacy_session_id in the retry ClientHello")
    let patched_sid = save_session_id(&client_hello).unwrap();

    // Phase 3: Send patched ClientHello
    let (res, _) = tcp.write_all(client_hello).await;
    res?;

    // Phase 4: Read ServerHello, handle HelloRetryRequest (HRR)
    let mut server_hello = read_tls_frame_timeout(tcp, HANDSHAKE_TIMEOUT).await?;
    let mut server_random = extract_server_random_raw(&server_hello).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to extract ServerRandom from ServerHello",
        )
    })?;
    let mut original_sid = original_sid;

    // Restore original session_id and feed to boring
    restore_server_hello_session_id(&mut server_hello, &original_sid);
    mid.get_mut().feed(&server_hello);

    // Handle HRR: boring needs to produce a new ClientHello
    if server_random == HRR_RANDOM {
        tracing::debug!("HelloRetryRequest detected, producing new ClientHello");
        match mid.handshake() {
            Err(HandshakeError::WouldBlock(mut new_mid)) => {
                let mut pending = new_mid.get_mut().take_write_buf();
                if !pending.is_empty() {
                    // HRR: CH2 must carry the same session_id as CH1 (RFC 8446 §4.1.2).
                    // Save boring's new original for restoring in the real ServerHello,
                    // then overwrite with the patched sid from CH1.
                    if pending.len() >= SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE {
                        if let Some(new_sid) = save_session_id(&pending) {
                            original_sid = new_sid;
                        }
                        pending[SESSION_ID_OFFSET..SESSION_ID_OFFSET + TLS_SESSION_ID_SIZE]
                            .copy_from_slice(&patched_sid);
                    }
                    let (res, _) = tcp.write_all(pending).await;
                    res?;
                }
                mid = new_mid;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unexpected handshake completion during HRR",
                ))
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("HRR handshake error: {e}"),
                ))
            }
        }

        // Read the real ServerHello after HRR
        server_hello = read_tls_frame_timeout(tcp, HANDSHAKE_TIMEOUT).await?;
        server_random = extract_server_random_raw(&server_hello).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "failed to extract ServerRandom after HRR",
            )
        })?;
        if server_random == HRR_RANDOM {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "server sent double HelloRetryRequest",
            ));
        }
        restore_server_hello_session_id(&mut server_hello, &original_sid);
        mid.get_mut().feed(&server_hello);
    }

    let tls13 = crate::util::support_tls13(&server_hello);
    let cipher = extract_cipher_suite_raw(&server_hello);
    tracing::debug!("ServerHello received (tls1.3={tls13}, cipher={cipher:?})");

    // Phase 6: Continue handshake — feed server frames, collect client flight
    let mut client_flight = Vec::new();
    let mut client_flight_flushed: usize = 0;
    // TLS 1.2 with large cert chains can produce many records. Use a byte
    // budget instead of a fixed record count to handle fragmented flights.
    const MAX_FRAMES: usize = 40;
    const MAX_HANDSHAKE_BYTES: usize = 256 * 1024; // 256 KiB total handshake data
    let mut handshake_bytes: usize = 0;
    let mut completed = false;

    for _ in 0..MAX_FRAMES {
        match mid.handshake() {
            Ok(mut stream) => {
                // Handshake completed (rare but possible)
                client_flight.extend(stream.get_mut().take_write_buf());
                completed = true;
                break;
            }
            Err(HandshakeError::WouldBlock(mut new_mid)) => {
                let pending = new_mid.get_mut().take_write_buf();

                // Flush any pending writes to TCP before blocking on read.
                // This is critical for HelloRetryRequest: boring produces a
                // second ClientHello that must reach the server before it
                // will send the next flight.
                if !pending.is_empty() {
                    client_flight_flushed += pending.len();
                    let (res, _) = tcp.write_all(pending).await;
                    res?;
                }

                // For TLS 1.2: once boring produces substantial output
                // (CKE + CCS + Finished), stop — the server can't respond
                // until we send these bytes (would deadlock).
                if !tls13 && client_flight_flushed > 20 {
                    tracing::debug!(
                        "TLS 1.2 client flight ready ({client_flight_flushed} bytes, flushed to TCP)"
                    );
                    completed = true;
                    break;
                }

                // Read another server frame from TCP and feed to boring
                let frame = read_tls_frame_timeout(tcp, HANDSHAKE_TIMEOUT).await?;
                handshake_bytes += frame.len();
                if handshake_bytes > MAX_HANDSHAKE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("handshake exceeded byte budget ({MAX_HANDSHAKE_BYTES} bytes)"),
                    ));
                }
                new_mid.get_mut().feed(&frame);
                mid = new_mid;
            }
            Err(HandshakeError::Failure(mut fail_mid)) => {
                client_flight.extend(fail_mid.get_mut().take_write_buf());
                let err = fail_mid.error();
                let err_str = format!("{err}");

                if tls13 {
                    // Expected for TLS 1.3: BAD_DECRYPT when boring tries to
                    // decrypt server's encrypted flight (different transcript hash).
                    //
                    // Accept the error if EITHER:
                    //   1. boring already flushed output (CCS) in the main loop, OR
                    //   2. the error is a decrypt/MAC error (always expected in TLS 1.3)
                    //
                    // Case 2 is needed for HelloRetryRequest flows: boring may have
                    // flushed CCS during HRR handling (before client_flight_flushed
                    // tracking), so client_flight_flushed can be 0 even though the
                    // handshake progressed correctly.
                    let err_lower = err_str.to_lowercase();
                    let is_decrypt_error = err_lower.contains("decrypt")
                        || err_lower.contains("bad_record_mac")
                        || err_lower.contains("mac");
                    if is_decrypt_error || client_flight_flushed > 0 {
                        if !is_decrypt_error {
                            tracing::warn!(
                                "TLS 1.3: non-decrypt failure after CCS ({client_flight_flushed} bytes flushed): {err_str}"
                            );
                        }
                        tracing::debug!(
                            "boring handshake terminated (expected for TLS 1.3): {err_str}"
                        );
                        completed = true;
                        break;
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("TLS handshake failure: {err_str}"),
                ));
            }
            Err(HandshakeError::SetupFailure(e)) => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("TLS setup failure: {e}")));
            }
        }
    }

    if !completed {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("handshake did not complete within {MAX_FRAMES} server records"),
        ));
    }

    // Phase 7: TLS 1.3 — append ApplicationData matching real encrypted Finished size
    if tls13 && !contains_application_data(&client_flight) {
        append_random_finished(&mut client_flight, cipher);
    }

    // Phase 8: Send client flight
    if !client_flight.is_empty() {
        tracing::debug!("sending client flight ({} bytes)", client_flight.len());
        let (res, _) = tcp.write_all(client_flight).await;
        res?;
    }

    tracing::debug!("handshake phase done (tls1.3={tls13})");
    Ok((server_random, tls13))
}

// ---------------------------------------------------------------------------
// TLS 1.2 Fallback (V3 strict)
// ---------------------------------------------------------------------------

/// Send a fake encrypted HTTP request and drain remaining handshake frames
/// on the TLS 1.2 fallback path.
///
/// At this point, `perform_v3_handshake` has already sent boring's authentic
/// client flight (CKE + CCS + encrypted Finished) via the shadow-tls server's
/// bidirectional proxy to the handshake server. The handshake server will reject
/// the Finished (wrong transcript hash) and send a fatal alert.
///
/// We send an additional encrypted-looking ApplicationData record (simulating
/// an HTTP request after the handshake) and drain the server's response to
/// complete a realistic traffic pattern before closing.
pub(crate) async fn fake_request_and_drain(tcp: &mut TcpStream, sni: &str) -> io::Result<()> {
    // Send a fake encrypted HTTP request as ApplicationData.
    // Size matches a realistic GET request for the configured SNI host.
    // Content is random (encrypted traffic is indistinguishable from random).
    let fake_len = format!(
        "GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
    )
    .len()
        + (rand::random::<usize>() % 32);
    let mut frame = vec![0u8; TLS_HEADER_SIZE + fake_len];
    frame[0] = APPLICATION_DATA;
    frame[1] = TLS_MAJOR;
    frame[2] = TLS_MINOR.0;
    frame[3] = (fake_len >> 8) as u8;
    frame[4] = fake_len as u8;
    rand::Rng::fill(&mut rand::thread_rng(), &mut frame[TLS_HEADER_SIZE..]);
    let (res, _) = tcp.write_all(frame).await;
    res?;

    // Drain server response frames (alert from rejected Finished, etc.)
    for _ in 0..5 {
        match monoio::time::timeout(std::time::Duration::from_secs(2), read_tls_frame(tcp)).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    Ok(())
}
