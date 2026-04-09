use std::{
    io::{ErrorKind, Read},
    net::ToSocketAddrs,
    ptr::copy_nonoverlapping,
    time::Duration,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use local_sync::oneshot::{Receiver, Sender};
use monoio::{
    buf::IoBufMut,
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    net::{ListenerOpts, TcpListener, TcpStream},
};

use aes_gcm::{aead::AeadInPlace, aead::generic_array::typenum::U12, Aes128Gcm, KeyInit as AesKeyInit, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
use rand::Rng;
use serde::Deserialize;
use sha2::Sha256;

use prelude::*;

pub(crate) mod prelude {
    pub(crate) const TLS_MAJOR: u8 = 0x03;
    pub(crate) const TLS_MINOR: (u8, u8) = (0x03, 0x01);
    pub(crate) const SNI_EXT_TYPE: u16 = 0;
    pub(crate) const SUPPORTED_VERSIONS_TYPE: u16 = 43;
    pub(crate) const TLS_RANDOM_SIZE: usize = 32;
    pub(crate) const TLS_HEADER_SIZE: usize = 5;
    pub(crate) const TLS_SESSION_ID_SIZE: usize = 32;
    pub(crate) const TLS_13: u16 = 0x0304;

    pub(crate) const CLIENT_HELLO: u8 = 0x01;
    pub(crate) const SERVER_HELLO: u8 = 0x02;
    pub(crate) const ALERT: u8 = 0x15;
    pub(crate) const HANDSHAKE: u8 = 0x16;
    pub(crate) const APPLICATION_DATA: u8 = 0x17;

    pub(crate) const SERVER_RANDOM_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
    pub(crate) const SESSION_ID_LEN_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    pub(crate) const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

    /// V3 per-frame HMAC tag size (16 bytes = HMAC-SHA256 truncated to 128 bits).
    pub(crate) const HMAC_SIZE: usize = 16;
    /// V3 SessionID HMAC size (4 bytes, used for ClientHello authentication).
    /// This is separate from per-frame HMAC_SIZE since it must fit in the session ID.
    pub(crate) const SESSION_HMAC_SIZE: usize = 4;

    // Inner framing protocol (anti TLS-in-TLS)
    /// Inner header: cmd(1) + data_len(2) = 3 bytes, placed after HMAC tag.
    pub(crate) const INNER_HEADER_SIZE: usize = 3;
    /// Full overhead per TLS record: TLS header + HMAC + inner header.
    pub(crate) const FRAME_OVERHEAD: usize = TLS_HEADER_SIZE + HMAC_SIZE + INNER_HEADER_SIZE;
    /// Inner command: real user data.
    pub(crate) const CMD_DATA: u8 = 0x01;
    /// Inner command: padding/waste (receiver discards).
    pub(crate) const CMD_PADDING: u8 = 0x00;

    // --- Mux commands (multiplexing protocol) ---
    pub(crate) const CMD_MUX_SYN: u8 = 0x02;
    pub(crate) const CMD_MUX_DATA: u8 = 0x03;
    pub(crate) const CMD_MUX_FIN: u8 = 0x04;
    pub(crate) const CMD_MUX_RST: u8 = 0x05;
    pub(crate) const CMD_MUX_WINDOW: u8 = 0x06;
    pub(crate) const CMD_MUX_PING: u8 = 0x07;
    pub(crate) const CMD_MUX_PONG: u8 = 0x08;

    /// Max inner payload per TLS record (data portion, excluding TLS header and GCM tag).
    pub(crate) const MAX_INNER_PAYLOAD: usize = 16384 - HMAC_SIZE;

    /// Default coalescing timeout in milliseconds (0 = disabled).
    pub(crate) const DEFAULT_COALESCE_MS: u64 = 2;
}

#[derive(Copy, Clone, Debug)]
pub enum V3Mode {
    Disabled,
    Lossy,
    Strict,
}

impl std::fmt::Display for V3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V3Mode::Disabled => write!(f, "disabled"),
            V3Mode::Lossy => write!(f, "enabled(lossy)"),
            V3Mode::Strict => write!(f, "enabled(strict)"),
        }
    }
}

impl V3Mode {
    #[inline]
    pub fn enabled(&self) -> bool {
        !matches!(self, V3Mode::Disabled)
    }

    #[inline]
    pub fn strict(&self) -> bool {
        matches!(self, V3Mode::Strict)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, clap::ValueEnum, Deserialize)]
pub enum WildcardSNI {
    /// Disabled
    #[serde(rename = "off")]
    Off,
    /// For authenticated client only(may be differentiable); in v2 protocol it is eq to all.
    #[serde(rename = "authed")]
    Authed,
    /// For all request(may cause service abused but not differentiable)
    #[serde(rename = "all")]
    All,
}

impl Default for WildcardSNI {
    fn default() -> Self {
        Self::Off
    }
}

impl std::fmt::Display for WildcardSNI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WildcardSNI::Off => write!(f, "off"),
            WildcardSNI::Authed => write!(f, "authed"),
            WildcardSNI::All => write!(f, "all"),
        }
    }
}

pub(crate) async fn copy_until_eof<R, W>(mut read_half: R, mut write_half: W) -> std::io::Result<()>
where
    R: monoio::io::AsyncReadRent,
    W: monoio::io::AsyncWriteRent,
{
    let copy_result = monoio::io::copy(&mut read_half, &mut write_half).await;
    let _ = write_half.shutdown().await;
    copy_result?;
    Ok(())
}

pub(crate) async fn copy_bidirectional(l: TcpStream, r: TcpStream) {
    let (lr, lw) = l.into_split();
    let (rr, rw) = r.into_split();
    let _ = monoio::join!(copy_until_eof(lr, rw), copy_until_eof(rr, lw));
}

pub(crate) fn mod_tcp_conn(conn: &mut TcpStream, keepalive: bool, nodelay: bool) {
    if keepalive {
        let _ = conn.set_tcp_keepalive(
            Some(Duration::from_secs(90)),
            Some(Duration::from_secs(90)),
            Some(2),
        );
    }
    let _ = conn.set_nodelay(nodelay);
}

#[derive(Clone)]
pub(crate) struct Hmac(hmac::Hmac<sha1::Sha1>);

impl Hmac {
    #[inline]
    pub(crate) fn new(password: &str, init_data: (&[u8], &[u8])) -> Self {
        // Note: infact new_from_slice never returns Err.
        let mut hmac: hmac::Hmac<sha1::Sha1> =
            <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(password.as_bytes())
                .expect("unable to build hmac instance");
        hmac.update(init_data.0);
        hmac.update(init_data.1);
        Self(hmac)
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub(crate) fn finalize(&self) -> [u8; SESSION_HMAC_SIZE] {
        let hmac = self.0.clone();
        let hash = hmac.finalize().into_bytes();
        let mut res = [0; SESSION_HMAC_SIZE];
        unsafe {
            copy_nonoverlapping(hash.as_slice().as_ptr(), res.as_mut_ptr(), SESSION_HMAC_SIZE)
        };
        res
    }

}

/// Per-frame AEAD with AES-128-GCM, independent sequence numbers, and direction-separated keys.
///
/// Key derivation: HKDF-SHA256 with:
///   - IKM = password
///   - salt = server_random
///   - info = direction (b"c2s" or b"s2c")
///   - output = 16-byte AES key + 12-byte base nonce (28 bytes total)
///
/// Each frame is encrypted and authenticated:
///   nonce = base_nonce XOR (seq_be64 zero-padded to 12 bytes, aligned right)
///   AAD = TLS record header (5 bytes)
///   ciphertext || tag = AES-128-GCM(key, nonce, AAD, plaintext)
///
/// The 16-byte GCM tag replaces the old HMAC-SHA256 tag (same size, same wire layout).
/// Inner payload (cmd + data_len + data + padding) is now encrypted in addition to authenticated.
///
/// Uses 64-bit sequence counter to eliminate nonce overflow risk at 64 TB
/// (u32 would overflow at ~2^32 * ~16KB ≈ 64 TB of data).
///
/// Failed verifications do NOT advance the sequence counter, avoiding state corruption.
/// In Authenticated state, any tag mismatch = immediate disconnect (strict seq policy).
pub(crate) struct FrameAead {
    cipher: Aes128Gcm,
    base_nonce: [u8; 12],
    seq: u64,
}

impl FrameAead {
    /// Create a new FrameAead with HKDF-SHA256 derived, direction-separated key and nonce.
    /// `direction` should be b"c2s" or b"s2c".
    pub(crate) fn new(password: &str, server_random: &[u8], direction: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(server_random), password.as_bytes());
        // Derive 28 bytes: 16-byte AES key + 12-byte base nonce
        let mut okm = [0u8; 28];
        hk.expand(direction, &mut okm)
            .expect("HKDF-SHA256 expand failed");
        let key: [u8; 16] = okm[..16].try_into().unwrap();
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&okm[16..28]);
        let cipher =
            <Aes128Gcm as AesKeyInit>::new_from_slice(&key).expect("AES-128-GCM key init failed");
        Self {
            cipher,
            base_nonce,
            seq: 0,
        }
    }

    /// Build the 12-byte nonce: base_nonce XOR (seq_be64 right-aligned to 12 bytes).
    #[inline]
    fn make_nonce(&self) -> Nonce<U12> {
        let mut nonce = self.base_nonce;
        let seq_bytes = self.seq.to_be_bytes(); // 8 bytes
        // XOR seq into the last 8 bytes of the nonce
        nonce[4] ^= seq_bytes[0];
        nonce[5] ^= seq_bytes[1];
        nonce[6] ^= seq_bytes[2];
        nonce[7] ^= seq_bytes[3];
        nonce[8] ^= seq_bytes[4];
        nonce[9] ^= seq_bytes[5];
        nonce[10] ^= seq_bytes[6];
        nonce[11] ^= seq_bytes[7];
        *Nonce::from_slice(&nonce)
    }

    /// Encrypt payload in-place and return the 16-byte GCM tag.
    /// `header` = TLS record header (5 bytes, used as AAD).
    /// `payload` is modified in-place to ciphertext.
    pub(crate) fn encrypt_and_advance(
        &mut self,
        header: &[u8],
        payload: &mut [u8],
    ) -> [u8; HMAC_SIZE] {
        let nonce = self.make_nonce();
        let gcm_tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, header, payload)
            .expect("AES-GCM encrypt failed");
        self.seq += 1;
        let mut tag = [0u8; HMAC_SIZE];
        tag.copy_from_slice(gcm_tag.as_slice());
        tag
    }

    /// Decrypt payload in-place and verify the GCM tag. Advances seq only on success.
    /// `header` = TLS record header (5 bytes, used as AAD).
    /// `payload` is modified in-place to plaintext on success.
    pub(crate) fn decrypt_and_advance(
        &mut self,
        header: &[u8],
        payload: &mut [u8],
        tag: &[u8; HMAC_SIZE],
    ) -> bool {
        let nonce = self.make_nonce();
        let gcm_tag = aes_gcm::Tag::from_slice(tag);
        match self
            .cipher
            .decrypt_in_place_detached(&nonce, header, payload, gcm_tag)
        {
            Ok(()) => {
                self.seq += 1;
                true
            }
            Err(_) => false,
        }
    }
}

/// Padding state for anti TLS-in-TLS with realistic traffic distribution.
///
/// Key improvements over naive fixed-boundary padding:
///   1. **Randomized transition point**: the boundary between mandatory and
///      probabilistic padding is randomized per-connection (range 5-13),
///      preventing statistical fingerprinting of a fixed packet boundary.
///   2. **Realistic traffic distribution**: mimics real HTTPS (HTTP/2) traffic
///      patterns with variable frame sizes.
///   3. **Higher tail padding**: 5% probability of 0-512B random padding after
///      the initial phase, smoothing the statistical transition.
pub(crate) struct PaddingState {
    sent: usize,
    /// Per-connection randomized transition point from mandatory to probabilistic padding.
    transition_point: usize,
}

/// Probability (out of 100) that initial-phase packets produce a near-full-size frame.
const FULL_FRAME_PROBABILITY: u32 = 5;
/// Near-full-size range when triggered (mimics large HTTPS response body).
const FULL_FRAME_RANGE: (usize, usize) = (14000, 16000);
/// Probability (out of 100) of post-initial-phase random padding.
const TAIL_PADDING_PROBABILITY: u32 = 5;
/// Max tail padding bytes.
const TAIL_PADDING_MAX: usize = 512;

impl PaddingState {
    pub(crate) fn new() -> Self {
        let mut rng = rand::thread_rng();
        // Randomize transition point: sum of three small uniforms gives a
        // roughly bell-shaped distribution centered around 9, range [5, 13].
        // This eliminates the fixed-boundary fingerprint that an observer
        // could detect across multiple connections.
        let transition_point = 5 + rng.gen_range(0..=3u32) as usize
            + rng.gen_range(0..=3u32) as usize
            + rng.gen_range(0..=2u32) as usize;
        Self {
            sent: 0,
            transition_point,
        }
    }

    /// Returns the number of padding bytes to append for the current packet.
    /// `current_payload` = tag + inner header + data (before padding).
    ///
    /// During initial phase: pads to a target payload size (mandatory).
    /// After transition: 5% chance of 0-512B extra padding (smooths the cutoff).
    pub(crate) fn next_padding_len(&mut self, current_payload: usize) -> usize {
        let mut rng = rand::thread_rng();

        if self.sent < self.transition_point {
            let range = match self.sent {
                0 => (200, 600), // HTTP request / small response
                1 => {
                    // HTTP response headers, with small chance of full-size
                    if rng.gen_range(0..100u32) < FULL_FRAME_PROBABILITY {
                        FULL_FRAME_RANGE
                    } else {
                        (800, 1400)
                    }
                }
                _ => {
                    // HTTP response body chunks, with small chance of full-size
                    // (mimics real large file download producing max-size TLS records)
                    if rng.gen_range(0..100u32) < FULL_FRAME_PROBABILITY {
                        FULL_FRAME_RANGE
                    } else {
                        (500, 1400)
                    }
                }
            };
            self.sent += 1;
            let target = rng.gen_range(range.0..=range.1);
            target.saturating_sub(current_payload)
        } else {
            // Post-initial phase: probabilistic tail padding (5%).
            // Higher probability and wider range than before to better smooth
            // the statistical transition and resist traffic analysis.
            self.sent += 1;
            if rng.gen_range(0..100u32) < TAIL_PADDING_PROBABILITY {
                rng.gen_range(0..=TAIL_PADDING_MAX)
            } else {
                0
            }
        }
    }
}

/// Parse inner framing header from a verified ApplicationData payload.
/// Input: the bytes after HMAC tag (= inner_header + data + padding).
/// Returns (cmd, data_slice) or None if malformed.
pub(crate) fn parse_inner_frame(inner: &[u8]) -> Option<(u8, &[u8])> {
    if inner.len() < INNER_HEADER_SIZE {
        return None;
    }
    let cmd = inner[0];
    let data_len = u16::from_be_bytes([inner[1], inner[2]]) as usize;
    if inner.len() < INNER_HEADER_SIZE + data_len {
        return None;
    }
    Some((cmd, &inner[INNER_HEADER_SIZE..INNER_HEADER_SIZE + data_len]))
}

/// Iterator over multiple inner frames packed in a single decrypted payload.
/// Supports coalesced records where multiple [CMD][LEN][data] tuples are
/// concatenated before encryption. Trailing bytes (padding) are ignored.
pub(crate) struct InnerFrameIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> InnerFrameIter<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for InnerFrameIter<'a> {
    /// (cmd, data_offset_in_original_buffer, data_len)
    type Item = (u8, usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = &self.data[self.pos..];
        if remaining.len() < INNER_HEADER_SIZE {
            return None;
        }
        let cmd = remaining[0];
        let data_len = u16::from_be_bytes([remaining[1], remaining[2]]) as usize;
        if remaining.len() < INNER_HEADER_SIZE + data_len {
            return None;
        }
        let data_offset = self.pos + INNER_HEADER_SIZE;
        self.pos += INNER_HEADER_SIZE + data_len;
        // For PADDING frames, consume the rest as padding (no more frames after)
        if cmd == CMD_PADDING && data_len == 0 {
            self.pos = self.data.len();
        }
        Some((cmd, data_offset, data_len))
    }
}

pub(crate) async fn verified_relay(
    raw: TcpStream,
    tls: TcpStream,
    aead_encrypt: FrameAead,
    aead_decrypt: FrameAead,
    alert_enabled: bool,
    auth_pending: bool,
) {
    verified_relay_with_coalesce(raw, tls, aead_encrypt, aead_decrypt, alert_enabled, auth_pending, 0).await;
}

pub(crate) async fn verified_relay_with_coalesce(
    raw: TcpStream,
    tls: TcpStream,
    mut aead_encrypt: FrameAead,
    mut aead_decrypt: FrameAead,
    alert_enabled: bool,
    auth_pending: bool,
    coalesce_ms: u64,
) {
    tracing::debug!("verified relay started (auth_pending={auth_pending}, coalesce_ms={coalesce_ms})");
    let (mut tls_read, mut tls_write) = tls.into_split();
    let (mut raw_read, mut raw_write) = raw.into_split();
    let (mut notfied, mut notifier) = local_sync::oneshot::channel::<()>();
    let _ = monoio::join!(
        async {
            copy_remove_appdata_and_decrypt(
                &mut tls_read,
                &mut raw_write,
                &mut aead_decrypt,
                &mut notifier,
                auth_pending,
            )
            .await;
            let _ = raw_write.shutdown().await;
        },
        async {
            if coalesce_ms > 0 {
                copy_add_appdata_coalesced(
                    &mut raw_read,
                    &mut tls_write,
                    &mut aead_encrypt,
                    &mut notfied,
                    alert_enabled,
                    coalesce_ms,
                )
                .await;
            } else {
                copy_add_appdata_and_encrypt(
                    &mut raw_read,
                    &mut tls_write,
                    &mut aead_encrypt,
                    &mut notfied,
                    alert_enabled,
                )
                .await;
            }
            let _ = tls_write.shutdown().await;
        }
    );
}

/// Bind with pretty error.
pub(crate) fn bind_with_pretty_error<A: ToSocketAddrs>(
    addr: A,
    fastopen: bool,
) -> anyhow::Result<TcpListener> {
    let cfg = ListenerOpts::default().tcp_fast_open(fastopen);
    TcpListener::bind_with_config(addr, &cfg).map_err(|e| match e.kind() {
        ErrorKind::AddrInUse => {
            anyhow::anyhow!("bind failed, check if the port is used: {e}")
        }
        ErrorKind::PermissionDenied => {
            anyhow::anyhow!("bind failed, check if permission configured correct: {e}")
        }
        _ => anyhow::anyhow!("bind failed: {e}"),
    })
}

/// State machine for receiving and decrypting authenticated application data.
///
/// States:
///   AuthPending → Authenticated (on first valid GCM frame)
///
/// In AuthPending: non-authenticated ApplicationData frames (e.g., NewSessionTickets
/// from handshake server drain) are silently discarded. FrameAead's per-frame
/// design means failed verifications do NOT corrupt state (seq stays unchanged).
/// AuthPending has resource limits: max 64 KiB discarded and max 10 seconds.
///
/// In Authenticated: ALL ApplicationData frames must have valid GCM tag.
/// Any tag mismatch = immediate disconnect (strict seq policy, no reordering).
async fn copy_remove_appdata_and_decrypt(
    read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    aead: &mut FrameAead,
    alert_notifier: &mut Receiver<()>,
    auth_pending: bool,
) {
    /// Max bytes discarded during AuthPending before giving up.
    const AUTH_PENDING_MAX_BYTES: usize = 64 * 1024;
    /// Max time in AuthPending before giving up.
    const AUTH_PENDING_MAX_SECS: u64 = 10;
    const INIT_BUFFER_SIZE: usize = 2048;

    let mut decoder = BufferFrameDecoder::new(read, INIT_BUFFER_SIZE);
    let mut authenticated = !auth_pending;
    let mut pending_bytes_discarded: usize = 0;
    // Pre-allocated decrypt buffer — reused across frames to avoid per-frame allocation.
    let mut decrypt_buf: Vec<u8> = Vec::with_capacity(16384);
    let auth_deadline = if auth_pending {
        Some(std::time::Instant::now() + Duration::from_secs(AUTH_PENDING_MAX_SECS))
    } else {
        None
    };

    loop {
        // During AuthPending, enforce a timeout on the read so that if the
        // handshake server goes quiet after sending a fatal alert, we don't
        // block forever waiting for the next frame.
        let maybe_frame = if !authenticated {
            if let Some(deadline) = auth_deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    tracing::warn!("auth pending: time limit exceeded, disconnecting");
                    alert_notifier.close();
                    return;
                }
                match monoio::time::timeout(remaining, decoder.next()).await {
                    Ok(Ok(f)) => f,
                    Ok(Err(e)) => {
                        tracing::error!("io error {e}");
                        alert_notifier.close();
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("auth pending: time limit exceeded, disconnecting");
                        alert_notifier.close();
                        return;
                    }
                }
            } else {
                match decoder.next().await {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("io error {e}");
                        alert_notifier.close();
                        return;
                    }
                }
            }
        } else {
            match decoder.next().await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("io error {e}");
                    alert_notifier.close();
                    return;
                }
            }
        };
        let frame = match maybe_frame {
            Some(frame) => frame,
            None => {
                // EOF — let encrypt side finish via raw_write.shutdown() + FIN
                return;
            }
        };
        match frame[0] {
            ALERT => {
                if !authenticated {
                    // AuthPending: discard ALL alerts (fatal and warning) from the
                    // handshake server. After our synthetic TLS 1.3 Finished, the
                    // handshake server will send a fatal alert (bad_record_mac etc.)
                    // — this is expected and must not tear down the connection before
                    // the real AEAD frame arrives from the shadow-tls client.
                    pending_bytes_discarded += frame.len();
                    if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                        tracing::warn!("auth pending: byte limit exceeded, disconnecting");
                        alert_notifier.close();
                        return;
                    }
                    if frame.len() >= TLS_HEADER_SIZE + 2 && frame[TLS_HEADER_SIZE] == 2 {
                        tracing::debug!(
                            "auth pending: discarding fatal alert (desc={})",
                            frame[TLS_HEADER_SIZE + 1]
                        );
                    } else {
                        tracing::debug!("auth pending: discarding warning alert");
                    }
                    continue;
                }
                // Authenticated: let encrypt side finish via half-close
                return;
            }
            APPLICATION_DATA => {
                if frame[1] != TLS_MAJOR
                    || frame[2] != TLS_MINOR.0
                    || frame.len() < TLS_HMAC_HEADER_SIZE
                {
                    if !authenticated {
                        pending_bytes_discarded += frame.len();
                        if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                            tracing::warn!("auth pending: byte limit exceeded, disconnecting");
                            alert_notifier.close();
                            return;
                        }
                        tracing::debug!("auth pending: discarding non-conforming frame");
                        continue;
                    }
                    alert_notifier.close();
                    return;
                }

                let header: [u8; TLS_HEADER_SIZE] =
                    frame[..TLS_HEADER_SIZE].try_into().unwrap();
                let mut tag = [0u8; HMAC_SIZE];
                tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

                // Decrypt using reusable buffer (avoids per-frame allocation)
                decrypt_buf.clear();
                decrypt_buf.extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);

                if aead.decrypt_and_advance(&header, &mut decrypt_buf, &tag) {
                    if !authenticated {
                        tracing::debug!("auth pending → authenticated (first valid GCM frame)");
                        authenticated = true;
                    }
                    // Parse inner framing from decrypted plaintext
                    match parse_inner_frame(&decrypt_buf) {
                        Some((CMD_DATA, data)) if !data.is_empty() => {
                            let data_offset = INNER_HEADER_SIZE;
                            let data_len = data.len();
                            let (res, _) = write
                                .write_all(unsafe {
                                    monoio::buf::RawBuf::new(
                                        decrypt_buf.as_ptr().add(data_offset),
                                        data_len,
                                    )
                                })
                                .await;
                            if let Err(e) = res {
                                tracing::error!("write data server failed: {e}");
                                alert_notifier.close();
                                return;
                            }
                        }
                        Some((CMD_PADDING, _)) => {
                            tracing::trace!("discarding padding frame");
                        }
                        Some((CMD_DATA, _)) => {
                            tracing::trace!("discarding empty data frame");
                        }
                        _ => {
                            tracing::warn!("malformed inner frame, disconnecting");
                            alert_notifier.close();
                            return;
                        }
                    }
                } else if !authenticated {
                    // AuthPending: discard non-authenticated frame (NewSessionTicket etc.)
                    // FrameAead seq is NOT advanced on failure, so state is clean.
                    pending_bytes_discarded += frame.len();
                    if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                        tracing::warn!("auth pending: byte limit exceeded, disconnecting");
                        alert_notifier.close();
                        return;
                    }
                    tracing::debug!("auth pending: discarding non-authenticated ApplicationData");
                    continue;
                } else {
                    // Strict seq policy: any tag error in Authenticated = disconnect.
                    tracing::warn!("authenticated: GCM verification failed (strict disconnect)");
                    alert_notifier.close();
                    return;
                }
            }
            _ => {
                if !authenticated {
                    // AuthPending: discard non-ApplicationData frames (CCS, Handshake, etc.)
                    // from the incomplete TLS handshake relay.
                    pending_bytes_discarded += frame.len();
                    if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                        tracing::warn!("auth pending: byte limit exceeded, disconnecting");
                        alert_notifier.close();
                        return;
                    }
                    tracing::debug!(
                        "auth pending: discarding frame type=0x{:02x}",
                        frame[0]
                    );
                    continue;
                }
                alert_notifier.close();
                return;
            }
        }
    }
}

/// Buffer capacity for encrypt-and-send frames.
/// Sized to fit max data (16384) + framing overhead + worst-case initial padding (16000)
/// without reallocation. Previous value (16384 + 24) caused reallocation on every
/// padded frame during the initial phase.
const ENCRYPT_BUF_SIZE: usize = 16384 + FRAME_OVERHEAD + 16384;

/// Max data bytes per read to keep TLS record payload ≤ 16384 bytes.
///
/// TLS record payload = HMAC_SIZE(16) + inner_header(3) + data + padding.
/// We cap data reads so that even without padding the record stays within
/// the standard TLS fragment limit (16384). Middleboxes and firewalls may
/// silently drop or truncate records exceeding this limit, causing frame
/// misalignment and GCM verification failures under high throughput.
const MAX_DATA_PER_FRAME: usize = 16384 - HMAC_SIZE - INNER_HEADER_SIZE;

async fn copy_add_appdata_and_encrypt(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    aead: &mut FrameAead,
    alert_notified: &mut Sender<()>,
    alert_enabled: bool,
) {
    // Buffer layout: [TLS_HDR:5][TAG:16][CMD:1][DATA_LEN:2][payload...][padding...]
    let mut buffer = Vec::with_capacity(ENCRYPT_BUF_SIZE);
    buffer.resize(FRAME_OVERHEAD, 0);
    buffer[0] = APPLICATION_DATA;
    buffer[1] = TLS_MAJOR;
    buffer[2] = TLS_MINOR.0;

    let mut padding = PaddingState::new();

    // io_uring safety: never race a read against alert_notified in select!.
    // Dropping an in-flight io_uring read leaks the buffer. Instead, complete
    // the read first and check the alert flag after each iteration.
    loop {
        let (res, buf) = read.read(buffer.slice_mut(FRAME_OVERHEAD..FRAME_OVERHEAD + MAX_DATA_PER_FRAME)).await;
        if matches!(res, Ok(0) | Err(_)) || alert_notified.is_closed() {
            buffer = buf.into_inner();
            send_alert(&mut write, alert_enabled).await;
            return;
        }
        buffer = buf.into_inner();
        let data_len = buffer.len() - FRAME_OVERHEAD;

        // Write inner header: CMD_DATA + data_len
        buffer[TLS_HMAC_HEADER_SIZE] = CMD_DATA;
        buffer[TLS_HMAC_HEADER_SIZE + 1] = (data_len >> 8) as u8;
        buffer[TLS_HMAC_HEADER_SIZE + 2] = data_len as u8;

        // Add padding (initial-phase target sizing or tail-phase random)
        let current_payload = HMAC_SIZE + INNER_HEADER_SIZE + data_len;
        let mut pad_len = padding.next_padding_len(current_payload);
        // Clamp padding so TLS record payload stays ≤ 16384
        let max_pad = MAX_DATA_PER_FRAME.saturating_sub(data_len);
        pad_len = pad_len.min(max_pad);
        if pad_len > 0 {
            buffer.resize(buffer.len() + pad_len, 0);
            rand::thread_rng().fill(&mut buffer[FRAME_OVERHEAD + data_len..]);
        }

        // Write TLS record length (before encryption, since it's AAD)
        let frame_len = buffer.len() - TLS_HEADER_SIZE;
        (&mut buffer[3..5])
            .write_u16::<BigEndian>(frame_len as u16)
            .unwrap();

        // AES-128-GCM encrypt inner payload in-place, get 16-byte tag
        let header: [u8; TLS_HEADER_SIZE] =
            buffer[..TLS_HEADER_SIZE].try_into().unwrap();
        let tag = aead.encrypt_and_advance(
            &header,
            &mut buffer[TLS_HMAC_HEADER_SIZE..],
        );
        unsafe {
            copy_nonoverlapping(
                tag.as_ptr(),
                buffer.as_mut_ptr().add(TLS_HEADER_SIZE),
                HMAC_SIZE,
            )
        };

        let (res, buf) = write.write_all(buffer).await;
        buffer = buf;

        // Reset buffer for next iteration
        unsafe { buffer.set_len(FRAME_OVERHEAD) };

        if res.is_err() {
            return;
        }
    }
}


/// Coalescing version: adds a brief delay before reading to let the kernel's
/// TCP receive buffer accumulate data, producing fewer, larger TLS records.
///
/// This is io_uring-safe: monoio's completion-based I/O cannot safely cancel
/// in-flight reads (buffer submitted to io_uring would be leaked). Instead of
/// timer+cancel, we sleep BEFORE each read (after the initial packet), which
/// causes the kernel to batch incoming TCP data naturally.
///
/// Net effect: interactive protocols (SSH, HTTP/2 control frames) produce
/// ~2-5x fewer TLS records, matching real HTTPS coalescing behavior.
async fn copy_add_appdata_coalesced(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    aead: &mut FrameAead,
    alert_notified: &mut Sender<()>,
    alert_enabled: bool,
    coalesce_ms: u64,
) {
    let mut buffer = Vec::with_capacity(ENCRYPT_BUF_SIZE);
    buffer.resize(FRAME_OVERHEAD, 0);
    buffer[0] = APPLICATION_DATA;
    buffer[1] = TLS_MAJOR;
    buffer[2] = TLS_MINOR.0;

    let mut padding = PaddingState::new();
    let coalesce_dur = Duration::from_millis(coalesce_ms);
    let mut packet_count: usize = 0;

    // io_uring safety: complete the read before checking alert, same as
    // copy_add_appdata_and_encrypt. Coalescing delay is applied BEFORE the
    // read so it naturally batches TCP data without cancelling in-flight ops.
    loop {
        if packet_count > 0 {
            monoio::time::sleep(coalesce_dur).await;
        }

        let (res, buf) = read.read(buffer.slice_mut(FRAME_OVERHEAD..FRAME_OVERHEAD + MAX_DATA_PER_FRAME)).await;
        if matches!(res, Ok(0) | Err(_)) || alert_notified.is_closed() {
            buffer = buf.into_inner();
            send_alert(&mut write, alert_enabled).await;
            return;
        }
        buffer = buf.into_inner();
        let data_len = buffer.len() - FRAME_OVERHEAD;
        packet_count += 1;

        // Write inner header: CMD_DATA + data_len
        buffer[TLS_HMAC_HEADER_SIZE] = CMD_DATA;
        buffer[TLS_HMAC_HEADER_SIZE + 1] = (data_len >> 8) as u8;
        buffer[TLS_HMAC_HEADER_SIZE + 2] = data_len as u8;

        // Add padding
        let current_payload = HMAC_SIZE + INNER_HEADER_SIZE + data_len;
        let mut pad_len = padding.next_padding_len(current_payload);
        // Clamp padding so TLS record payload stays ≤ 16384
        let max_pad = MAX_DATA_PER_FRAME.saturating_sub(data_len);
        pad_len = pad_len.min(max_pad);
        if pad_len > 0 {
            buffer.resize(buffer.len() + pad_len, 0);
            rand::thread_rng().fill(&mut buffer[FRAME_OVERHEAD + data_len..]);
        }

        // Write TLS record length
        let frame_len = buffer.len() - TLS_HEADER_SIZE;
        (&mut buffer[3..5])
            .write_u16::<BigEndian>(frame_len as u16)
            .unwrap();

        // Encrypt
        let header: [u8; TLS_HEADER_SIZE] =
            buffer[..TLS_HEADER_SIZE].try_into().unwrap();
        let tag = aead.encrypt_and_advance(
            &header,
            &mut buffer[TLS_HMAC_HEADER_SIZE..],
        );
        unsafe {
            copy_nonoverlapping(
                tag.as_ptr(),
                buffer.as_mut_ptr().add(TLS_HEADER_SIZE),
                HMAC_SIZE,
            )
        };

        let (res, buf) = write.write_all(buffer).await;
        buffer = buf;
        unsafe { buffer.set_len(FRAME_OVERHEAD) };
    }
}

async fn send_alert(mut w: impl AsyncWriteRent, alert_enabled: bool) {
    if !alert_enabled {
        return;
    }
    const FULL_SIZE: u8 = 31;
    const HEADER: [u8; TLS_HEADER_SIZE] = [
        ALERT,
        TLS_MAJOR,
        TLS_MINOR.0,
        0x00,
        FULL_SIZE - TLS_HEADER_SIZE as u8,
    ];

    let mut buf = vec![0; FULL_SIZE as usize];
    unsafe { copy_nonoverlapping(HEADER.as_ptr(), buf.as_mut_ptr(), HEADER.len()) };
    rand::thread_rng().fill(&mut buf[HEADER.len()..]);

    let _ = w.write_all(buf).await;
}

/// Parse ServerHello and return if tls1.3 is supported.
pub(crate) fn support_tls13(frame: &[u8]) -> bool {
    if frame.len() < SESSION_ID_LEN_IDX {
        return false;
    }
    let mut cursor = std::io::Cursor::new(&frame[SESSION_ID_LEN_IDX..]);
    macro_rules! read_ok {
        ($res: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return false;
                }
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites
    read_ok!(cursor.skip(3));
    // skip ext length
    let cnt = read_ok!(cursor.read_u16::<BigEndian>());

    for _ in 0..cnt {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type != SUPPORTED_VERSIONS_TYPE {
            read_ok!(cursor.skip_by_u16());
            continue;
        }
        let ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        let ext_val = read_ok!(cursor.read_u16::<BigEndian>());
        let use_tls13 = ext_len == 2 && ext_val == TLS_13;
        tracing::debug!("found supported_versions extension, tls1.3: {use_tls13}");
        return use_tls13;
    }
    false
}

/// A helper trait for fast read and skip.
pub(crate) trait CursorExt {
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>>;
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
    fn skip_by_u8(&mut self) -> std::io::Result<u8>;
    fn skip_by_u16(&mut self) -> std::io::Result<u16>;
}

impl<T> CursorExt for std::io::Cursor<T>
where
    std::io::Cursor<T>: std::io::Read,
{
    #[inline]
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.read_u16::<BigEndian>()?;
        let mut buf = vec![0; len as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[inline]
    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        for _ in 0..n {
            self.read_u8()?;
        }
        Ok(())
    }

    #[inline]
    fn skip_by_u8(&mut self) -> std::io::Result<u8> {
        let len = self.read_u8()?;
        self.skip(len as usize)?;
        Ok(len)
    }

    #[inline]
    fn skip_by_u16(&mut self) -> std::io::Result<u16> {
        let len = self.read_u16::<BigEndian>()?;
        self.skip(len as usize)?;
        Ok(len)
    }
}

trait ReadExt {
    fn unexpected_eof(self) -> Self;
}

impl ReadExt for std::io::Result<usize> {
    #[inline]
    fn unexpected_eof(self) -> Self {
        self.and_then(|n| match n {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )),
            _ => Ok(n),
        })
    }
}

pub(crate) struct BufferFrameDecoder<T> {
    reader: T,
    buffer: Option<Vec<u8>>,
    read_pos: usize,
}

impl<T: AsyncReadRent> BufferFrameDecoder<T> {
    #[inline]
    pub(crate) fn new(reader: T, capacity: usize) -> Self {
        Self {
            reader,
            buffer: Some(Vec::with_capacity(capacity)),
            read_pos: 0,
        }
    }

    // note: uncancelable
    pub(crate) async fn next(&mut self) -> std::io::Result<Option<&[u8]>> {
        loop {
            let l = self.get_buffer().len();
            match l {
                0 => {
                    // empty buffer
                    if self.feed_data().await? == 0 {
                        // eof
                        return Ok(None);
                    }
                    continue;
                }
                1..=4 => {
                    // has header but not enough to parse length
                    self.feed_data().await.unexpected_eof()?;
                    continue;
                }
                _ => {
                    // buffer is enough to parse length
                    let buffer = self.get_buffer();
                    let mut size: [u8; 2] = Default::default();
                    size.copy_from_slice(&buffer[3..5]);
                    let data_size = u16::from_be_bytes(size) as usize;
                    if buffer.len() < TLS_HEADER_SIZE + data_size {
                        // we will do compact and read more data
                        self.reserve(TLS_HEADER_SIZE + data_size);
                        self.feed_data().await.unexpected_eof()?;
                        continue;
                    }
                    // buffer is enough to parse data
                    let slice = &self.buffer.as_ref().unwrap()
                        [self.read_pos..self.read_pos + TLS_HEADER_SIZE + data_size];
                    self.read_pos += TLS_HEADER_SIZE + data_size;
                    return Ok(Some(slice));
                }
            }
        }
    }

    // note: uncancelable
    async fn feed_data(&mut self) -> std::io::Result<usize> {
        self.compact();
        let buffer = self.buffer.take().unwrap();
        let idx = buffer.len();
        let read_buffer = buffer.slice_mut(idx..);
        let (res, read_buffer) = self.reader.read(read_buffer).await;
        self.buffer = Some(read_buffer.into_inner());
        res
    }

    #[inline]
    fn get_buffer(&self) -> &[u8] {
        &self.buffer.as_ref().unwrap()[self.read_pos..]
    }

    /// Make sure the Vec has at least that capacity.
    #[inline]
    fn reserve(&mut self, n: usize) {
        let buf = self.buffer.as_mut().unwrap();
        if n > buf.len() {
            buf.reserve(n - buf.len());
        }
    }

    #[inline]
    fn compact(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        let buffer = self.buffer.as_mut().unwrap();
        let ptr = buffer.as_mut_ptr();
        let readable_len = buffer.len() - self.read_pos;
        unsafe {
            std::ptr::copy(ptr.add(self.read_pos), ptr, readable_len);
            buffer.set_init(readable_len);
        }
        self.read_pos = 0;
    }
}

pub(crate) async fn resolve(addr: &str) -> std::io::Result<std::net::SocketAddr> {
    // Try parse as SocketAddr
    if let Ok(sockaddr) = addr.parse() {
        return Ok(sockaddr);
    }
    // Spawn blocking
    let addr_clone = addr.to_string();
    let mut addr_iter = monoio::spawn_blocking(move || addr_clone.to_socket_addrs())
        .await
        .unwrap()?;
    addr_iter.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unable to resolve addr: {addr}"),
        )
    })
}
