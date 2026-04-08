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

use hkdf::Hkdf;
use hmac::Mac;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};

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
    pub(crate) const CHANGE_CIPHER_SPEC: u8 = 0x14;

    pub(crate) const SERVER_RANDOM_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
    pub(crate) const SESSION_ID_LEN_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    pub(crate) const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

    pub(crate) const COPY_BUF_SIZE: usize = 4096;
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
    /// Number of initial data packets to pad.
    pub(crate) const PADDING_COUNT: usize = 8;
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
            hmac::Hmac::new_from_slice(password.as_bytes()).expect("unable to build hmac instance");
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

    #[inline]
    pub(crate) fn to_owned(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Per-frame HMAC with independent sequence numbers and direction-separated keys.
///
/// Key derivation: HKDF-SHA256 with:
///   - IKM = password
///   - salt = server_random
///   - info = direction (b"c2s" or b"s2c")
///
/// Each frame is authenticated independently:
///   tag = HMAC-SHA256(key, seq || header || payload)[..16]
///
/// `header` = TLS record header (type + version + length, 5 bytes).
/// Failed verifications do NOT advance the sequence counter, avoiding state corruption.
/// In Authenticated state, any tag mismatch = immediate disconnect (strict seq policy).
pub(crate) struct FrameHmac {
    key: [u8; 32],
    seq: u32,
}

impl FrameHmac {
    /// Create a new FrameHmac with HKDF-SHA256 derived, direction-separated key.
    /// `direction` should be b"c2s" or b"s2c".
    pub(crate) fn new(password: &str, server_random: &[u8], direction: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(server_random), password.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(direction, &mut key)
            .expect("HKDF-SHA256 expand failed");
        Self { key, seq: 0 }
    }

    /// Compute HMAC-SHA256 tag for a frame at the current sequence number.
    /// `header` is the 5-byte TLS record header; `payload` is the frame body after the HMAC tag.
    fn compute_tag(&self, header: &[u8], payload: &[u8]) -> [u8; HMAC_SIZE] {
        let mut mac: hmac::Hmac<Sha256> =
            hmac::Hmac::new_from_slice(&self.key).expect("unable to build hmac instance");
        mac.update(&self.seq.to_be_bytes());
        mac.update(header);
        mac.update(payload);
        let hash = mac.finalize().into_bytes();
        let mut tag = [0u8; HMAC_SIZE];
        unsafe { copy_nonoverlapping(hash.as_slice().as_ptr(), tag.as_mut_ptr(), HMAC_SIZE) };
        tag
    }

    /// Verify tag against frame data. Advances seq only on success.
    /// `header` = TLS record header (5 bytes), `payload` = data after HMAC tag.
    pub(crate) fn verify_and_advance(
        &mut self,
        header: &[u8],
        payload: &[u8],
        tag: &[u8; HMAC_SIZE],
    ) -> bool {
        let expected = self.compute_tag(header, payload);
        if expected == *tag {
            self.seq += 1;
            true
        } else {
            false
        }
    }

    /// Compute tag and advance seq. Used when sending.
    /// `header` = TLS record header (5 bytes), `payload` = frame body.
    pub(crate) fn tag_and_advance(&mut self, header: &[u8], payload: &[u8]) -> [u8; HMAC_SIZE] {
        let tag = self.compute_tag(header, payload);
        self.seq += 1;
        tag
    }
}

/// Padding state for anti TLS-in-TLS.
///
/// Tracks how many data packets have been sent and generates target
/// TLS record payload sizes for the first `PADDING_COUNT` packets.
/// After that, no padding is added.
pub(crate) struct PaddingState {
    sent: usize,
}

impl PaddingState {
    pub(crate) fn new() -> Self {
        Self { sent: 0 }
    }

    /// Returns the target TLS record *payload* size (= HMAC + inner header + data + padding)
    /// for the current packet, or None if padding is no longer needed.
    pub(crate) fn next_target_payload(&mut self) -> Option<usize> {
        if self.sent >= PADDING_COUNT {
            return None;
        }
        let range = match self.sent {
            0 => (200, 600),      // mimics HTTP request / small response
            1 => (800, 1400),     // mimics HTTP response headers
            _ => (500, 1400),     // mimics HTTP response body chunks
        };
        self.sent += 1;
        let target = rand::thread_rng().gen_range(range.0..=range.1);
        Some(target)
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

#[inline]
#[allow(dead_code)]
pub(crate) fn xor_slice(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(d, k)| *d ^= k);
}

#[inline]
#[allow(dead_code)]
pub(crate) fn kdf(password: &str, server_random: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    let hash = hasher.finalize();
    hash.to_vec()
}

pub(crate) async fn verified_relay(
    raw: TcpStream,
    tls: TcpStream,
    mut hmac_add: FrameHmac,
    mut hmac_verify: FrameHmac,
    alert_enabled: bool,
    auth_pending: bool,
) {
    tracing::debug!("verified relay started (auth_pending={auth_pending})");
    let (mut tls_read, mut tls_write) = tls.into_split();
    let (mut raw_read, mut raw_write) = raw.into_split();
    let (mut notfied, mut notifier) = local_sync::oneshot::channel::<()>();
    let _ = monoio::join!(
        async {
            copy_remove_appdata_and_verify(
                &mut tls_read,
                &mut raw_write,
                &mut hmac_verify,
                &mut notifier,
                auth_pending,
            )
            .await;
            let _ = raw_write.shutdown().await;
        },
        async {
            copy_add_appdata(
                &mut raw_read,
                &mut tls_write,
                &mut hmac_add,
                &mut notfied,
                alert_enabled,
            )
            .await;
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

/// State machine for receiving authenticated application data.
///
/// States:
///   AuthPending → Authenticated (on first valid HMAC frame)
///
/// In AuthPending: non-HMAC ApplicationData frames (e.g., NewSessionTickets
/// from handshake server drain) are silently discarded. FrameHmac's per-frame
/// design means failed verifications do NOT corrupt state (seq stays unchanged).
/// AuthPending has resource limits: max 64 KiB discarded and max 10 seconds.
///
/// In Authenticated: ALL ApplicationData frames must have valid HMAC.
/// Any tag mismatch = immediate disconnect (strict seq policy, no reordering).
async fn copy_remove_appdata_and_verify(
    read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac_verify: &mut FrameHmac,
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
    let auth_deadline = if auth_pending {
        Some(std::time::Instant::now() + Duration::from_secs(AUTH_PENDING_MAX_SECS))
    } else {
        None
    };

    loop {
        // Check AuthPending time limit
        if !authenticated {
            if let Some(deadline) = auth_deadline {
                if std::time::Instant::now() >= deadline {
                    tracing::warn!("auth pending: time limit exceeded, disconnecting");
                    alert_notifier.close();
                    return;
                }
            }
        }

        let maybe_frame = match decoder.next().await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("io error {e}");
                alert_notifier.close();
                return;
            }
        };
        let frame = match maybe_frame {
            Some(frame) => frame,
            None => {
                // EOF
                return;
            }
        };
        match frame[0] {
            ALERT => {
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

                let header = &frame[..TLS_HEADER_SIZE];
                let payload = &frame[TLS_HMAC_HEADER_SIZE..];
                let mut tag = [0u8; HMAC_SIZE];
                tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

                if hmac_verify.verify_and_advance(header, payload, &tag) {
                    if !authenticated {
                        tracing::debug!("auth pending → authenticated (first valid HMAC frame)");
                        authenticated = true;
                    }
                    // Parse inner framing: [cmd:1][data_len:2][data...][padding...]
                    let inner = &frame[TLS_HMAC_HEADER_SIZE..];
                    match parse_inner_frame(inner) {
                        Some((CMD_DATA, data)) if !data.is_empty() => {
                            let data_offset = TLS_HMAC_HEADER_SIZE + INNER_HEADER_SIZE;
                            let data_len = data.len();
                            let (res, _) = write
                                .write_all(unsafe {
                                    monoio::buf::RawBuf::new(
                                        frame.as_ptr().add(data_offset),
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
                            // Pure padding/waste frame, discard silently
                            tracing::trace!("discarding padding frame");
                        }
                        Some((CMD_DATA, _)) => {
                            // DATA with zero-length payload — skip
                            tracing::trace!("discarding empty data frame");
                        }
                        _ => {
                            tracing::warn!("malformed inner frame, disconnecting");
                            alert_notifier.close();
                            return;
                        }
                    }
                } else if !authenticated {
                    // AuthPending: discard non-HMAC frame (NewSessionTicket etc.)
                    // FrameHmac seq is NOT advanced on failure, so state is clean.
                    pending_bytes_discarded += frame.len();
                    if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                        tracing::warn!("auth pending: byte limit exceeded, disconnecting");
                        alert_notifier.close();
                        return;
                    }
                    tracing::debug!("auth pending: discarding non-HMAC ApplicationData");
                    continue;
                } else {
                    // Strict seq policy: any tag error in Authenticated = disconnect.
                    tracing::warn!("authenticated: HMAC verification failed (strict disconnect)");
                    alert_notifier.close();
                    return;
                }
            }
            _ => {
                alert_notifier.close();
                return;
            }
        }
    }
}

async fn copy_add_appdata(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    hmac: &mut FrameHmac,
    alert_notified: &mut Sender<()>,
    alert_enabled: bool,
) {
    // Buffer layout: [TLS_HDR:5][HMAC:16][CMD:1][DATA_LEN:2][payload...][padding...]
    let mut buffer = Vec::with_capacity(COPY_BUF_SIZE);
    // Reserve space for TLS header + HMAC + inner header
    buffer.resize(FRAME_OVERHEAD, 0);
    buffer[0] = APPLICATION_DATA;
    buffer[1] = TLS_MAJOR;
    buffer[2] = TLS_MINOR.0;

    let mut padding = PaddingState::new();
    let alert_notified = alert_notified.closed();
    let mut alert_notified = std::pin::pin!(alert_notified);

    loop {
        monoio::select! {
            _ = &mut alert_notified => {
                send_alert(&mut write, alert_enabled).await;
                return;
            },
            (res, buf) = read.read(buffer.slice_mut(FRAME_OVERHEAD..)) => {
                if matches!(res, Ok(0) | Err(_)) {
                    send_alert(&mut write, alert_enabled).await;
                    return;
                }
                buffer = buf.into_inner();
                let data_len = buffer.len() - FRAME_OVERHEAD;

                // Write inner header: CMD_DATA + data_len
                buffer[TLS_HMAC_HEADER_SIZE] = CMD_DATA;
                buffer[TLS_HMAC_HEADER_SIZE + 1] = (data_len >> 8) as u8;
                buffer[TLS_HMAC_HEADER_SIZE + 2] = data_len as u8;

                // Add padding for first N packets
                if let Some(target_payload) = padding.next_target_payload() {
                    // target_payload = total TLS record payload (HMAC + inner_hdr + data + padding)
                    let current_payload = HMAC_SIZE + INNER_HEADER_SIZE + data_len;
                    if target_payload > current_payload {
                        let pad_len = target_payload - current_payload;
                        buffer.resize(buffer.len() + pad_len, 0);
                        // Fill padding with random bytes
                        rand::thread_rng().fill(&mut buffer[FRAME_OVERHEAD + data_len..]);
                    }
                }

                // Write TLS record length
                let frame_len = buffer.len() - TLS_HEADER_SIZE;
                (&mut buffer[3..5])
                    .write_u16::<BigEndian>(frame_len as u16)
                    .unwrap();

                // Per-frame HMAC over inner content (cmd + data_len + data + padding)
                let header = &[buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]];
                let hmac_val = hmac.tag_and_advance(header, &buffer[TLS_HMAC_HEADER_SIZE..]);
                unsafe { copy_nonoverlapping(hmac_val.as_ptr(), buffer.as_mut_ptr().add(TLS_HEADER_SIZE), HMAC_SIZE) };

                let (res, buf) = write.write_all(buffer).await;
                buffer = buf;

                // Reset buffer for next iteration
                unsafe { buffer.set_len(FRAME_OVERHEAD) };

                if res.is_err() {
                    return;
                }
            }
        }
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

struct BufferFrameDecoder<T> {
    reader: T,
    buffer: Option<Vec<u8>>,
    read_pos: usize,
}

impl<T: AsyncReadRent> BufferFrameDecoder<T> {
    #[inline]
    fn new(reader: T, capacity: usize) -> Self {
        Self {
            reader,
            buffer: Some(Vec::with_capacity(capacity)),
            read_pos: 0,
        }
    }

    // note: uncancelable
    async fn next(&mut self) -> std::io::Result<Option<&[u8]>> {
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
