use std::{
    borrow::Cow,
    ptr::copy_nonoverlapping,
    rc::Rc,
    sync::Arc,
};

use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt};
use local_sync::oneshot::Sender;
use monoio::{
    buf::IoBufMut,
    io::{
        AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt,
        Splitable,
    },
    net::TcpStream,
};
use serde::Deserialize;

use crate::{
    util::{
        bind_with_pretty_error, copy_bidirectional, mod_tcp_conn, prelude::*,
        resolve, support_tls13, verified_relay, CursorExt, FrameAead, Hmac, V3Mode,
    },
    WildcardSNI,
};

/// ShadowTlsServer.
#[derive(Clone)]
pub struct ShadowTlsServer {
    listen_addr: Arc<String>,
    target_addr: Arc<String>,
    tls_addr: Arc<TlsAddrs>,
    password: Arc<String>,
    nodelay: bool,
    fastopen: bool,
    v3: V3Mode,
    mux: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TlsAddrs {
    dispatch: rustc_hash::FxHashMap<String, String>,
    fallback: String,
    wildcard_sni: WildcardSNI,
}

impl TlsAddrs {
    fn find<'a>(&'a self, key: Option<&str>, auth: bool) -> Cow<'a, str> {
        match key {
            Some(k) => match self.dispatch.get(k) {
                Some(v) => Cow::Borrowed(v),
                None => match self.wildcard_sni {
                    WildcardSNI::Authed if auth => Cow::Owned(format!("{k}:443")),
                    WildcardSNI::All => Cow::Owned(format!("{k}:443")),
                    _ => Cow::Borrowed(&self.fallback),
                },
            },
            None => Cow::Borrowed(&self.fallback),
        }
    }

    pub fn set_wildcard_sni(&mut self, wildcard_sni: WildcardSNI) {
        self.wildcard_sni = wildcard_sni;
    }
}

/// Parse a single address part from the TLS address list.
/// Supports formats: `host`, `host:port`, `key:host:port`, `[ipv6]:port`, `key:[ipv6]:port`
fn parse_addr_part(part: &str) -> anyhow::Result<(String, String, String)> {
    // Handle bracketed IPv6: find ] first
    if let Some(bracket_end) = part.find(']') {
        let bracket_start = part.find('[').ok_or_else(|| {
            anyhow::anyhow!("mismatched brackets in address: {part}")
        })?;
        let ipv6 = &part[bracket_start + 1..bracket_end];
        let before = &part[..bracket_start];
        let after = &part[bracket_end + 1..];

        let key = if before.ends_with(':') {
            before.trim_end_matches(':').to_string()
        } else {
            String::new()
        };

        let port = if after.starts_with(':') {
            after[1..].to_string()
        } else {
            "443".to_string()
        };

        let host = format!("[{ipv6}]");
        let key = if key.is_empty() { host.clone() } else { key };
        return Ok((key, host, port));
    }

    // Non-IPv6: split by ':'
    let parts: Vec<&str> = part.split(':').collect();
    match parts.len() {
        1 => {
            // host only
            Ok((parts[0].to_string(), parts[0].to_string(), "443".to_string()))
        }
        2 => {
            // host:port or key:host
            if parts[1].parse::<u16>().is_ok() {
                Ok((parts[0].to_string(), parts[0].to_string(), parts[1].to_string()))
            } else {
                Ok((parts[0].to_string(), parts[1].to_string(), "443".to_string()))
            }
        }
        3 => {
            // key:host:port
            Ok((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()))
        }
        _ => anyhow::bail!("unrecognized server addrs part: {part}"),
    }
}

impl TryFrom<&str> for TlsAddrs {
    type Error = anyhow::Error;

    fn try_from(arg: &str) -> Result<Self, Self::Error> {
        let mut rev_parts = arg.split(';').rev();
        let fallback = rev_parts
            .next()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) })
            .ok_or_else(|| anyhow::anyhow!("empty server addrs"))?;
        let fallback = if fallback.contains('[') || fallback.contains(':') {
            // Already has port or is IPv6
            fallback.to_string()
        } else {
            format!("{fallback}:443")
        };

        let mut dispatch = rustc_hash::FxHashMap::default();
        for p in rev_parts {
            let part = p.trim();
            // Parse host:port supporting IPv6 bracket notation [::1]:443
            // Format: [key:]host[:port] where host may be [ipv6]
            let (key, host, port) = parse_addr_part(part)?;
            if dispatch
                .insert(key.to_string(), format!("{host}:{port}"))
                .is_some()
            {
                bail!("duplicate server addrs part found");
            }
        }
        Ok(TlsAddrs {
            dispatch,
            fallback,
            wildcard_sni: Default::default(),
        })
    }
}

impl std::fmt::Display for TlsAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(wildcard-sni:{})", self.wildcard_sni)?;
        for (k, v) in self.dispatch.iter() {
            write!(f, "{k}->{v};")?;
        }
        write!(f, "fallback->{}", self.fallback)
    }
}

impl ShadowTlsServer {
    pub fn new(
        listen_addr: String,
        target_addr: String,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
        mux: bool,
    ) -> Self {
        Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            tls_addr: Arc::new(tls_addr),
            password: Arc::new(password),
            nodelay,
            fastopen,
            v3,
            mux,
        }
    }
}

impl ShadowTlsServer {
    /// Serve a raw connection.
    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = bind_with_pretty_error(self.listen_addr.as_ref(), self.fastopen)?;
        let shared = Rc::new(self);
        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let server = shared.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        let _ = server.relay(conn).await;
                        tracing::info!("Relay for {addr} finished");
                    });
                }
                Err(e) => {
                    tracing::error!("Accept failed: {e}");
                }
            }
        }
    }

    /// Main relay (V3 protocol).
    async fn relay(&self, mut in_stream: TcpStream) -> anyhow::Result<()> {
        // stage 1.1: read and validate client hello
        let first_client_frame = read_exact_frame(&mut in_stream).await?;
        let (client_hello_pass, sni) = verified_extract_sni(&first_client_frame, &self.password);

        // connect handshake server
        let server_name = sni.and_then(|s| String::from_utf8(s).ok());
        let addr = resolve(
            &self
                .tls_addr
                .find(server_name.as_ref().map(AsRef::as_ref), client_hello_pass),
        )
        .await?;
        let mut handshake_stream = TcpStream::connect_addr(addr).await?;
        mod_tcp_conn(&mut handshake_stream, true, self.nodelay);
        tracing::debug!("handshake server connected: {addr}");
        tracing::trace!("ClientHello frame {first_client_frame:?}");
        let (res, _) = handshake_stream.write_all(first_client_frame).await;
        res?;
        if !client_hello_pass {
            // if client verify failed, bidirectional copy and return
            tracing::warn!("ClientHello verify failed, will work as a SNI proxy");
            copy_bidirectional(in_stream, handshake_stream).await;
            return Ok(());
        }
        tracing::debug!("ClientHello verify success");

        // stage 1.2: read server hello and extract server random from it
        let first_server_frame = read_exact_frame(&mut handshake_stream).await?;
        let (res, first_server_frame) = in_stream.write_all(first_server_frame).await;
        res?;
        let mut server_random = match extract_server_random(&first_server_frame) {
            Some(sr) => sr,
            None => {
                // we cannot extract server random, bidirectional copy and return
                tracing::warn!("ServerRandom extract failed, will copy bidirectional");
                copy_bidirectional(in_stream, handshake_stream).await;
                return Ok(());
            }
        };
        tracing::debug!("Client authenticated. ServerRandom extracted: {server_random:?}");

        // Handle HelloRetryRequest: if the first server frame is HRR (synthetic random),
        // relay the retry ClientHello and read the real ServerHello to get the actual random.
        // Without this, client and server derive different AEAD keys on HRR paths.
        if server_random == crate::boring_tls::HRR_RANDOM {
            tracing::debug!("HelloRetryRequest detected on server side, relaying retry");
            // Read retry ClientHello from shadow-tls client → forward to handshake server
            let retry_client_hello = read_exact_frame(&mut in_stream).await?;
            let (res, _) = handshake_stream.write_all(retry_client_hello).await;
            res?;
            // Read real ServerHello from handshake server → forward to shadow-tls client
            let real_server_hello = read_exact_frame(&mut handshake_stream).await?;
            let (res, real_server_hello) = in_stream.write_all(real_server_hello).await;
            res?;
            server_random = match extract_server_random(&real_server_hello) {
                Some(sr) => sr,
                None => {
                    tracing::warn!("ServerRandom extract failed after HRR, will copy bidirectional");
                    copy_bidirectional(in_stream, handshake_stream).await;
                    return Ok(());
                }
            };
            if server_random == crate::boring_tls::HRR_RANDOM {
                tracing::error!("double HelloRetryRequest, aborting");
                return Ok(());
            }
            tracing::debug!("Real ServerRandom extracted after HRR: {server_random:?}");
        }

        let use_tls13 = support_tls13(&first_server_frame);
        if self.v3.strict() && !use_tls13 {
            tracing::error!(
                "V3 strict enabled and TLS 1.3 is not supported, will copy bidirectional"
            );
            copy_bidirectional(in_stream, handshake_stream).await;
            return Ok(());
        }

        // stage 1.3.1: create per-frame AEAD with direction-separated keys
        let mut frame_aead_c2s = FrameAead::new(&self.password, &server_random, b"c2s");
        let frame_aead_s2c = FrameAead::new(&self.password, &server_random, b"s2c");

        // Pre-resolve data server address during handshake relay to save DNS latency.
        // This overlaps DNS resolution with the handshake relay phase.
        let data_addr = resolve(&self.target_addr).await?;

        // stage 1.3.2: copy ShadowTLS Client -> Handshake Server until hmac matches
        // stage 1.3.3: copy Handshake Server -> ShadowTLS Client verbatim (no modification)
        //
        // Event-driven drain: after client HMAC detected, shutdown h_write (TCP FIN).
        // The handshake server processes ClientFinished, sends NewSessionTickets, then
        // sees EOF and closes. The verbatim relay reads until h_read EOF (event-driven,
        // no sleep/timeout). A safety timeout prevents indefinite blocking if the
        // handshake server misbehaves.
        let (mut c_read, mut c_write) = in_stream.into_split();
        let pure_data = {
            let (mut h_read, mut h_write) = handshake_stream.into_split();
            let (mut stop_tx, stop_rx) = local_sync::oneshot::channel::<()>();
            let (maybe_pure, _) = monoio::join!(
                async {
                    let r = copy_by_frame_until_aead_matches(
                        &mut c_read,
                        &mut h_write,
                        &mut frame_aead_c2s,
                    )
                    .await;
                    // Shutdown write to handshake server (TCP FIN). Handshake server
                    // processes ClientFinished, sends NewSessionTickets, then closes.
                    let _ = h_write.shutdown().await;
                    // Drop the receiver to signal verbatim relay to stop immediately.
                    // This unblocks stop_tx.closed() in copy_by_frame_verbatim,
                    // avoiding a 30s idle timeout wait.
                    drop(stop_rx);
                    r
                },
                async {
                    // Relay handshake server → client verbatim, concurrently.
                    // Terminates on: EOF from handshake server, stop signal, or idle timeout.
                    let _ = copy_by_frame_verbatim(
                        &mut h_read,
                        &mut c_write,
                        &mut stop_tx,
                    )
                    .await;
                    // Do NOT shutdown c_write — the client TCP continues in data phase.
                }
            );
            match maybe_pure {
                Ok(ref data) => tracing::trace!("aead match ok, pure_data len={}", data.len()),
                Err(ref e) => tracing::warn!("aead match failed: {e}"),
            }
            maybe_pure?
        };
        tracing::debug!("handshake relay finished");

        // early drop useless resources
        drop(first_server_frame);

        let tls_stream = unsafe { c_read.reunite(c_write).unwrap_unchecked() };

        // Detect mux mode: if the first decrypted payload starts with CMD_MUX_SYN (0x02),
        // the client is using multiplexing. Otherwise it's legacy 1:1 relay.
        if self.mux && !pure_data.is_empty() && pure_data[0] == CMD_MUX_SYN {
            // Parse the SYN frame from pure_data (it's the raw inner payload)
            if let Some((syn_frame, _)) = crate::mux::MuxFrame::decode(&pure_data) {
                tracing::info!("Mux mode detected, entering mux dispatcher");
                crate::mux::mux_server_dispatch(
                    tls_stream,
                    frame_aead_s2c,
                    frame_aead_c2s,
                    &self.target_addr,
                    self.nodelay,
                    syn_frame,
                )
                .await?;
            }
        } else {
            // Legacy 1:1 relay
            let mut data_stream = TcpStream::connect_addr(data_addr).await?;
            mod_tcp_conn(&mut data_stream, true, self.nodelay);
            let (res, _) = data_stream.write_all(pure_data).await;
            res?;
            verified_relay(
                data_stream,
                tls_stream,
                frame_aead_s2c,
                frame_aead_c2s,
                !use_tls13,
                false,
            )
            .await;
        }
        Ok(())
    }
}


/// Read a single frame and return Vec.
///
/// Only used by V3 protocol.
async fn read_exact_frame(r: impl AsyncReadRent) -> std::io::Result<Vec<u8>> {
    read_exact_frame_into(r, Vec::new()).await
}

/// Read a single frame into given Vec.
///
/// Only used by V3 protocol.
async fn read_exact_frame_into(
    mut r: impl AsyncReadRent,
    mut buffer: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    unsafe { buffer.set_len(0) };
    buffer.reserve(TLS_HEADER_SIZE);
    let (res, header) = r.read_exact(buffer.slice_mut(..TLS_HEADER_SIZE)).await;
    res?;
    let mut buffer = header.into_inner();

    // read tls frame length
    let mut size: [u8; 2] = Default::default();
    size.copy_from_slice(&buffer[3..5]);
    let data_size = u16::from_be_bytes(size) as usize;

    // read tls frame body
    buffer.reserve(data_size);
    let (res, data_slice) = r
        .read_exact(buffer.slice_mut(TLS_HEADER_SIZE..TLS_HEADER_SIZE + data_size))
        .await;
    res?;

    Ok(data_slice.into_inner())
}

/// Parse frame, verify it and extract SNI.
/// Return is_pass and Option<SNI>.
/// It requires &mut but it is meant for doing operation inplace.
/// It does not modify the data.
///
/// Only used by V3 protocol.
fn verified_extract_sni(frame: &[u8], password: &str) -> (bool, Option<Vec<u8>>) {
    // 5 frame header + 1 handshake type + 3 length + 2 version + 32 random + 1 session id len + 32 session id
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
    const HMAC_IDX: usize = SESSION_ID_LEN_IDX + 1 + TLS_SESSION_ID_SIZE - SESSION_HMAC_SIZE;
    const ZERO4B: [u8; SESSION_HMAC_SIZE] = [0; SESSION_HMAC_SIZE];

    if frame.len() < SESSION_ID_LEN_IDX || frame[0] != HANDSHAKE || frame[5] != CLIENT_HELLO {
        return (false, None);
    }

    let pass = if frame.len() < MIN_LEN || frame[SESSION_ID_LEN_IDX] != TLS_SESSION_ID_SIZE as u8 {
        false
    } else {
        let mut hmac = Hmac::new(password, (&[], &[]));
        hmac.update(&frame[TLS_HEADER_SIZE..HMAC_IDX]);
        hmac.update(&ZERO4B);
        hmac.update(&frame[HMAC_IDX + SESSION_HMAC_SIZE..]);
        hmac.finalize() == frame[HMAC_IDX..HMAC_IDX + SESSION_HMAC_SIZE]
    };

    let mut cursor = std::io::Cursor::new(&frame[SESSION_ID_LEN_IDX..]);
    macro_rules! read_ok {
        ($res: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return (pass, None);
                }
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites
    read_ok!(cursor.skip_by_u16());
    // skip compression method
    read_ok!(cursor.skip_by_u8());
    // skip ext length
    read_ok!(cursor.read_u16::<BigEndian>());

    loop {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type != SNI_EXT_TYPE {
            read_ok!(cursor.skip_by_u16());
            continue;
        }
        tracing::debug!("found server_name extension");
        let _ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        let _sni_len = read_ok!(cursor.read_u16::<BigEndian>());
        // must be host_name
        if read_ok!(cursor.read_u8()) != 0 {
            return (pass, None);
        }
        let sni = Some(read_ok!(cursor.read_by_u16()));
        return (pass, sni);
    }
}

/// Parse given frame and extract ServerRandom.
/// Return Option<ServerRandom>.
///
/// Only used by V3 protocol.
fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    // 5 frame header + 1 handshake type + 3 length + 2 version + 32 random
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;

    if frame.len() < MIN_LEN || frame[0] != HANDSHAKE || frame[5] != SERVER_HELLO {
        return None;
    }

    let mut server_random = [0; TLS_RANDOM_SIZE];
    unsafe {
        copy_nonoverlapping(
            frame.as_ptr().add(SERVER_RANDOM_IDX),
            server_random.as_mut_ptr(),
            TLS_RANDOM_SIZE,
        )
    };

    Some(server_random)
}

/// Copy frame by frame until an appdata frame is authenticated via AES-GCM.
/// Return the decrypted pure data (without header).
///
/// Uses FrameAead: failed verifications do NOT corrupt state (seq unchanged).
///
/// Only used by V3 protocol.
async fn copy_by_frame_until_aead_matches(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    aead: &mut FrameAead,
) -> std::io::Result<Vec<u8>> {
    /// Max time waiting for the first authenticated data frame.
    /// Generous to accommodate browser preconnects and idle SOCKS tunnels.
    const STAGE1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    /// Max bytes forwarded to handshake server before giving up.
    const STAGE1_MAX_BYTES: usize = 256 * 1024;

    let deadline = std::time::Instant::now() + STAGE1_TIMEOUT;
    let mut g_buffer = Vec::new();
    let mut aead_active = false;
    let mut forwarded_bytes: usize = 0;
    // Pre-allocated decrypt buffer — reused across attempts to avoid per-frame allocation.
    let mut decrypt_buf: Vec<u8> = Vec::with_capacity(16384);

    loop {
        // Enforce time budget
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "stage-1: timed out waiting for first authenticated data frame",
            ));
        }
        let buffer = match monoio::time::timeout(
            remaining,
            read_exact_frame_into(&mut read, g_buffer),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "stage-1: timed out waiting for first authenticated data frame",
                ));
            }
        };

        if buffer.len() > TLS_HMAC_HEADER_SIZE && buffer[0] == APPLICATION_DATA {
            let header: [u8; TLS_HEADER_SIZE] =
                buffer[..TLS_HEADER_SIZE].try_into().unwrap();
            let mut tag = [0u8; HMAC_SIZE];
            tag.copy_from_slice(&buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

            // Always try to decrypt — don't latch on first match
            decrypt_buf.clear();
            decrypt_buf.extend_from_slice(&buffer[TLS_HMAC_HEADER_SIZE..]);
            if aead.decrypt_and_advance(&header, &mut decrypt_buf, &tag) {
                aead_active = true;
                // Parse inner framing from decrypted plaintext
                match crate::util::parse_inner_frame(&decrypt_buf) {
                    Some((CMD_DATA, data)) if !data.is_empty() => {
                        return Ok(data.to_vec());
                    }
                    Some((CMD_MUX_SYN, _)) => {
                        // Mux mode: return the entire decrypted inner payload
                        // (including CMD byte) so the caller can parse the SYN.
                        return Ok(decrypt_buf.clone());
                    }
                    Some((CMD_PADDING, _)) | Some((CMD_DATA, _)) => {
                        // Valid AEAD frame but padding/empty — keep reading
                        g_buffer = buffer;
                        continue;
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "malformed inner frame in AEAD-matched packet",
                        ));
                    }
                }
            } else if aead_active {
                // After first AEAD success, all frames must authenticate
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "AEAD verification failed after authentication",
                ));
            }
        } else if aead_active {
            // After authentication, non-ApplicationData frames are unexpected
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected non-ApplicationData frame after authentication",
            ));
        }

        // Pre-authentication: forward to handshake server
        forwarded_bytes += buffer.len();
        if forwarded_bytes > STAGE1_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stage-1: byte budget exceeded waiting for first authenticated frame",
            ));
        }
        let (res, buffer) = write.write_all(buffer).await;
        res?;
        g_buffer = buffer;
    }
}

/// Copy frame by frame verbatim (no modification).
/// Relay handshake server frames to client without altering content or length.
/// This avoids detectable frame length changes (e.g., ServerFinished 53→57).
///
/// Has an idle timeout (30s) to protect against half-dead connections where
/// the handshake server never sends EOF.
///
/// Only used by V3 protocol.
async fn copy_by_frame_verbatim(
    mut read: impl AsyncReadRent,
    mut write: impl AsyncWriteRent,
    stop: &mut Sender<()>,
) -> std::io::Result<()> {
    /// Idle timeout for drain relay: if no frame arrives within this duration,
    /// assume the connection is half-dead and stop. Reduced from 30s to 5s:
    /// the handshake server typically sends NewSessionTickets + alert within
    /// 1-2 RTTs after receiving the client's Finished (~200ms max for remote
    /// servers). 5s is generous enough for any server while minimizing the
    /// delay before data phase starts in edge cases.
    const DRAIN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let mut g_buffer = Vec::new();
    let stop = stop.closed();
    let mut stop = std::pin::pin!(stop);

    loop {
        monoio::select! {
            // this function can be stopped by a channel when reading.
            _ = &mut stop => {
                return Ok(());
            },
            buffer_res = read_exact_frame_into(&mut read, g_buffer) => {
                let buffer = buffer_res?;
                tracing::trace!("h2c frame: type=0x{:02x}, len={}", buffer[0], buffer.len());
                // writing is not cancelable
                let (res, buffer) = write.write_all(buffer).await;
                res?;
                g_buffer = buffer;
            },
            _ = monoio::time::sleep(DRAIN_IDLE_TIMEOUT) => {
                tracing::warn!("drain relay: idle timeout ({DRAIN_IDLE_TIMEOUT:?}), stopping");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_map<K: Into<String>, V: Into<String>>(
        kvs: Vec<(K, V)>,
    ) -> rustc_hash::FxHashMap<String, String> {
        kvs.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
    }

    macro_rules! map {
        [] => {rustc_hash::FxHashMap::<String, String>::default()};
        [$($k:expr => $v:expr),*] => {to_map(vec![$(($k.to_owned(), $v.to_owned())), *])};
        [$($k:expr => $v:expr,)*] => {to_map(vec![$(($k.to_owned(), $v.to_owned())), *])};
    }

    macro_rules! s {
        ($v:expr) => {
            $v.to_string()
        };
    }

    #[test]
    fn parse_tls_addrs() {
        assert_eq!(
            TlsAddrs::try_from("google.com").unwrap(),
            TlsAddrs {
                dispatch: map![],
                fallback: s!("google.com:443"),
                wildcard_sni: Default::default(),
            }
        );
        assert_eq!(
            TlsAddrs::try_from("feishu.cn;cloudflare.com:1.1.1.1:80;google.com").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "feishu.cn" => "feishu.cn:443",
                    "cloudflare.com" => "1.1.1.1:80",
                ],
                fallback: s!("google.com:443"),
                wildcard_sni: Default::default(),
            }
        );
        assert_eq!(
            TlsAddrs::try_from("captive.apple.com;feishu.cn:80").unwrap(),
            TlsAddrs {
                dispatch: map![
                    "captive.apple.com" => "captive.apple.com:443",
                ],
                fallback: s!("feishu.cn:80"),
                wildcard_sni: Default::default(),
            }
        );
    }
}
