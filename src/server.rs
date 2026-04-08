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

impl TryFrom<&str> for TlsAddrs {
    type Error = anyhow::Error;

    fn try_from(arg: &str) -> Result<Self, Self::Error> {
        let mut rev_parts = arg.split(';').rev();
        let fallback = rev_parts
            .next()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) })
            .ok_or_else(|| anyhow::anyhow!("empty server addrs"))?;
        let fallback = if !fallback.contains(':') {
            format!("{fallback}:443")
        } else {
            fallback.to_string()
        };

        let mut dispatch = rustc_hash::FxHashMap::default();
        for p in rev_parts {
            let mut p = p.trim().split(':').rev();
            let mut port = Cow::<'static, str>::Borrowed("443");
            let maybe_port = p
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty part found in server addrs"))?;
            let host = if maybe_port.parse::<u16>().is_ok() {
                // there is a port at the end
                port = maybe_port.into();
                p.next()
                    .ok_or_else(|| anyhow::anyhow!("no host found in server addrs part"))?
            } else {
                maybe_port
            };
            let key = match p.next() {
                Some(key) => key,
                None => host,
            };
            if p.next().is_some() {
                bail!("unrecognized server addrs part");
            }
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
    ) -> Self {
        Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            tls_addr: Arc::new(tls_addr),
            password: Arc::new(password),
            nodelay,
            fastopen,
            v3,
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
        let server_random = match extract_server_random(&first_server_frame) {
            Some(sr) => sr,
            None => {
                // we cannot extract server random, bidirectional copy and return
                tracing::warn!("ServerRandom extract failed, will copy bidirectional");
                copy_bidirectional(in_stream, handshake_stream).await;
                return Ok(());
            }
        };
        tracing::debug!("Client authenticated. ServerRandom extracted: {server_random:?}");

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
            let (mut stop_tx, mut stop_rx) = local_sync::oneshot::channel::<()>();
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
            // After verbatim relay ends (handshake server EOF), close the stop channel
            // to let any pending safety logic terminate.
            stop_rx.close();
            maybe_pure?
        };
        tracing::debug!("handshake relay finished");

        // early drop useless resources
        drop(first_server_frame);

        // stage 2.2: copy ShadowTLS Client -> Data Server
        // stage 2.3: copy Data Server -> ShadowTLS Client
        let mut data_stream = TcpStream::connect_addr(resolve(&self.target_addr).await?).await?;
        mod_tcp_conn(&mut data_stream, true, self.nodelay);
        let (res, _) = data_stream.write_all(pure_data).await;
        res?;
        verified_relay(
            data_stream,
            unsafe { c_read.reunite(c_write).unwrap_unchecked() },
            frame_aead_s2c,
            frame_aead_c2s,
            !use_tls13,
            false, // server: already authenticated client via SessionID + first HMAC frame
        )
        .await;
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
    let mut g_buffer = Vec::new();
    let mut aead_matched = false;

    loop {
        let buffer = read_exact_frame_into(&mut read, g_buffer).await?;
        if buffer.len() > TLS_HMAC_HEADER_SIZE && buffer[0] == APPLICATION_DATA {
            let header: [u8; TLS_HEADER_SIZE] =
                buffer[..TLS_HEADER_SIZE].try_into().unwrap();
            let mut tag = [0u8; HMAC_SIZE];
            tag.copy_from_slice(&buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

            if !aead_matched {
                // Decrypt in-place: copy ciphertext to mutable buffer
                let mut payload = buffer[TLS_HMAC_HEADER_SIZE..].to_vec();
                aead_matched = aead.decrypt_and_advance(&header, &mut payload, &tag);

                if aead_matched {
                    // Parse inner framing from decrypted plaintext
                    match crate::util::parse_inner_frame(&payload) {
                        Some((CMD_DATA, data)) if !data.is_empty() => {
                            return Ok(data.to_vec());
                        }
                        Some((CMD_PADDING, _)) | Some((CMD_DATA, _)) => {
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
                }
            }
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
    /// assume the connection is half-dead and stop.
    const DRAIN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
