use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::{TcpConnectOpts, TcpStream};
use rand::seq::SliceRandom;
use serde::{de::Visitor, Deserialize};

use crate::{
    boring_tls,
    mux,
    util::{
        bind_with_pretty_error, mod_tcp_conn, resolve, verified_relay, FrameAead,
        V3Mode,
    },
};

/// ShadowTlsClient.
#[derive(Clone)]
pub struct ShadowTlsClient {
    listen_addr: Arc<String>,
    target_addr: Arc<String>,
    ssl_connector: Arc<boring::ssl::SslConnector>,
    tls_names: Arc<TlsNames>,
    password: Arc<String>,
    nodelay: bool,
    fastopen: bool,
    v3: V3Mode,
    mux: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TlsNames(Vec<String>);

impl TlsNames {
    #[inline]
    pub fn random_choose(&self) -> &str {
        self.0.choose(&mut rand::thread_rng()).unwrap()
    }
}

impl TryFrom<&str> for TlsNames {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v: Vec<String> = value
            .trim()
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if v.is_empty() {
            return Err(anyhow::anyhow!("empty tls names"));
        }
        Ok(Self(v))
    }
}

struct TlsNamesVisitor;

impl<'de> Visitor<'de> for TlsNamesVisitor {
    type Value = TlsNames;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a semicolon seperated list of domains and ip addresses")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match Self::Value::try_from(v) {
            Err(e) => Err(E::custom(e.to_string())),
            Ok(u) => Ok(u),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self.visit_str(&v)
    }
}

impl<'de> Deserialize<'de> for TlsNames {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(TlsNamesVisitor)
    }
}

impl std::fmt::Display for TlsNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Default, Debug)]
pub struct TlsExtConfig {
    alpn: Option<Vec<Vec<u8>>>,
}

impl TlsExtConfig {
    #[allow(unused)]
    #[inline]
    pub fn new(alpn: Option<Vec<Vec<u8>>>) -> TlsExtConfig {
        TlsExtConfig { alpn }
    }
}

impl From<Option<Vec<String>>> for TlsExtConfig {
    fn from(maybe_alpns: Option<Vec<String>>) -> Self {
        Self {
            alpn: maybe_alpns.map(|alpns| alpns.into_iter().map(Into::into).collect()),
        }
    }
}

impl std::fmt::Display for TlsExtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.alpn.as_ref() {
            Some(alpns) => {
                write!(f, "ALPN(Some(")?;
                for alpn in alpns.iter() {
                    write!(f, "{},", String::from_utf8_lossy(alpn))?;
                }
                write!(f, "))")?;
            }
            None => {
                write!(f, "ALPN(None)")?;
            }
        }
        Ok(())
    }
}

impl ShadowTlsClient {
    /// Create new ShadowTlsClient.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen_addr: String,
        target_addr: String,
        tls_names: TlsNames,
        tls_ext_config: TlsExtConfig,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
        mux: bool,
    ) -> anyhow::Result<Self> {
        let alpn = tls_ext_config.alpn.unwrap_or_default();
        let ssl_connector = boring_tls::build_chrome_ssl_connector(&alpn)
            .map_err(|e| anyhow::anyhow!("Failed to build SSL connector: {e}"))?;

        Ok(Self {
            listen_addr: Arc::new(listen_addr),
            target_addr: Arc::new(target_addr),
            ssl_connector: Arc::new(ssl_connector),
            tls_names: Arc::new(tls_names),
            password: Arc::new(password),
            nodelay,
            fastopen,
            v3,
            mux,
        })
    }

    /// Serve a raw connection.
    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = bind_with_pretty_error(self.listen_addr.as_ref(), self.fastopen)?;
        let shared = Rc::new(self);
        // Mux pool: shared across all connections on this thread.
        // Each monoio thread gets its own pool (Rc, not Arc).
        let mux_pool: Rc<mux::MuxPool> = Rc::new(mux::MuxPool::new(4));

        // Prewarm: establish a mux session before the first connection arrives.
        // Periodic maintenance replaces dead/evicted sessions in the background.
        if shared.mux {
            let client = shared.clone();
            let pool = mux_pool.clone();
            monoio::spawn(async move {
                match client.get_or_create_mux_session(&pool).await {
                    Ok(_) => tracing::info!("Mux: prewarmed session ready"),
                    Err(e) => tracing::warn!("Mux: prewarm failed: {e:#}"),
                }
                loop {
                    monoio::time::sleep(Duration::from_secs(5)).await;
                    pool.cleanup();
                    if pool.get_session().is_none() {
                        let _ = client.get_or_create_mux_session(&pool).await;
                    }
                }
            });
        }

        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let client = shared.clone();
                    let pool = mux_pool.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        let result = if client.mux {
                            client.relay_mux(conn, &pool).await
                        } else {
                            client.relay(conn).await
                        };
                        if let Err(e) = result {
                            tracing::warn!("Relay error for {addr}: {e:#}");
                        }
                        tracing::info!("Relay for {addr} finished");
                    });
                }
                Err(e) => {
                    tracing::error!("Accept failed: {e}");
                }
            }
        }
    }

    /// Main relay (V3 protocol, non-mux: one TLS connection per client connection).
    async fn relay(&self, in_stream: TcpStream) -> anyhow::Result<()> {
        let addr = resolve(&self.target_addr).await?;
        let mut stream = TcpStream::connect_addr_with_config(
            addr,
            &TcpConnectOpts::default().tcp_fast_open(self.fastopen),
        )
        .await?;
        mod_tcp_conn(&mut stream, true, self.nodelay);
        tracing::debug!("tcp connected, start handshaking");

        let sni = self.tls_names.random_choose();
        let (server_random, tls13) =
            boring_tls::perform_v3_handshake(&mut stream, &self.ssl_connector, sni, &self.password)
                .await?;

        if !tls13 {
            let mode_name = match self.v3 {
                V3Mode::Strict => "strict",
                V3Mode::Lossy => "lossy",
                V3Mode::Disabled => "disabled",
            };
            tracing::warn!("TLS 1.3 not supported ({mode_name} mode), sending fake request and aborting");
            boring_tls::fake_request_and_drain(&mut stream, sni).await?;
            bail!("TLS 1.3 is not supported ({mode_name} mode)");
        }

        tracing::debug!("Authorized, ServerRandom extracted: {server_random:?}");
        let frame_aead_c2s = FrameAead::new(&self.password, &server_random, b"c2s");
        let frame_aead_s2c = FrameAead::new(&self.password, &server_random, b"s2c");

        verified_relay(
            in_stream,
            stream,
            frame_aead_c2s,
            frame_aead_s2c,
            !tls13,
            true,
        )
        .await;
        Ok(())
    }

    /// Obtain a mux session and its buffer pool: reuse existing or create new.
    /// Only one task creates a session at a time; others poll and wait.
    async fn get_or_create_mux_session(
        &self,
        pool: &mux::MuxPool,
    ) -> anyhow::Result<(Rc<mux::MuxSession>, Rc<mux::BufPool>)> {
        const WAIT_TIMEOUT: Duration = Duration::from_secs(15);
        const POLL_INTERVAL: Duration = Duration::from_millis(100);

        let deadline = Instant::now() + WAIT_TIMEOUT;

        loop {
            pool.cleanup();

            if let Some(s) = pool.get_session() {
                return Ok(s);
            }

            if Instant::now() >= deadline {
                anyhow::bail!("mux: timed out waiting for session");
            }

            if !pool.try_lock_create() {
                monoio::time::sleep(POLL_INTERVAL).await;
                continue;
            }

            // Double-check after acquiring lock
            if let Some(s) = pool.get_session() {
                pool.unlock_create();
                return Ok(s);
            }

            let result = self.create_mux_session(pool).await;
            pool.unlock_create();
            match result {
                Ok(s) => return Ok(s),
                Err(e) => {
                    tracing::warn!("Mux: session creation failed: {e:#}");
                    // Propagate non-transient errors immediately instead of
                    // retrying until the deadline.
                    let msg = format!("{e:#}");
                    if msg.contains("TLS 1.3 is not supported") {
                        return Err(e);
                    }
                    monoio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Create a single mux session (TLS handshake + session setup).
    async fn create_mux_session(
        &self,
        pool: &mux::MuxPool,
    ) -> anyhow::Result<(Rc<mux::MuxSession>, Rc<mux::BufPool>)> {
        let addr = resolve(&self.target_addr).await?;
        let mut stream = TcpStream::connect_addr_with_config(
            addr,
            &TcpConnectOpts::default().tcp_fast_open(self.fastopen),
        )
        .await?;
        mod_tcp_conn(&mut stream, true, self.nodelay);

        let sni = self.tls_names.random_choose();
        let (server_random, tls13) = boring_tls::perform_v3_handshake(
            &mut stream,
            &self.ssl_connector,
            sni,
            &self.password,
        )
        .await?;

        if !tls13 {
            boring_tls::fake_request_and_drain(&mut stream, sni).await?;
            anyhow::bail!("TLS 1.3 is not supported (mux requires TLS 1.3)");
        }

        tracing::info!("Mux: new TLS session established");
        let aead_c2s = FrameAead::new(&self.password, &server_random, b"c2s");
        let aead_s2c = FrameAead::new(&self.password, &server_random, b"s2c");
        let (s, bp) = mux::create_client_session(stream, aead_c2s, aead_s2c);
        pool.add_session(s.clone(), bp.clone());
        Ok((s, bp))
    }

    /// Mux relay: reuse an existing TLS connection or create a new one.
    /// Multiple client connections share a single TLS session via stream multiplexing.
    async fn relay_mux(&self, in_stream: TcpStream, pool: &mux::MuxPool) -> anyhow::Result<()> {
        let (session, buf_pool) = self.get_or_create_mux_session(pool).await?;

        let (stream_id, mut data_rx) = session.open_stream();
        tracing::debug!("Mux stream {stream_id} opened");

        let (in_read, in_write) = in_stream.into_split();

        let session_for_write = session.clone();
        let pool_for_write = buf_pool.clone();
        let sid = stream_id;
        let _ = monoio::join!(
            // Client app -> mux stream (use pool for allocation)
            async {
                let mut in_read = in_read;
                let mut buf = vec![0u8; crate::mux::MAX_MUX_DATA];
                loop {
                    let (res, b) = in_read.read(buf).await;
                    buf = b;
                    match res {
                        Ok(0) | Err(_) => {
                            session_for_write.close_stream(sid);
                            return;
                        }
                        Ok(n) => {
                            if !session_for_write.send_data(sid, buf_pool.take(&buf[..n])) {
                                return;
                            }
                        }
                    }
                }
            },
            // Mux stream -> client app (recycle buffers after write)
            async {
                let mut in_write = in_write;
                while let Some(data) = data_rx.recv().await {
                    let (res, written_buf) = in_write.write_all(data).await;
                    pool_for_write.put(written_buf);
                    if res.is_err() {
                        return;
                    }
                }
                let _ = in_write.shutdown().await;
            }
        );

        pool.cleanup();
        Ok(())
    }
}
