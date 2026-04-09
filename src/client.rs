use std::rc::Rc;
use std::sync::Arc;

use anyhow::bail;
use monoio::net::{TcpConnectOpts, TcpStream};
use rand::seq::SliceRandom;
use serde::{de::Visitor, Deserialize};

use crate::{
    boring_tls,
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
        _v3: V3Mode,
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
        })
    }

    /// Serve a raw connection.
    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = bind_with_pretty_error(self.listen_addr.as_ref(), self.fastopen)?;
        let shared = Rc::new(self);
        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    tracing::info!("Accepted a connection from {addr}");
                    let client = shared.clone();
                    mod_tcp_conn(&mut conn, true, shared.nodelay);
                    monoio::spawn(async move {
                        match client.relay(conn).await {
                            Ok(()) => {}
                            Err(e) => tracing::warn!("Relay error for {addr}: {e:#}"),
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

    /// Main relay (V3 protocol).
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
            tracing::warn!("TLS 1.3 not supported, sending fake request and aborting");
            boring_tls::fake_request_and_drain(&mut stream, sni).await?;
            bail!("TLS 1.3 is not supported");
        }

        // Client flight (CCS + encrypted Finished) was already sent by
        // perform_v3_handshake using boring's authentic TLS output.
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
}
