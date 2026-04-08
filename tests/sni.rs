use std::io::{Read, Write};
use std::time::Duration;

use boring::ssl::{SslConnector, SslMethod, SslVersion};
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::TcpStream,
};
use shadow_tls::{RunningArgs, TlsAddrs, V3Mode};

#[allow(unused)]
mod utils;
use utils::{CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP};

/// Build a simple boring TLS connector for testing.
fn build_test_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    builder.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    builder.build()
}

/// Drive a boring SslStream handshake over an async monoio TcpStream,
/// then write/read application data through the encrypted channel.
///
/// This is a simplified version of the SyncBridge pattern used in boring_tls.rs.
struct SyncBridge {
    read_buf: std::collections::VecDeque<u8>,
    write_buf: Vec<u8>,
}

impl SyncBridge {
    fn new() -> Self {
        Self {
            read_buf: std::collections::VecDeque::with_capacity(16384),
            write_buf: Vec::with_capacity(4096),
        }
    }

    fn feed_read(&mut self, data: &[u8]) {
        self.read_buf.extend(data);
    }

    fn take_write_buf(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.write_buf, Vec::with_capacity(4096))
    }

    fn has_pending_write(&self) -> bool {
        !self.write_buf.is_empty()
    }
}

impl Read for SyncBridge {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_buf.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "need more data"));
        }
        let (front, _) = self.read_buf.as_slices();
        let n = buf.len().min(front.len());
        buf[..n].copy_from_slice(&front[..n]);
        self.read_buf.drain(..n);
        Ok(n)
    }
}

impl Write for SyncBridge {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[monoio::test(enable_timer = true)]
async fn sni() {
    let connector = build_test_connector();

    // run server
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:32000".to_string(),
        target_addr: "bing.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("captive.apple.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
    };
    server.build().expect("build server failed").start(1);
    monoio::time::sleep(Duration::from_secs(1)).await;

    // Connect TCP
    let mut tcp = TcpStream::connect("127.0.0.1:32000").await.unwrap();

    // Perform TLS handshake via SyncBridge
    let bridge = SyncBridge::new();
    let ssl = connector.configure().unwrap().into_ssl("captive.apple.com").unwrap();
    let mut builder = boring::ssl::SslStreamBuilder::new(ssl, bridge);
    builder.set_connect_state();

    let mut mid = match builder.handshake() {
        Ok(_) => unreachable!("handshake should not complete immediately"),
        Err(boring::ssl::HandshakeError::WouldBlock(mid)) => mid,
        Err(e) => panic!("handshake setup error: {e}"),
    };

    let mut stream = loop {
        // Flush writes
        let bridge = mid.get_mut();
        if bridge.has_pending_write() {
            let data = bridge.take_write_buf();
            let (res, _) = tcp.write_all(data).await;
            res.unwrap();
        }

        // Read from network
        let buf = vec![0u8; 16384];
        let (res, buf) = tcp.read(buf).await;
        let n = res.unwrap();
        assert!(n > 0, "unexpected EOF during handshake");
        mid.get_mut().feed_read(&buf[..n]);

        // Continue handshake
        mid = match mid.handshake() {
            Ok(stream) => break stream,
            Err(boring::ssl::HandshakeError::WouldBlock(m)) => m,
            Err(e) => panic!("handshake failed: {e}"),
        };
    };

    // Flush any remaining handshake writes
    let bridge = stream.get_mut();
    if bridge.has_pending_write() {
        let data = bridge.take_write_buf();
        let (res, _) = tcp.write_all(data).await;
        res.unwrap();
    }

    // Write HTTP request through TLS
    stream.write_all(CAPTIVE_HTTP_REQUEST).unwrap();
    let bridge = stream.get_mut();
    let data = bridge.take_write_buf();
    let (res, _) = tcp.write_all(data).await;
    res.unwrap();

    // Read response through TLS
    let mut response = Vec::new();
    loop {
        let buf = vec![0u8; 16384];
        let (res, buf) = tcp.read(buf).await;
        let n = res.unwrap();
        if n == 0 {
            break;
        }
        stream.get_mut().feed_read(&buf[..n]);
        let mut tmp = vec![0u8; 16384];
        match stream.read(&mut tmp) {
            Ok(n) => response.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => panic!("TLS read error: {e}"),
        }
    }

    assert_eq!(&response[..CAPTIVE_HTTP_RESP.len()], CAPTIVE_HTTP_RESP);
}
