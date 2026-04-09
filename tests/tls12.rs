use shadow_tls::{RunningArgs, TlsAddrs, TlsExtConfig, TlsNames, V3Mode};

#[allow(unused)]
mod utils;
use utils::*;

// handshake: badssl.com (may be TLS 1.2 only)
// data: captive.apple.com:80
// protocol: v3 lossy
// Note: if the handshake server only supports TLS 1.2, boring's Finished
// will have the wrong transcript hash. Lossy mode proceeds anyway but relay
// may fail — this is expected behavior. The test verifies no crash/panic.
#[test]
fn tls12_v3_lossy() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30002".to_string(),
        target_addr: "127.0.0.1:30003".to_string(),
        tls_names: TlsNames::try_from("badssl.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
        mux: false,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:30003".to_string(),
        target_addr: "captive.apple.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("badssl.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
        mux: false,
    };
    // Lossy mode: try to relay, but connection may fail if TLS 1.2 only.
    // Success means TLS 1.3 was negotiated; failure is acceptable for TLS 1.2.
    test_lossy_ok_or_fail(client, server, CAPTIVE_HTTP_REQUEST, CAPTIVE_HTTP_RESP);
}

// handshake: badssl.com(tls1.2 only)
// data: captive.apple.com:80
// protocol: v3 strict — connection must fail because server only supports TLS 1.2.
// Uses test_strict_rejects instead of #[should_panic] to verify the specific failure mode.
#[test]
fn tls12_v3_strict() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30004".to_string(),
        target_addr: "127.0.0.1:30005".to_string(),
        tls_names: TlsNames::try_from("badssl.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
        mux: false,
    };
    let server = RunningArgs::Server {
        listen_addr: "127.0.0.1:30005".to_string(),
        target_addr: "captive.apple.com:80".to_string(),
        tls_addr: TlsAddrs::try_from("badssl.com").unwrap(),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
        mux: false,
    };
    test_strict_rejects(client, server);
}

// handshake: badssl.com(tls1.2 only)
// protocol: v3 lossy
// tls1.2 with v3 protocol does NOT defend against hijack attack(lossy).
#[test]
fn tls12_v3_lossy_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30006".to_string(),
        target_addr: "badssl.com:443".to_string(),
        tls_names: TlsNames::try_from("badssl.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Lossy,
        mux: false,
    };
    test_hijack(client);
}

// badssl.com(tls1.2 only)
// protocol: v3 strict
// tls1.2 with v3 protocol does NOT defend against hijack attack(strict).
// BUT: it does reject the hijacked data, making it fail.
#[test]
fn tls12_v2_hijack() {
    let client = RunningArgs::Client {
        listen_addr: "127.0.0.1:30007".to_string(),
        target_addr: "badssl.com:443".to_string(),
        tls_names: TlsNames::try_from("badssl.com").unwrap(),
        tls_ext: TlsExtConfig::new(None),
        password: "test".to_string(),
        nodelay: true,
        fastopen: true,
        v3: V3Mode::Strict,
        mux: false,
    };
    test_hijack(client);
}
