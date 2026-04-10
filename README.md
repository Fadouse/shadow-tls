# Shadow TLS (Enhanced Fork)
[![Build Releases](https://github.com/ihciah/shadow-tls/actions/workflows/build-release.yml/badge.svg)](https://github.com/ihciah/shadow-tls/releases) [![Crates.io](https://img.shields.io/crates/v/shadow-tls.svg)](https://crates.io/crates/shadow-tls)

一个**可以使用别人的受信证书**的 TLS 伪装代理。基于 [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) 的增强分支，由 **[Fadouse](https://github.com/Fadouse)** 维护。

A TLS camouflage proxy that uses **trusted certificates from real servers**. Enhanced fork of [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls), maintained by **[Fadouse](https://github.com/Fadouse)**.

---

## Enhancements over Upstream | 相对上游的改进

### BoringSSL 驱动握手 / BoringSSL-Driven Handshake
- 使用 **BoringSSL**（Chrome 的 TLS 库）替代 rustls，ClientHello 指纹与 Chrome 完全一致
- 原生 X25519Kyber768 后量子密钥交换、GREASE (RFC 8701)
- 正确处理 HelloRetryRequest (HRR)，上游在 HRR 时会失败

### 逐帧 AEAD 加密 / Per-Frame AEAD Encryption
- 将上游的 HMAC-SHA256 帧认证替换为 **AES-128-GCM AEAD** 逐帧加密
- HKDF-SHA256 密钥派生，方向独立密钥 (c2s/s2c)，64 位序号防重放
- 内层 payload 加密（机密性 + 完整性），而非仅认证

### 完美前向保密 / Perfect Forward Secrecy (PFS)
- 握手后通过已认证 AEAD 通道进行 **X25519 临时密钥交换**
- 非 Mux 模式 **0-RTT**：客户端发送公钥后立即开始数据传输，服务端异步响应
- Mux 模式 1-RTT：开销在所有复用连接间分摊
- 即使 password 未来泄露，历史流量无法解密

### 反检测强化 / Anti-Detection Hardening
- 合成 Finished 精确匹配真实 TLS 1.3 大小（53/69 字节），防被动指纹检测
- **方向感知 HTTP/2 流量模拟**：C2S/S2C 独立填充配置，匹配真实浏览器流量不对称性
- **握手后前导记录**：1–3 个填充记录模拟 HTTP/2 SETTINGS 交换，消除握手→数据过渡指纹
- NewSessionTickets 逐字转发，不修改帧长度（绕过 aparecium 类检测）
- 受 [restls](https://github.com/3andne/restls) 流量脚本思路启发

### 多路复用 / Multiplexing (Mux)
- 多连接共享单条 TLS 隧道，后续连接 **0 额外 RTT**
- 流量模式天然匹配 HTTP/2 多路复用，更隐蔽
- Session 生命周期管理：死 session 自动检测清理，防止连接卡死
- 客户端 AuthPending 阶段自动排空握手残留帧

### TLS Record 合规 / TLS Record Compliance
- 所有帧严格 ≤ 16384 字节标准 TLS fragment 上限
- 防止网络中间设备截断超大 record 导致的 GCM 验证失败
- 高吞吐量场景（speedtest 826 Mbps）验证通过

### io_uring 安全 / io_uring Safety
- 消除 `select!` 中取消 in-flight io_uring 读操作的 buffer 生命周期风险
- 先完成 read 再检查信号，而非竞争取消

### 性能优化 / Performance
- TCP Fast Open (`--fastopen`)：减少 1 RTT 连接延迟
- Mux + TFO：首次连接 ~1 RTT，后续连接 0 RTT
- 帧合并 (Coalescing)：减少小帧数量，更接近真实 HTTPS

---

## Quick Start | 快速开始

### 服务端 / Server
```bash
# Shadowsocks 2022
ssserver -s 127.0.0.1:8388 -m 2022-blake3-aes-128-gcm -k "$SS_PASSWORD" &

# ShadowTLS Server
shadow-tls --v3 --strict --mux --fastopen server \
    --listen "[::]:443" \
    --server "127.0.0.1:8388" \
    --tls "objects.githubusercontent.com" \
    --password "$STLS_PASSWORD"
```

### 客户端 / Client
```bash
# ShadowTLS Client
shadow-tls --v3 --strict --mux --fastopen client \
    --listen "127.0.0.1:1443" \
    --server "YOUR_VPS_IP:443" \
    --sni "objects.githubusercontent.com" \
    --password "$STLS_PASSWORD"

# Shadowsocks Client
sslocal -b "127.0.0.1:1080" \
    -s "127.0.0.1:1443" \
    -m "2022-blake3-aes-128-gcm" \
    -k "$SS_PASSWORD"

# Test
curl --socks5 127.0.0.1:1080 http://captive.apple.com/
```

### 关键参数 / Key Flags

| 参数 | 说明 |
|------|------|
| `--v3 --strict` | V3 协议严格模式（仅 TLS 1.3） |
| `--mux` | 多路复用（客户端服务端需同时启用） |
| `--fastopen` | TCP Fast Open（需内核 `net.ipv4.tcp_fastopen >= 3`） |

> 去掉 `--mux` 回退到每连接独立 TLS 隧道模式，与上游完全兼容。

---

## Documentation | 文档

- **部署指南**: [DEPLOY.md](./DEPLOY.md)
- **V3 协议设计**: [English](./docs/protocol-v3-en.md) | [中文](./docs/protocol-v3-zh.md)
- **协议横向对比**: [protocol-comparison.md](./docs/protocol-comparison.md)
- Legacy V1/V2 (不再维护): [English](./docs/protocol-en.md) | [中文](./docs/protocol-zh.md)

## How it Works

Client side: performs a real TLS handshake using BoringSSL (Chrome's TLS library) for an authentic browser fingerprint. The server relays the handshake to a real TLS server, authenticates the client via a signed SessionID, and switches to encrypted data relay. A post-handshake X25519 ephemeral key exchange provides perfect forward secrecy (0-RTT for non-mux, 1-RTT for mux). All data is protected with per-frame AES-128-GCM. With mux enabled, multiple connections share a single TLS tunnel for zero-RTT subsequent connections.

## Note
This project relies on [Monoio](https://github.com/bytedance/monoio) (io_uring async runtime). It does not support Windows natively. Use environment variable `MONOIO_FORCE_LEGACY_DRIVER=1` to use epoll instead of io_uring.

你可能需要修改某些系统设置来让它工作，[参考这里](https://github.com/bytedance/monoio/blob/master/docs/en/memlock.md)。如果它不起作用，您可以添加环境变量 `MONOIO_FORCE_LEGACY_DRIVER=1` 以使用 epoll 而不是 io_uring。

## Credits

- Original project by [ihciah](https://github.com/ihciah/shadow-tls)
- Enhanced fork maintained by [Fadouse](https://github.com/Fadouse)
- BoringSSL integration, AEAD encryption, anti-detection hardening, multiplexing, TLS record compliance, and io_uring safety improvements by Fadouse

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fihciah%2Fshadow-tls?ref=badge_large)
