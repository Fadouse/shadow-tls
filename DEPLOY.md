# ShadowTLS V3 + Shadowsocks 2022 部署指南

本文档介绍如何部署经过反检测优化的 ShadowTLS V3，搭配 Shadowsocks 2022 (ss-2022-aes-128-gcm) 作为实际数据传输协议。

## 架构概览

```
用户应用 (浏览器等)
    |  SOCKS5
sslocal (Shadowsocks 客户端)
    |  Shadowsocks 2022 加密流
shadow-tls client
    |  TLS 伪装 (对外看起来像正常 HTTPS)
    |  内置 padding 防 TLS-in-TLS 检测
  互联网 / GFW
    |
shadow-tls server
    |  还原 Shadowsocks 2022 加密流
ssserver (Shadowsocks 服务端)
    |  解密
目标网站
```

**防检测特性:**
- BoringSSL（Chrome 的 TLS 库）驱动真实 TLS 握手，ClientHello 指纹与 Chrome 完全一致
- 包含 X25519Kyber768 后量子密钥交换（~1200 字节密钥份额），原生 GREASE
- 逐帧 AES-128-GCM AEAD 加密 (HKDF-SHA256 密钥派生，64 位序号)
- 合成 Finished 精确匹配真实 TLS 1.3 大小 (53/69 字节)，防止被动指纹检测
- 随机化填充边界 [5,13] + 5% 尾部填充，消除跨连接 TLS-in-TLS 统计指纹
- 帧合并 (Coalescing): 减少小帧数量，产出更接近真实 HTTPS 的 TLS 记录模式
- NewSessionTickets 逐字转发，不修改帧长度 (绕过 aparecium 类检测)
- **多路复用 (Mux)**: 多个连接共享一条 TLS 隧道，减少握手开销，天然打散流量模式

---

## 1. 准备工作

### 编译 ShadowTLS

```bash
# 需要 Rust nightly
rustup default nightly

git clone <本仓库>
cd shadow-tls
cargo build --release

# 二进制文件位于 target/release/shadow-tls
```

### 安装 Shadowsocks

```bash
# 方式一: cargo 安装
cargo install shadowsocks-rust

# 方式二: 从 GitHub Releases 下载预编译包
# https://github.com/shadowsocks/shadowsocks-rust/releases
```

### 生成密码

```bash
# ShadowTLS 密码 (任意字符串)
STLS_PASSWORD="your-shadowtls-password-here"

# Shadowsocks 2022 密码 (必须是 16 字节的 base64 编码，用于 aes-128)
SS_PASSWORD=$(openssl rand -base64 16)
echo "SS_PASSWORD=$SS_PASSWORD"
```

### 选择握手服务器

选择一个支持 TLS 1.3 的大型网站作为伪装目标，建议：

| 网站 | 说明 |
|------|------|
| `www.google.com` | 稳定，TLS 1.3 |
| `www.microsoft.com` | 稳定，TLS 1.3 |
| `www.apple.com` | 稳定，TLS 1.3 |
| `cloudflare.com` | 稳定，TLS 1.3 |

> **重要**: 必须使用 TLS 1.3 的网站。V3 strict 模式下 TLS 1.2 会失败。

---

## 2. 服务端部署 (VPS)

### 2.1 启动 Shadowsocks 服务端

```bash
ssserver -s "127.0.0.1:8388" \
    -m "2022-blake3-aes-128-gcm" \
    -k "$SS_PASSWORD"
```

> ssserver 仅监听 localhost，不暴露到公网。

### 2.2 启动 ShadowTLS 服务端

```bash
shadow-tls --v3 --strict --mux server \
    --listen "[::]:443" \
    --server "127.0.0.1:8388" \
    --tls "www.google.com" \
    --password "$STLS_PASSWORD"
```

参数说明：
- `--v3 --strict`: 启用 V3 协议严格模式 (仅 TLS 1.3，最安全)
- `--mux`: 启用多路复用 (多连接共享单条 TLS 隧道，减少握手开销)
- `--listen "[::]:443"`: 监听所有接口的 443 端口 (对外伪装 HTTPS)
- `--server "127.0.0.1:8388"`: 内部 Shadowsocks 服务端地址
- `--tls "www.google.com"`: 握手伪装目标
- `--password`: ShadowTLS 认证密码

> **提示**: `--mux` 需客户端和服务端同时启用。不加 `--mux` 时行为与旧版完全兼容。

### 2.3 systemd 服务 (推荐)

**/etc/systemd/system/ssserver.service:**
```ini
[Unit]
Description=Shadowsocks Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -s "127.0.0.1:8388" -m "2022-blake3-aes-128-gcm" -k "YOUR_SS_PASSWORD"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**/etc/systemd/system/shadow-tls.service:**
```ini
[Unit]
Description=ShadowTLS Server
After=network.target ssserver.service
Requires=ssserver.service

[Service]
Type=simple
ExecStart=/usr/local/bin/shadow-tls --v3 --strict --mux server --listen "[::]:443" --server "127.0.0.1:8388" --tls "www.google.com" --password "YOUR_STLS_PASSWORD"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssserver shadow-tls
sudo systemctl status shadow-tls
```

---

## 3. 客户端部署 (本地)

### 3.1 启动 ShadowTLS 客户端

```bash
shadow-tls --v3 --strict --mux client \
    --listen "127.0.0.1:1443" \
    --server "YOUR_VPS_IP:443" \
    --sni "www.google.com" \
    --password "$STLS_PASSWORD"
```

参数说明：
- `--listen "127.0.0.1:1443"`: 本地监听地址 (sslocal 连接到这里)
- `--server "YOUR_VPS_IP:443"`: 服务端 ShadowTLS 地址
- `--sni "www.google.com"`: 必须与服务端 `--tls` 一致
- `--mux`: 启用多路复用 (必须与服务端一致)
- `--password`: 必须与服务端一致

### 3.2 启动 Shadowsocks 客户端

```bash
sslocal -b "127.0.0.1:1080" \
    -s "127.0.0.1:1443" \
    -m "2022-blake3-aes-128-gcm" \
    -k "$SS_PASSWORD"
```

### 3.3 使用代理

```bash
# SOCKS5 代理
curl --socks5 127.0.0.1:1080 https://www.google.com

# 或设置系统代理
export ALL_PROXY=socks5://127.0.0.1:1080
```

---

## 4. 客户端 GUI 配置

### sing-box 配置

```json
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "server": "127.0.0.1",
      "server_port": 1443,
      "method": "2022-blake3-aes-128-gcm",
      "password": "YOUR_SS_PASSWORD"
    }
  ]
}
```

ShadowTLS 客户端仍需独立运行（或使用 sing-box 内置的 shadowtls 支持）。

### sing-box 内置 ShadowTLS (推荐)

sing-box 原生支持 ShadowTLS V3，无需单独运行客户端：

```json
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "server": "YOUR_VPS_IP",
      "server_port": 443,
      "method": "2022-blake3-aes-128-gcm",
      "password": "YOUR_SS_PASSWORD",
      "multiplex": {
        "enabled": false
      },
      "detour": "shadowtls-out"
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls-out",
      "server": "YOUR_VPS_IP",
      "server_port": 443,
      "version": 3,
      "password": "YOUR_STLS_PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "www.google.com"
      }
    }
  ]
}
```

> **注意**: sing-box 的内置 shadowtls 实现可能不包含本项目的 padding 防检测增强。如需完整防检测能力，请使用本仓库编译的二进制。

---

## 5. 多 SNI / 多握手服务器

服务端支持多个握手目标，客户端随机选择：

**服务端:**
```bash
shadow-tls --v3 --strict server \
    --listen "[::]:443" \
    --server "127.0.0.1:8388" \
    --tls "www.google.com;www.apple.com;www.microsoft.com" \
    --password "$STLS_PASSWORD"
```

**客户端:**
```bash
shadow-tls --v3 --strict client \
    --listen "127.0.0.1:1443" \
    --server "YOUR_VPS_IP:443" \
    --sni "www.google.com;www.apple.com;www.microsoft.com" \
    --password "$STLS_PASSWORD"
```

---

## 6. 验证部署

### 基本连通性测试

```bash
# HTTP
curl --socks5 127.0.0.1:1080 http://captive.apple.com/
# 期望输出: <HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>

# HTTPS
curl --socks5-hostname 127.0.0.1:1080 https://www.google.com/ -o /dev/null -w "%{http_code}\n"
# 期望输出: 200
```

### 抓包验证 padding 效果

```bash
# 在服务端抓包，观察 ApplicationData record 长度
sudo tcpdump -i eth0 port 443 -w capture.pcap

# 用 tshark 分析 TLS record 长度
tshark -r capture.pcap -Y "tls.record.content_type == 23" -T fields -e tls.record.length
```

正常情况下，前 5-13 个数据包 (随机化边界) 长度应在 200-1400 范围内随机分布，而非 Shadowsocks 固有的特征长度。启用 `--mux` 后，多个流的数据交错合并，TLS 记录模式更接近真实 HTTP/2 流量。

### 运行 aparecium 检测

```bash
# 如果有 aparecium 工具
go run aparecium/main.go -addr ":10444" -remote "YOUR_VPS_IP:443" -victim shadowtls
# 期望结果: 不再输出 "TLS camouflage connection detected"
```

---

## 7. 安全建议

1. **密码强度**: ShadowTLS 和 Shadowsocks 使用不同的强密码
2. **端口选择**: 使用 443 端口最佳，与正常 HTTPS 流量混合
3. **SNI 选择**: 选择目标地区常访问的大型网站，避免冷门域名
4. **保持更新**: 定期更新 ShadowTLS 获取最新防检测改进
5. **日志级别**: 生产环境不要使用 debug/trace 日志，有性能开销

---

## 8. 故障排查

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| 连接超时 | 握手服务器不可达 | 换一个 `--tls` / `--sni` 目标 |
| 握手失败 | TLS 1.2 only 的握手目标 | 使用支持 TLS 1.3 的网站 |
| 数据传输错误 | 客户端/服务端密码不匹配 | 确认 `--password` 和 SS 密码一致 |
| 连接被重置 | 被主动探测检测 | 检查日志中是否有 "ClientHello verify failed" |

**启用调试日志:**
```bash
RUST_LOG=debug shadow-tls --v3 --strict server ...
```

---

## 快速参考

```bash
# === 服务端 (VPS) ===
ssserver -s 127.0.0.1:8388 -m 2022-blake3-aes-128-gcm -k "$SS_PASSWORD" &
shadow-tls --v3 --strict --mux server --listen [::]:443 --server 127.0.0.1:8388 --tls www.google.com --password "$STLS_PASSWORD" &

# === 客户端 (本地) ===
shadow-tls --v3 --strict --mux client --listen 127.0.0.1:1443 --server VPS_IP:443 --sni www.google.com --password "$STLS_PASSWORD" &
sslocal -b 127.0.0.1:1080 -s 127.0.0.1:1443 -m 2022-blake3-aes-128-gcm -k "$SS_PASSWORD" &

# === 测试 ===
curl --socks5 127.0.0.1:1080 http://captive.apple.com/
```

> **不使用多路复用**: 去掉 `--mux` 即可回退到每连接独立 TLS 隧道模式，与旧版完全兼容。
