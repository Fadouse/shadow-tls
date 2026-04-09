---
title: ShadowTLS V3 协议设计
date: 2023-02-06 11:00:00
updated: 2026-04-09 00:00:00
author: ihciah
---

# 版本演进

2022 年 8 月实现了第一版 ShadowTLS。V1 通过代理 TLS 握手来逃避流量判别，假设中间人只观察握手流量。

V2 添加了 challenge-response 客户端认证和 ApplicationData 封装。配合多 SNI 支持，可作为 SNI Proxy 运行，看起来完全不像偷渡数据的代理。

但 V2 仍假设中间人不做流量劫持（参考 [issue #30](https://github.com/ihciah/shadow-tls/issues/30)）。[restls](https://github.com/3andne/restls)（[issue #66](https://github.com/ihciah/shadow-tls/issues/66)）提供了隐蔽服务端身份验证的创新思路。

V3 应对所有已知攻击向量：流量特征检测、主动探测和流量劫持。

# V3 协议目标

1. 防御流量特征检测、主动探测和流量劫持。
2. 易于正确实现。
3. 弱感知 TLS 协议细节——无需 Hack TLS 库或自行实现 TLS。
4. 保持简单：仅作为 TCP 流代理。

## TLS 版本支持

V3 **要求握手服务器支持 TLS 1.3**。检测方法：`openssl s_client -tls1_3 -connect example.com:443`。

BoringSSL 无法产生有效的 TLS 1.2 Finished（patched session_id 导致不同的转录哈希），因此所有模式在 TLS 1.2 时均终止连接。客户端发送伪造加密请求并排空服务器响应，完成一个看似正常的流量模式后关闭。

# 握手流程

## Session ID 认证

客户端构造包含自定义 32 字节 SessionID 的 ClientHello：

```
SessionID (32 字节) = [28 字节随机值] [4 字节 HMAC-SHA1]
```

HMAC 计算范围为 ClientHello 记录体（不含 5 字节 TLS 头），计算时 SessionID 末 4 字节填零。HMAC 密钥为共享密码。

服务端验证此 HMAC 以认证客户端。验证失败则退化为与握手服务器的纯 TCP 中继（对主动探测者而言不可区分于真实 TLS 反向代理）。

## BoringSSL 驱动的握手

客户端使用 **BoringSSL**（Chrome 的 TLS 库）驱动真实 TLS 握手，产生原生 TLS 记录：

### 正常流程（TLS 1.3）

```
客户端 (boring)           Shadow-TLS 服务端         握手服务器
     |                         |                         |
     |--- ClientHello -------->|--- ClientHello -------->|
     |   (session_id 已补丁)   |   (HMAC 已验证)         |
     |                         |                         |
     |<-- ServerHello ---------|<-- ServerHello ----------|
     |   (session_id 已恢复)   |   (ServerRandom 已保存) |
     |                         |                         |
     |   (boring 处理服务端飞行，产生 CCS)                |
     |                         |                         |
     |--- CCS + 伪 Finished -->|--- 转发 ---------------->|
     |   (随机 AppData)        |                         |
     |                         |                         |
     |=== AEAD 数据阶段 ======>|===> 数据服务器 =========>|
```

1. **ClientHello**：boring 生成；保存原始 session_id，补丁 HMAC 后发送。
2. **ServerHello**：恢复原始 session_id（boring 验证回显），提取 ServerRandom，喂给 boring。
3. **客户端飞行**：boring 写出 CCS，尝试解密服务端加密扩展，BAD_DECRYPT 失败（预期——不同转录哈希）。追加随机 ApplicationData 作为合成 Finished。
4. **数据阶段**：双方从 ServerRandom 派生 AEAD 密钥，开始认证中继。

### HelloRetryRequest（HRR）

握手服务器发送 HelloRetryRequest 时（通过 RFC 8446 §4.1.3 定义的固定合成 ServerRandom 检测），客户端和服务端均需处理：

**客户端侧：**
1. 将 HRR 喂给 boring → boring 产生新的 ClientHello（CH2）。
2. CH2 必须携带与 CH1 **相同**的 session_id（RFC 8446 §4.1.2）。用 CH1 的补丁值覆盖 CH2 的 session_id。
3. 保存 boring 为 CH2 生成的新原始 session_id，用于恢复真实 ServerHello。
4. 读取真实 ServerHello，提取真实 ServerRandom。

**服务端侧：**
1. 通过合成 ServerRandom 检测 HRR。
2. 将重试 ClientHello 从 shadow-tls 客户端中继到握手服务器。
3. 读取真实 ServerHello，提取真实 ServerRandom 用于 AEAD 密钥派生。

双重 HRR 作为协议错误拒绝。

### Alert 竞态安全性

握手服务器因错误的 Finished 发送致命 alert，但需要完整网络往返（50–200 ms）。shadow-tls 服务器的 AEAD 匹配在本地微秒级完成（AEAD 帧紧跟客户端飞行），握手中继在 alert 到达前即已终止。AuthPending 阶段所有来自握手服务器的 alert 均被静默丢弃。

BoringSSL 上下文中禁用证书验证——仅用于产生真实记录，不做安全验证。

# 数据封装

## 密钥派生

握手完成后，双方通过 **HKDF-SHA256** 派生方向独立的密钥：

```
okm = HKDF-SHA256(IKM=password, salt=ServerRandom, info=direction)  →  28 字节
```

`direction` 为 `"c2s"` 或 `"s2c"`。每 28 字节输出拆分为：
- **AES 密钥**（前 16 字节）：AES-128-GCM 加密密钥
- **基础 nonce**（后 12 字节）：GCM nonce 构造基础值

ServerRandom 作为 HKDF salt，将密钥绑定到具体 TLS 会话，防止跨会话重放。

## 逐帧 AEAD（AES-128-GCM）

每个 ApplicationData 帧独立加密认证：

```
nonce       = base_nonce XOR (seq_be64 右对齐至 12 字节)
ciphertext || tag = AES-128-GCM(key, nonce, AAD=tls_header, plaintext)
```

线上格式：

```
[5B TLS 记录头] [16B GCM tag] [加密: 1B CMD | 2B DATA_LEN | 数据 | 填充]
```

- **序号**：64 位大端序，从 0 开始，每方向每帧递增，异或到 base_nonce 末 8 字节。
- **AAD**：5 字节 TLS 记录头，防止头部篡改。
- **严格序号策略**：认证后任何 GCM 失败 = 立即断连。
- **AuthPending 限制**：首个有效 GCM 帧前，不匹配帧静默丢弃（上限 64 KiB / 10 秒）。

## 内层帧（反 TLS-in-TLS）

每个加密 payload 携带 3 字节内层头，防止内层协议统计指纹：

```
[CMD : 1B] [DATA_LEN : 2B 大端序] [用户数据 : DATA_LEN 字节] [填充]
```

- `CMD = 0x01`（DATA）：真实用户数据 + 可选填充。
- `CMD = 0x00`（PADDING）：纯填充帧，接收方整体丢弃。

### 填充策略

**阶段 1 — 初始塑形（第 0–7 包）：**

| 包序号 | 目标 payload 范围 | 模拟流量类型 |
|--------|------------------|-------------|
| 0 | 200 – 600 B | HTTP 请求 / 小型响应 |
| 1 | 800 – 1400 B（5%: 14000 – 16000） | HTTP 响应头 / 大文件 |
| 2–7 | 500 – 1400 B（5%: 14000 – 16000） | HTTP 响应体 / 大文件 |

**阶段 2 — 尾部填充（第 8 包及以后）：**

每帧 **2% 概率**追加 0–256 字节随机填充，消除第 8 包边界处的统计突变。

# 安全特性

| 攻击类型 | 防御机制 |
|---------|---------|
| 流量特征检测 | BoringSSL 产生 Chrome 原生 ClientHello（JA3/JA4、X25519Kyber768、GREASE） |
| 主动探测 | session_id HMAC 失败 → 透明 SNI 代理退化 |
| 流量劫持（数据） | 逐帧 AES-128-GCM，方向独立密钥 |
| 跨会话重放 | HKDF salt = ServerRandom（每会话唯一） |
| 会话内重放/乱序 | GCM nonce 中 64 位序号 |
| 头部篡改 | TLS 记录头作为 GCM AAD |
| TLS-in-TLS 指纹 | 两阶段填充，模拟真实流量分布 |
| 内层 payload 检测 | AES-128-GCM 加密（机密性 + 完整性） |

# 实现指南

## TLS 指纹

客户端**必须**产生 Chrome 原生 ClientHello。本实现通过 `boring` crate 使用 **BoringSSL**：

- **GREASE**：原生 BoringSSL（RFC 8701）
- **密码套件**：Chrome 顺序（TLS 1.3 + TLS 1.2 ECDHE 套件）
- **密钥交换**：X25519Kyber768Draft00（后量子）、X25519、P-256、P-384
- **ALPN**：`h2`、`http/1.1`
- **签名算法**：Chrome 顺序
- **支持版本**：TLS 1.2、TLS 1.3

## 客户端实现

**Stage 1 — 握手：**
1. BoringSSL 生成 ClientHello，保存原始 session_id，补丁 HMAC 后发送。
2. 读取 ServerHello（检测到合成随机值则处理 HRR），恢复 session_id，提取 ServerRandom。
3. 通过 BoringSSL 继续握手直到产生客户端飞行。
4. TLS 1.3：追加随机 ApplicationData 作为合成 Finished。
5. 发送客户端飞行。TLS 1.2：发送伪造请求后终止。

**Stage 2 — 数据中继（无需 TLS 库）：**
1. 通过 HKDF-SHA256(password, ServerRandom, direction) 派生 `key_c2s` 和 `key_s2c`。
2. **读取服务端数据**：解析 ApplicationData，提取 16B GCM tag，用 `key_s2c` 解密。解析内层帧，转发用户数据，丢弃填充。
3. **写入服务端数据**：构建内层帧（CMD + DATA_LEN + 数据 + 填充），用 `key_c2s` 加密，封装为 ApplicationData。

## 服务端实现

**Stage 1 — 握手中继（无需 TLS 库）：**
1. 读取 ClientHello，验证 session_id HMAC。失败则纯 TCP 中继（SNI 代理退化）。
2. 转发 ClientHello 至握手服务器。读取 ServerHello，提取 ServerRandom。检测到 HRR 则中继重试 ClientHello 并读取真实 ServerHello。
3. 双向中继直到首个 AEAD 认证的 ApplicationData 帧从客户端到达。
4. AEAD 匹配：关闭握手服务器连接，通知逐帧中继停止。

**Stage 2 — 数据中继：**
1. 通过 HKDF-SHA256(password, ServerRandom, direction) 派生 `key_c2s` 和 `key_s2c`。
2. **客户端 → 数据服务器**：用 `key_c2s` 解密，解析内层帧，转发用户数据。
3. **数据服务器 → 客户端**：用 `key_s2c` 加密，构建内层帧，应用填充。
