---
title: ShadowTLS V3 协议设计
date: 2023-02-06 11:00:00
updated: 2026-04-10 00:00:00
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
3. **客户端飞行**：boring 写出 CCS，尝试解密服务端加密扩展，BAD_DECRYPT 失败（预期——不同转录哈希）。追加精确匹配真实 TLS 1.3 加密 Finished 大小（SHA-256 套件 53 字节，SHA-384 套件 69 字节）的 ApplicationData 记录作为合成 Finished。
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

握手完成后，双方通过 **HKDF-SHA256** 派生初始方向独立密钥：

```
okm = HKDF-SHA256(IKM=password, salt=ServerRandom, info=direction)  →  28 字节
```

`direction` 为 `"c2s"` 或 `"s2c"`。每 28 字节输出拆分为：
- **AES 密钥**（前 16 字节）：AES-128-GCM 加密密钥
- **基础 nonce**（后 12 字节）：GCM nonce 构造基础值

ServerRandom 作为 HKDF salt，将密钥绑定到具体 TLS 会话，防止跨会话重放。

## 完美前向保密（PFS）

初始密钥派生仅依赖长期 `password` 和公开的 `ServerRandom`。若 password 未来泄露，录制了历史流量的对手可解密所有过往会话。为防止此风险，ShadowTLS 在已认证的 AEAD 通道上执行**握手后 X25519 临时密钥交换**。

### 0-RTT 设计（非 Mux 模式）

密钥交换为数据路径增加**零额外 RTT**。客户端发送临时公钥后立即开始数据传输，服务端异步响应。

```
客户端                           服务端
  |                               |
  |=== TLS 握手（中继） =========|
  |                               |
  | 派生初始 AEAD 密钥            | 派生初始 AEAD 密钥
  |                               |
  |--- CMD_EPHEMERAL (公钥) ----->| （首个 AEAD 帧）
  |--- 前导填充 + 数据 ---------->| 生成密钥对，计算 DH
  |                               |--- CMD_EPHEMERAL (公钥) --->
  |                               | 立即 rekey s2c
  |                               | 在 c2s 上安装 pending rekey
  | 收到 CMD_EPHEMERAL            |
  | 计算 DH，rekey 双方 AEAD      |
  |--- 数据（新 c2s 密钥）------->| 双密钥 c2s 检测到切换
  |                               | 永久丢弃旧 c2s 密钥
```

在短暂的过渡窗口期间，服务端在 c2s 方向维护**双密钥解密**：先尝试当前（旧）密钥，失败则尝试 pending（新）密钥。新密钥成功后永久丢弃旧密钥。失败的解密尝试不推进序号计数器，确保状态一致。

### 1-RTT 设计（Mux 模式）

多路复用 session 使用阻塞式 1-RTT 方式（客户端等待服务端响应后再继续）。此开销在共享 session 的所有复用连接间分摊。

### CMD_EPHEMERAL 帧格式

```
CMD = 0x09  [32B X25519 公钥]
```

### Rekey 后的密钥派生

DH 完成后，双方派生新的 AEAD 密钥：

```
shared_secret = X25519(我方临时私钥, 对方临时公钥)
okm = HKDF-SHA256(IKM=shared_secret, salt=ServerRandom, info=direction)  →  28 字节
```

临时私钥在 DH 计算后立即丢弃。即使 password 未来泄露，shared_secret 也无法从录制的流量中恢复。

### 安全特性

- **真正的 PFS**：会话密钥依赖临时 DH，而非仅长期密码
- **认证交换**：初始 AEAD 保护密钥交换——MITM 需要知道 password
- **Mux 零开销**：PFS 交换每 session 仅一次，分摊到所有 stream
- **兼容现有帧格式**：CMD_EPHEMERAL 使用与现有命令相同的内层帧格式

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

## TLS Record 合规

所有构造的 ApplicationData 帧**严格遵守 16384 字节标准 TLS fragment 上限**：

```
TLS record payload = GCM tag(16) + 内层头(3) + 数据 + 填充 ≤ 16384
```

- **MAX_DATA_PER_FRAME** = 16384 − 16 − 3 = **16365 字节**
- 单次读取限制为 MAX_DATA_PER_FRAME，填充量额外 clamp
- Mux 模式：MAX_MUX_DATA = 16384 − 16 − 7（mux 帧头） = **16361 字节**

**重要性**：超过 16384 字节的 TLS record 不符合 RFC 8446 标准。网络中间设备（防火墙、NAT、DPI）可能静默截断超大 record，导致帧错位和 GCM 验证失败。高吞吐场景（如 speedtest）尤为敏感。

## 内层帧（反 TLS-in-TLS）

每个加密 payload 携带 3 字节内层头，防止内层协议统计指纹：

```
[CMD : 1B] [DATA_LEN : 2B 大端序] [用户数据 : DATA_LEN 字节] [填充]
```

- `CMD = 0x01`（DATA）：真实用户数据 + 可选填充。
- `CMD = 0x00`（PADDING）：纯填充帧，接收方整体丢弃。

### 填充策略（方向感知 HTTP/2 流量模拟）

真实 HTTP/2 over TLS 流量具有强烈的不对称性：客户端发送小帧（连接前言、SETTINGS、HEADERS），服务端发送大帧（DATA，最大 16 KB）。对两个方向使用相同的填充配置是可检测的指纹。ShadowTLS 受 [restls](https://github.com/3andne/restls) 的流量脚本思路启发，实现了**方向感知填充**。

#### 握手后前导记录（Preamble Records）

在真实数据传输前，双方发送 **1–3 个纯填充 AEAD 记录**（CMD_PADDING），模拟 HTTP/2 连接建立阶段（SETTINGS 交换）。前导记录数量每连接随机化（加权分布：50% 1 条，35% 2 条，15% 3 条），防止"数据总在第 N 条记录"的指纹。

| 角色 | 前导记录 0 | 后续前导记录 |
|------|----------|------------|
| 客户端 | 50 – 90 B（HTTP/2 连接前言 + SETTINGS） | 25 – 60 B（SETTINGS_ACK、WINDOW_UPDATE） |
| 服务端 | 40 – 90 B（SETTINGS + SETTINGS_ACK） | 30 – 70 B（控制帧） |

接收方已有的 CMD_PADDING 处理逻辑会透明丢弃这些记录——无需协议变更。开销：每连接约 100–200 字节，仅发送一次。

#### 客户端 → 服务端（C2S）配置

| 包序号 | 目标 payload 范围 | 模拟流量类型 |
|--------|------------------|-------------|
| 0 | 50 – 100 B | HTTP/2 连接前言（24B）+ SETTINGS（~24B） |
| 1 | 150 – 500 B | HTTP/2 HEADERS 帧（GET/POST 请求） |
| 2 | 50 – 300 B | WINDOW_UPDATE、SETTINGS_ACK、小型请求体 |
| 3+ | 80 – 400 B（5%: 2000 – 8000） | 控制帧 / 偶尔大型 POST 请求体 |

**尾部填充（第 N 包及以后，N 为每连接随机值 [4, 10]）：** 5% 概率追加 0–512 B。

#### 服务端 → 客户端（S2C）配置

| 包序号 | 目标 payload 范围 | 模拟流量类型 |
|--------|------------------|-------------|
| 0 | 40 – 100 B | HTTP/2 SETTINGS + SETTINGS_ACK |
| 1 | 150 – 2000 B | 响应 HEADERS（+ 可能的部分 DATA） |
| 2+ | 500 – 4000 B（12%: 12000 – 16000） | DATA 帧 / 大文件流式传输 |

**尾部填充（第 N 包及以后，N 为每连接随机值 [5, 13]）：** 8% 概率追加 0–1024 B。

服务端尾部填充更重（更高概率、更大范围），因为真实服务器产生的帧大小比客户端变化更大。

#### 与此前填充策略的对比

| 特性 | 此前 | 当前 |
|------|------|------|
| 方向感知 | 双向相同配置 | 独立 C2S / S2C 配置 |
| 初始大小 | 200–600 / 800–1400 | HTTP/2 真实尺寸，按方向区分 |
| 前导记录 | 无 | 1–3 个纯填充 AEAD 记录 |
| 过渡点 | [5, 13] | C2S: [4, 10]，S2C: [5, 13] |
| 尾部概率 | 5% / 0–512 B | C2S: 5% / 0–512 B，S2C: 8% / 0–1024 B |
| HTTP/2 模拟 | 无 | 有（SETTINGS、HEADERS、DATA 尺寸匹配） |

# 安全特性

| 攻击类型 | 防御机制 |
|---------|---------|
| 流量特征检测 | BoringSSL 产生 Chrome 原生 ClientHello（JA3/JA4、X25519Kyber768、GREASE） |
| 主动探测 | session_id HMAC 失败 → 透明 SNI 代理退化 |
| 流量劫持（数据） | 逐帧 AES-128-GCM，方向独立密钥 |
| 密码泄露（历史流量） | X25519 临时 DH 提供真正的完美前向保密 |
| 跨会话重放 | HKDF salt = ServerRandom（每会话唯一） |
| 会话内重放/乱序 | GCM nonce 中 64 位序号 |
| 头部篡改 | TLS 记录头作为 GCM AAD |
| TLS-in-TLS 指纹 | 方向感知 HTTP/2 填充 + 前导记录 |
| 握手→数据过渡指纹 | 1–3 个前导填充记录模拟 HTTP/2 SETTINGS 交换 |
| 流量不对称性指纹 | 独立 C2S（小帧）/ S2C（大帧）填充配置 |
| "数据在固定记录 N"指纹 | 每连接随机化前导记录数量（1–3） |
| 内层 payload 检测 | AES-128-GCM 加密（机密性 + 完整性） |
| TLS record 超长截断 | 所有帧严格 ≤ 16384 字节标准上限 |
| Mux session 卡死 | 死 session 自动检测 + shutdown 清理所有 stream |

# 多路复用 (Mux)

## 架构

Mux 允许多个逻辑流共享单条 TLS 隧道，消除后续连接的握手开销（0 额外 RTT）：

```
sslocal conn 1 ──┐                              ┌── ssserver conn 1
sslocal conn 2 ──┼── shadow-tls client ═══ TLS ═══ shadow-tls server ──┼── ssserver conn 2
sslocal conn 3 ──┘     (mux write/read)          (mux dispatch)   └── ssserver conn 3
```

## Mux 帧格式（加密内层 payload 内）

```
CMD_MUX_SYN    = 0x02  [4B stream_id] [2B initial_window_kb]
CMD_MUX_DATA   = 0x03  [4B stream_id] [2B data_len] [data]
CMD_MUX_FIN    = 0x04  [4B stream_id]
CMD_MUX_RST    = 0x05  [4B stream_id]
```

多个 mux 帧可合并到单个 TLS record（coalescing），上限 MAX_INNER_PAYLOAD（16368 字节）。

## Session 生命周期

1. **创建**：首个连接建立 TLS 隧道，创建 MuxSession，启动 read/write 循环。
2. **复用**：后续连接通过 MuxPool 获取存活 session，调用 `open_stream()` 创建新流。
3. **健康检测**：`MuxSession.is_alive()` 检查 `dead` 标志；`has_capacity()` 同时检查存活和流数量。
4. **死亡与清理**：read/write 循环退出时调用 `shutdown()`：
   - 设置 `dead = true`
   - 清空所有 stream 的数据通道（`streams.clear()`），使阻塞的 `data_rx.recv()` 立即返回 `None`
   - `MuxPool.cleanup()` 移除所有死 session
5. **新建**：下次连接发现无存活 session 时自动建立新 TLS 隧道。

## AuthPending（客户端侧）

客户端 mux read loop 启动时处于 AuthPending 状态，静默丢弃握手残留帧（NewSessionTickets、alerts），直到首个有效 AEAD 帧到达。上限 64 KiB / 10 秒。服务端不需要（handshake drain 在 mux dispatch 前已完成）。

# io_uring 安全

本实现使用 monoio（io_uring 异步运行时）。io_uring 的 completion-based I/O 不支持安全取消 in-flight 读操作（buffer 已提交给内核）。

**设计原则**：不在 `select!` 中取消正在进行的读操作。

- **加密写循环**：先完成 read，再检查 alert 标志（而非 select! 竞争）
- **verbatim drain**：完成 read 后检查 stop 信号和 deadline
- **coalescing**：在 read 前 sleep（而非 read 后 cancel）

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
4. TLS 1.3：追加精确匹配真实加密 Finished 大小的 ApplicationData 作为合成 Finished（根据协商密码套件选择 53 或 69 字节）。
5. 发送客户端飞行。TLS 1.2：发送伪造请求后终止。

**Stage 1.5 — PFS 密钥交换（0-RTT）：**
1. 生成 X25519 临时密钥对。
2. 发送 CMD_EPHEMERAL (0x09) + 32 字节公钥作为首个 AEAD 帧。
3. 立即进入数据中继（不等待服务端响应）。
4. 解密流中收到 CMD_EPHEMERAL 响应时：计算 DH 共享密钥，rekey 双方 AEAD。

**Stage 2 — 数据中继（无需 TLS 库）：**
1. 派生初始 `key_c2s` 和 `key_s2c`：HKDF-SHA256(password, ServerRandom, direction)。
2. PFS rekey 后：派生最终密钥 HKDF-SHA256(shared_secret, ServerRandom, direction)。
3. **读取服务端数据**：解析 ApplicationData，提取 16B GCM tag，用 `key_s2c` 解密。解析内层帧，转发用户数据，丢弃填充。处理 CMD_EPHEMERAL 进行 PFS rekey。
4. **写入服务端数据**：构建内层帧（CMD + DATA_LEN + 数据 + 填充），用 `key_c2s` 加密，封装为 ApplicationData。

## 服务端实现

**Stage 1 — 握手中继（无需 TLS 库）：**
1. 读取 ClientHello，验证 session_id HMAC。失败则纯 TCP 中继（SNI 代理退化）。
2. 转发 ClientHello 至握手服务器。读取 ServerHello，提取 ServerRandom。检测到 HRR 则中继重试 ClientHello 并读取真实 ServerHello。
3. 双向中继直到首个 AEAD 认证的 ApplicationData 帧从客户端到达。
4. AEAD 匹配：关闭握手服务器连接，通知逐帧中继停止。

**Stage 1.5 — PFS 密钥交换：**
1. 首个 AEAD 帧为 CMD_EPHEMERAL 时：解析客户端 X25519 公钥。
2. 生成服务端临时密钥对，发送 CMD_EPHEMERAL 响应。
3. 计算 DH 共享密钥。
4. 非 Mux（0-RTT）：立即 rekey `key_s2c`，在 `key_c2s` 上安装 pending rekey（双密钥过渡）。
5. Mux（1-RTT）：rekey 双方向，再读取下一帧数据。

**Stage 2 — 数据中继：**
1. 派生初始 `key_c2s` 和 `key_s2c`：HKDF-SHA256(password, ServerRandom, direction)。
2. PFS 后：派生最终密钥 HKDF-SHA256(shared_secret, ServerRandom, direction)。
3. **客户端 → 数据服务器**：用 `key_c2s` 解密，解析内层帧，转发用户数据。
4. **数据服务器 → 客户端**：用 `key_s2c` 加密，构建内层帧，应用填充。
