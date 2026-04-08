---
title: ShadowTLS V3 协议设计
date: 2023-02-06 11:00:00
updated: 2026-04-08 00:00:00
author: ihciah
---

# 版本演进
在 2022 年 8 月的时候我实现了第一版 ShadowTLS 协议。当时 V1 协议的目标非常简单，仅仅通过代理 TLS 握手来逃避中间人对流量的判别。V1 协议假定中间人只会观察握手流量，不会观察后续流量、不会做主动探测，也不会做流量劫持。

但这个假设并不成立。为了防御主动探测，在 V2 版本的协议中添加了通过 challenge-response 方式来验证客户端身份的机制；并新增了 Application Data 封装来更好地伪装流量。

V2 版本目前工作良好，在日常使用中我没有遇到被封锁等问题。在实现了对多 SNI 的支持后，它甚至可以作为一个 SNI Proxy 工作，看起来完全不像是一个偷渡数据用的代理。

但是 V2 协议仍假设中间人不会对流量做劫持（参考 [issue](https://github.com/ihciah/shadow-tls/issues/30)）。流量劫持成本比较高，目前没有被广泛应用，目前中间人的手段仍以旁路观测和注入以及主动探测为主。但这并不意味这未来流量劫持不会被大规模使用，协议设计上能够抵御流量劫持一定是更好的方案。面临的最大的一个问题是，服务端很难隐蔽地表明身份。

这个 [issue](https://github.com/ihciah/shadow-tls/issues/66) 提出的 [restls](https://github.com/3andne/restls) 提供了一个极具创新性的思路。借鉴这个思路我们可以解决服务端身份鉴定问题。

除此之外，我在[这篇博客](https://www.ihcblog.com/a-better-tls-obfs-proxy/)里也提到了一些针对数据封装的可能的劫持攻击，这也是 V3 协议必须解决的问题。

# V3 协议目标
1. 能够防御流量特征检测、主动探测和流量劫持。
2. 更易于正确实现。
3. 尽可能地弱感知 TLS 协议本身，实现者无需 Hack TLS 库，更不需要自行实现 TLS 协议。
4. 保持简单：仅作为 TCP 流代理，不重复造轮子。

## 关于对 TLS 1.2 的支持
V3 协议在严格模式下仅支持使用 TLS1.3 的握手服务器。你可以使用 `openssl s_client -tls1_3 -connect example.com:443` 来探测一个服务器是否支持 TLS1.3。

如果要支持 TLS1.2，需要感知更多 TLS 协议细节，实现起来会更加复杂；鉴于 TLS1.3 已经有较多厂商使用，我们决定在严格模式下仅支持 TLS1.3。

考虑到兼容性和部分对防御连接劫持需求较低的场景（如使用特定 SNI 绕过计费系统），在非严格模式下允许使用 TLS1.2。

# 握手流程
这部分协议设计借鉴 [restls](https://github.com/3andne/restls) 但存在一定差别：弱化了对 TLS 细节的感知，更易于实现。

1. 客户端的 TLS Client 构造 ClientHello，ClientHello 需要生成自定义的 SessionID。SessionID 长度需为 32，前 28 位是随机值，后 4 位是 ClientHello 帧（不含 TLS 帧的 5 字节头，SessionID 后 4 byte 填充 0）的 HMAC 签名数据。HMAC 实例仅为一次性使用，直接使用密码创建实例。同时需要一个 Read Wrapper 负责提取 ServerHello 中的 ServerRandom 并转发后续流。
2. 服务端收到包后，会对 ClientHello 做鉴定，如果鉴定失败则直接持续性与握手服务器进行 TCP 中继。如果鉴定成功，也会将其转发至握手服务器，并持续劫持握手服务器的返回数据流。服务端会：
    1. 记录转发的 ServerHello 中的 ServerRandom。
    2. 对所有 ApplicationData 帧的内容部分做处理：
        1. 对数据做变换，将其 XOR SHA256(PreSharedKey + ServerRandom)。
        2. 添加 4 byte 前缀 `HMAC_ServerRandom(处理后的帧数据)`，HMAC 实例需事先灌入 ServerRandom 作为初始值，对此后从握手服务器转发的 ApplicationData 需要复用这个 HMAC 实例。注意帧长度需要同时 + 4。
3. 客户端的 ReadWrapper 需要解析 ApplicationData 帧，判定前 4 byte HMAC：
    1. 符合 `HMAC_ServerRandom(帧数据)`，则证明服务端是可靠的。在握手完成后这类帧需要过滤掉。
    2. 符合 `HMAC_ServerRandomS(帧数据)`，则证明数据已经完成切换。需要将内容部分转发至用户侧。
    3. 都不符合，此时可能流量已被劫持，需要继续握手（握手失败则作罢），并在握手成功后发送一个长度随机的 HTTP 请求（糊弄性请求），在读取完响应后正确关闭连接。

## 安全性验证
1. 流量劫持时，Server 会返回没有做 XOR 的数据，Client 会直接进入糊弄流程。
2. ClientHello 可能会被重放，但无法使用其正确握手([restls 的讨论](https://github.com/3andne/restls/blob/main/Restls%3A%20%E5%AF%B9TLS%E6%8F%A1%E6%89%8B%E7%9A%84%E5%AE%8C%E7%BE%8E%E4%BC%AA%E8%A3%85.md))，所以无法鉴别我们返回的带前缀的 XOR 数据是否可解密。
2. 若 Client 假装数据解密成功，直接发送数据，由于存在数据帧校验，其也无法通过。

# 数据封装

V2 版本的数据封装协议事实上也无法抵御流量劫持，如中间人可能会在握手完成后对这部分数据做篡改，我们需要能够响应 Alert；中间人也可能会按照 V2 协议的样子将一个 ApplicationData 封装拆成两个，如果连接正常，则也可以用于识别协议。

要应对流量劫持，除了要优化握手流程，数据封装部分也要重新设计。我们需要能够对数据流做验证，并且抵御重放、数据篡改、数据切分、数据乱序等攻击。

## 密钥派生

TLS 握手完成后，双方通过 ServerRandom 派生出方向独立的密钥材料，使用 **HKDF-SHA256**：

```
okm_c2s = HKDF-SHA256(IKM=password, salt=ServerRandom, info="c2s")  →  28 字节
okm_s2c = HKDF-SHA256(IKM=password, salt=ServerRandom, info="s2c")  →  28 字节
```

每 28 字节输出拆分为：
- **AES 密钥**（前 16 字节）：AES-128-GCM 加密密钥
- **基础 nonce**（后 12 字节）：GCM nonce 构造的基础值

使用 ServerRandom 作为 HKDF 的 salt，将数据阶段密钥与具体 TLS 会话绑定，防止跨会话重放攻击。

## 逐帧 AEAD（AES-128-GCM）

每个 ApplicationData 帧使用 **AES-128-GCM** 独立加密和认证（通过 AES-NI 硬件加速，吞吐量约 10 GB/s）：

```
nonce       = base_nonce XOR (seq_be64 右对齐至 12 字节)
ciphertext || tag = AES-128-GCM(key, nonce, AAD=tls_header, plaintext=inner_payload)
```

- `seq_be64`：64 位帧序号（大端序），从 0 开始，每方向每帧递增。64 位计数器消除了 nonce 溢出风险（u32 在约 64 TB 数据量时会溢出）。序号异或到基础 nonce 的末 8 字节。
- `tls_header`：5 字节 TLS 记录头（`type || major || minor || len_hi || len_lo`），用作附加认证数据（AAD），防止头部字段（如长度字段）被篡改。
- `inner_payload`：明文内层帧（内层头 + 数据 + 填充），就地加密为密文。

16 字节 GCM 认证 tag 同时提供完整性和真实性。内层 payload 也被加密，在外层 TLS 加密之上增加了机密性保护。

封装后的帧格式：

```
(5B TLS 记录头)(16B GCM tag)(加密: 1B CMD | 2B DATA_LEN | 用户数据 | 可选填充)
```

**严格序号策略**：连接完成首帧认证（Authenticated）后，任何后续 GCM 校验失败均立即断开连接，不做重试。这消除了对序号计数器的预言攻击。

**AuthPending 资源限制**：在等待第一个认证帧期间（如 NewSessionTicket 残留数据排空），不匹配的 ApplicationData 帧会被静默丢弃。该阶段有两个硬限制：累计丢弃字节不超过 64 KiB，且等待时间不超过 10 秒。超出任一限制则触发断开。

## 帧合并（Coalescing）

当发送方从上游读取到少量数据时，会尝试再次读取以将更多数据合并到单个 TLS 记录中（最大约 16 KB）。这减少了小包场景（如网页浏览）下的 AES-GCM 计算次数和 TLS 记录数量，提升吞吐量，且不会为大数据传输增加延迟。

## 内层帧（反 TLS-in-TLS）

为防止内层协议流量特征（如 Shadowsocks 首包的固定长度）被统计分析检测，每个 ApplicationData payload 携带 3 字节内层头：

```
[CMD : 1 字节][DATA_LEN : 2 字节大端序][用户数据 : DATA_LEN 字节][填充 : 可变]
```

- `CMD = 0x01`（DATA）：帧携带 `DATA_LEN` 字节的真实用户数据，其后跟可变长度填充。接收方仅将 `DATA_LEN` 字节写入下游，丢弃填充部分。
- `CMD = 0x00`（PADDING）：纯填充帧，接收方丢弃整个 payload。

填充位于 HMAC 认证区域**内部**，因此填充内容与用户数据同等受到认证保护。

### 填充策略

填充分两个阶段运作，生成真实的流量分布并避免可检测的截断点。

**阶段 1 — 初始塑形（第 0–7 包）：**

每个方向的前 **8** 个数据包，发送方从贴近真实 HTTPS 流量分布的范围内随机选取目标 TLS 记录 payload 大小：

| 包序号 | 目标 payload 范围 | 模拟的流量类型 |
|---|---|---|
| 0（首包） | 200 – 600 字节 | HTTP 请求 / 小型响应 |
| 1 | 800 – 1 400 字节（5% 概率：14 000 – 16 000） | HTTP 响应头 / 大文件 |
| 2 – 7 | 500 – 1 400 字节（5% 概率：14 000 – 16 000） | HTTP 响应体分块 / 大文件 |

第 1–7 包有 5% 概率产生接近满载的帧（14–16 KB），模拟真实 HTTPS 大文件下载产生最大尺寸 TLS 记录的行为。

若实际用户数据已超过目标大小，则不添加填充（不截断数据）。

**阶段 2 — 尾部填充（第 8 包及以后）：**

初始 8 包之后，每帧有 **2% 概率**追加 0–256 字节随机填充。这消除了第 8 包边界处的突变统计特征，避免该特征成为可检测的指纹。

## 安全性验证

1. 对于中间人数据篡改，逐帧 AES-128-GCM 认证 tag 会立即检测并通过 TLS Alert 关闭连接。
2. 对于跨连接重放攻击，HKDF 派生密钥绑定了 `ServerRandom`，不同 TLS 会话密钥各不相同。
3. 对于连接内部的重放或乱序攻击，GCM nonce 中的 64 位序号保证任何乱序帧解密失败，触发严格断连。
4. 对于头部篡改（如 TLS 记录长度字段），TLS 记录头作为 GCM 的 AAD 输入，覆盖了这一攻击面。
5. 对于 TLS-in-TLS 流量指纹检测，两阶段填充系统在整个连接生命周期内随机化包大小，消除内层协议统计特征。
6. 对于内层 payload 的深度包检测，AES-128-GCM 加密确保内层帧结构（CMD、DATA_LEN、用户数据）即使在外层 TLS 加密被攻破的情况下也不可见。

# 实现指南

## TLS 指纹要求

客户端**必须**产生与真实 Chrome 浏览器完全一致的 TLS ClientHello。本实现使用 **BoringSSL**（Chrome 的实际 TLS 库），通过 `boring` crate 接入，保证指纹是原生的而非模拟的：

- **TLS 库**：BoringSSL（Chrome、Android、Cloudflare 使用的同一 TLS 库）
- **GREASE**：原生 BoringSSL GREASE（RFC 8701）——分布与 Chrome 完全一致
- **密码套件**：Chrome 顺序（TLS 1.3：AES-128-GCM、AES-256-GCM、CHACHA20；TLS 1.2：ECDHE-ECDSA/RSA 配合 AES-128/256-GCM 和 CHACHA20）
- **密钥交换组**：X25519Kyber768Draft00（后量子）、X25519、P-256、P-384——约 1200 字节的 Kyber 密钥份额是关键信号；缺少它，ClientHello 比真实 Chrome 短约 1000 字节
- **ALPN**：`h2`、`http/1.1`（强制）
- **扩展**：原生 BoringSSL 扩展顺序、证书压缩及所有 Chrome 标准扩展
- **签名算法**：Chrome 顺序（ECDSA+SHA256、RSA-PSS+SHA256、RSA+SHA256、ECDSA+SHA384、RSA-PSS+SHA384、RSA+SHA384、RSA-PSS+SHA512、RSA+SHA512）
- **支持版本**：TLS 1.2、TLS 1.3

由于 BoringSSL 就是 Chrome 的 TLS 栈，JA3/JA4 指纹、扩展顺序、密钥份额大小及所有内部编码细节均与真实 Chrome 一致，而非模拟。

## 糊弄性请求（Muddling Request）

V3 严格模式检测到流量劫持（ServerRandom 提取失败或鉴权失败）时，客户端发送模拟 Chrome 131 的真实 HTTP 请求：

- `User-Agent` 与 TLS 指纹的浏览器版本匹配
- 标准 Chrome 头部：`Accept`、`Accept-Language`、`Accept-Encoding`（gzip, deflate, br, zstd）、`Sec-Fetch-*`、`Upgrade-Insecure-Requests`
- 规范的 HTTP/1.1 行终止符（`\r\n`）

## 客户端
客户端负责 TLS 握手、切换并在切换后做数据封装和解封装。

客户端需要内置一个 TLS Client，并在其对网络流读时加一层 Read Wrapper：TLSClient <- ReadWrapper <- TCPStream；同样，在写数据链路上也需要附加一个 Write Wrapper：TLSClient -> WriteWrapper -> TCPStream。

Stage1: TLS 握手
1. 通过 TLS 库构造自定义 SessionID 并签名。
2. ReadWrapper:
    1. 提取 ServerHello 中的 ServerRandom；创建 `HMAC_ServerRandom`。
    2. 对 ApplicationData 使用 `HMAC_ServerRandom` 判定帧内容（不含 4byte HMAC）的 HMAC 与前 4 byte 是否匹配。若匹配则重写数据帧内容为其 XOR SHA256(PreSharedKey + ServerRandom)，并去掉前 4 byte HMAC 值。若不匹配则不做修改，并标记该连接被劫持，握手成功后发送糊弄性请求；握手失败则不做处理。

Stage2: 数据转发（该过程不依赖 TLS 库）
1. 使用 ServerRandom 作为 salt，通过 HKDF-SHA256 派生 `key_c2s` 和 `key_s2c`（各 28 字节：16 字节 AES 密钥 + 12 字节基础 nonce）。
2. 读取来自 Server 连接的 ApplicationData 帧，提取 16 字节 GCM tag，使用 `key_s2c` 和 `base_nonce XOR seq_be64` 构造 nonce 解密密文。
    1. GCM 通过（状态 = AuthPending）：切换至 Authenticated，解析解密后的内层帧，提取 `DATA_LEN` 字节的用户数据（丢弃填充），转发至用户。
    2. GCM 通过（状态 = Authenticated）：同上。纯填充帧（`CMD=0x00`）静默丢弃。
    3. GCM 失败（状态 = AuthPending）：可能为握手残留帧（NewSessionTicket 等），静默丢弃。适用资源限制（64 KiB / 10 秒）。
    4. GCM 失败（状态 = Authenticated）：严格断连——发送 TLS Alert 并关闭。
    说明：Server 在 Client 完成切换后仍可能发送残留 TLS 帧，Client 在 AuthPending 阶段负责过滤。
3. 向 Server 连接写入数据时，构建内层帧（CMD + DATA_LEN + 数据 + 填充），使用 `key_c2s` 和 `base_nonce XOR seq_be64` 进行 AES-128-GCM 加密，封装为 ApplicationData 并附加 GCM tag。应用两阶段填充。小数据量时使用帧合并。

## 服务端
服务端负责转发 TLS 握手、判定切换时机并在切换后做数据封装和解封装，它不依赖 TLS 库。

Stage1: 转发 TLS 握手
1. 读 ClientHello: 提取并鉴定 ClientHello 中的 SessionID，若未通过则标记为主动探测流量，后续直接启动 TCP 转发（实现多 SNI 的话还需要解析 SNI 并做对应分流转发）；若通过也会转发该数据帧，并继续第二步。
2. 从另一侧读 ServerHello: 提取 ServerRandom。
3. 启动双向转发(with Handshake Server):
    1. 创建 `HMAC_ServerRandomC` 和 `HMAC_ServerRandom`。
    2. ShadowTLS Client -> Handshake Server: 直接转发，直到遇到符合 ApplicationData 前 4 byte 符合 `HMAC_ServerRandomC` 签名结果的数据帧，此时停止双向转发（但需要保证残留正在发送中的帧的完整性）。
    3. Handshake Server -> ShadowTLS Client: 对 Application Data 帧做修改，对数据做 XOR SHA256(PreSharedKey + ServerRandom) 之后在头部添加 4 byte HMAC（由 `HMAC_ServerRandom` 计算）。

Stage2: 数据转发（with Data Server）
1. 使用 ServerRandom 作为 salt，通过 HKDF-SHA256 派生 `key_c2s` 和 `key_s2c`（各 28 字节：16 字节 AES 密钥 + 12 字节基础 nonce）。
2. ShadowTLS Client → Data Server：解析 ApplicationData，提取 16 字节 GCM tag，使用 `key_c2s` 和 `base_nonce XOR seq_be64` 解密密文。认证失败则按 Alert bad_record_mac 处理。认证成功后解析解密的内层帧，提取真实用户数据（丢弃填充），转发至 Data Server。
3. Data Server → ShadowTLS Client：构建内层帧，使用 `key_s2c` 进行 AES-128-GCM 加密，封装为 ApplicationData 并附加 GCM tag。对所有帧应用两阶段填充。小数据量时使用帧合并。
