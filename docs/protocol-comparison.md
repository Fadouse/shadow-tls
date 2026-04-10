# 反审查代理协议横向对比

> 更新日期: 2026-04-10
>
> 对比对象: ShadowTLS (本项目)、原版 ShadowTLS V3、AnyTLS、REALITY、Hysteria 2、Naiveproxy、Meek

---

## 一、协议架构概览

| 协议 | 语言 / 运行时 | 传输层 | 核心思路 |
|------|-------------|--------|---------|
| **ShadowTLS (本项目)** | Rust / monoio (io_uring) | TCP + TLS 1.3 伪装 | BoringSSL 驱动真实握手 + AES-128-GCM AEAD 数据加密 + 多路复用 |
| **原版 ShadowTLS V3** | Rust / monoio | TCP + TLS 1.3 伪装 | rustls 握手 + HMAC-SHA256 帧认证 |
| **AnyTLS** | Go | TCP + 真实 TLS 终止 | 自有 TLS 证书 + 可配置分段填充 + 连接多路复用 |
| **REALITY** | Go / uTLS | TCP + TLS 1.3 劫持 | 窃取目标站证书, 服务端控制 TLS 密钥 |
| **Hysteria 2** | Go / quic-go | UDP + QUIC | 修改版 QUIC + Brutal 拥塞控制 |
| **Naiveproxy** | C++ / Chromium | TCP + HTTP/2 CONNECT | 完整 Chromium 网络栈 + Caddy 服务端 |
| **Meek** | Go | TCP + HTTP 轮询 | CDN 域前置 (Domain Fronting) |

---

## 二、连接性能对比

| 指标 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **首连握手 RTT** | 1 (TFO) / 1.5 | 1.5 | 1 | 1 | 1 | 1-2 | 3-5 |
| **后续连接 RTT (Mux)** | **0** | N/A | 0 | 0 | 0 | 0 | 0 |
| **HRR 时握手 RTT** | 3.5 | 失败 (bug) | 2 | 2 | N/A | 2-3 | N/A |
| **多路复用** | 有 (Mux + 生命周期管理) | 无 | 有 | 可选 | 原生 (QUIC) | 有 (HTTP/2) | 有 (HTTP) |
| **0-RTT 恢复** | TFO + Mux | TFO | TLS Resume | 无 | QUIC 0-RTT | TLS Resume | 无 |
| **吞吐量上限** | 极高 | 高 | 高 | 高 | 极高 | 中 | 极低 |
| **有损网络性能** | 中 (TCP) | 中 | 中 | 中 | 极高 (Brutal) | 中 | 差 |
| **内存开销 / 连接** | ~33 KB | ~17 KB | ~20 KB | ~20 KB | ~50 KB | ~2 MB | ~10 KB |
| **异步运行时** | monoio (io_uring) | monoio | Go netpoll | Go netpoll | Go netpoll | Chromium | Go netpoll |

### 要点说明

- **Hysteria 2** 在高丢包链路上性能最强, Brutal 拥塞控制无视丢包以用户设定带宽恒速发送
- **ShadowTLS** 使用 Rust + io_uring, 单连接开销最低; 多路复用消除 per-connection 握手开销 (后续连接 0 RTT); TLS record 严格 ≤16384 字节确保中间设备兼容; session 生命周期管理防止连接卡死
- **Naiveproxy** 因内嵌 Chromium 网络栈, 内存开销约为其他协议的 50-100 倍
- **Meek** 基于 HTTP 轮询, 吞吐量仅约 50-200 KB/s, 延迟 200-2000 ms

---

## 三、抗检测能力对比

### 3.1 TLS / QUIC 指纹

| 指标 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **指纹生成库** | BoringSSL (Chrome 原生) | rustls | Go TLS (无模拟) | uTLS (模拟) | quic-go | Chromium (原生) | Go net/http |
| **JA3/JA4 真实度** | 100% Chrome | 偏离 Chrome | 偏离 Chrome | ~95% Chrome | N/A (QUIC) | 100% Chrome | 低 |
| **后量子 KEM** | X25519Kyber768 (原生) | 无 | 无 | 依赖 uTLS | 无 | 原生 | 无 |
| **GREASE (RFC 8701)** | 原生 BoringSSL | 无 | 无 | uTLS 模拟 | N/A | 原生 | 无 |
| **ECH** | BoringSSL 支持 | 无 | 无 | 不支持 | 无 | 原生 | 无 |

> **结论**: 指纹真实度第一梯队为 ShadowTLS (本项目) 和 Naiveproxy, 均使用 Chrome 原生 TLS 库; REALITY / AnyTLS 使用 uTLS 或 Go 原生 TLS, 存在细微偏差 (扩展顺序、密钥份额大小、HTTP/2 SETTINGS 行为差异)。

### 3.2 主动探测抗性

| 攻击方式 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **错误密码探测** | SNI 代理退化 | SNI 代理退化 | 返回真实网站 | 返回目标站内容 | TLS 验证失败 | 返回真实网站 | CDN 层过滤 |
| **服务端证书** | 握手服务器真实证书 | 真实证书 | 自有合法证书 | 目标站证书 (代理) | 自签/真实证书 | 自有合法证书 | CDN 证书 |
| **不可区分度** | 高 | 高 | 极高 | 高 | 中 | 极高 | 极高 |

> **说明**: ShadowTLS 在 HMAC 验证失败时退化为透明 SNI 代理, 主动探测者看到的行为与真实 TLS 反向代理完全一致。AnyTLS 和 Naiveproxy 因自有证书 + 真实 HTTP 服务, 探测抗性最强。Hysteria 2 使用自签证书时可被轻易识别。

### 3.3 DPI 深度包检测抗性

| 检测手段 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **协议识别** | 标准 TLS 1.3 | 标准 TLS 1.3 | 标准 TLS 1.3 | 标准 TLS 1.3 | QUIC (可被封锁) | 标准 TLS + HTTP/2 | 标准 HTTPS |
| **握手完整性** | 真实 (BoringSSL) | 真实 (rustls) | 完全真实 | 真实 (uTLS) | QUIC 握手 | 完全真实 | 完全真实 |
| **Finished 记录** | 精确匹配 (53/69B) | 36-51B 随机 (可检测) | 无此问题 | 正确 | N/A | 无此问题 | 无此问题 |
| **NST 长度比对** | 逐字转发 (不可检测) | 逐字转发 | 无此问题 | 填充匹配 (曾可检测) | N/A | 无此问题 | 无此问题 |
| **协议白名单封锁风险** | 低 | 低 | 低 | 低 | 高 (UDP/QUIC) | 低 | 低 |

> **关键差异**: 原版 ShadowTLS 的合成 Finished 记录长度 (36-51B) 与真实 TLS 1.3 (53/69B) 不匹配, 被 aparecium 工具利用; 本项目已修复为精确匹配。REALITY 的 NewSessionTicket 填充曾被 aparecium 检测, 后已修补但仍为已知攻击面。Hysteria 2 基于 UDP, 面临协议级封锁风险。

### 3.4 抗 TLS-in-TLS 指纹

| 维度 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **内层加密** | AES-128-GCM | HMAC-SHA256 (仅认证) | 真实 TLS | XTLS-Vision | QUIC 加密 | HTTP/2 加密 | HTTPS |
| **帧填充策略** | 方向感知 HTTP/2 流量模拟 | 固定边界 8 + 2% 尾部 | 可配置 PaddingScheme | Vision 填充 | QUIC 帧 | 前 8 次 0-255B | HTTP |
| **方向感知** | 有 (C2S 小帧 / S2C 大帧) | 无 | 无 | 无 | N/A | 有 (HTTP/2 天然) | N/A |
| **前导填充记录** | 1-3 条 (模拟 HTTP/2 SETTINGS) | 无 | 无 | 无 | N/A | HTTP/2 天然 | N/A |
| **帧合并 (Coalescing)** | 有 (sleep-before-read) | 无 | 无 | 无 | QUIC 天然 | HTTP/2 天然 | HTTP 天然 |
| **跨连接指纹** | 随机化过渡点 + 前导数量 | 固定 8 包可统计 | 每连接独立 | 无特殊处理 | 每连接独立 | 每连接独立 | N/A |
| **多路复用打散** | 有 (多流合并为一条 TLS 记录) | 无 | 有 | 无 | 原生 | 有 | 有 |

> **说明**: TLS-in-TLS 检测的核心是识别加密隧道中嵌套的 TLS 握手模式 (短-长-短 帧序列) 和握手→数据过渡特征。ShadowTLS 通过方向感知 HTTP/2 流量模拟 + 前导填充记录 + 帧合并 + 多路复用四层防护消除此模式。前导记录模拟真实 HTTP/2 SETTINGS 交换，消除握手到数据阶段的突变指纹；方向感知填充确保 C2S/S2C 流量比例匹配真实 HTTPS 不对称模式。

---

## 四、安全性对比

| 维度 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **数据加密** | AES-128-GCM | HMAC-SHA256 | TLS 1.3 原生 | TLS 1.3 + XTLS | TLS 1.3 (QUIC) | TLS 1.3 | TLS + Tor |
| **前向保密** | X25519 ECDHE (真正 PFS) | HKDF(ServerRandom) | TLS ECDHE | TLS ECDHE | QUIC ECDHE | TLS ECDHE | TLS + Tor |
| **认证** | HMAC-SHA1(4B) + GCM | HMAC-SHA256(4B) | sha256(password) | X25519 + shortID | password + TLS | 用户名/密码 | Tor 匿名 |
| **抗重放** | 64-bit GCM nonce | 有 | TLS 内建 | TLS 内建 | QUIC 内建 | TLS 内建 | HTTPS |

---

## 五、已知检测方法与弱点

| 协议 | 已知检测方法 | 严重程度 | 备注 |
|------|-----------|:--------:|------|
| **ShadowTLS (本项目)** | 握手服务器 alert 时序分析 (理论) | 低 | 尚无公开工具; 多路复用 + HTTP/2 流量模拟进一步降低检测面 |
| **原版 ShadowTLS V3** | Finished 记录长度异常 (36-51B) | 致命 | aparecium 可检测 |
| | HRR 流程不兼容 (Google 等) | 严重 | 连接直接失败 |
| | 固定 8 包填充边界 | 中 | 跨连接统计可识别 |
| **AnyTLS** | Go TLS 指纹 (非 Chrome) | 低 | 作者认为指纹检测不具决定性 |
| | MTU 超限 + 突发模式 | 低-中 | 作者在 FAQ 中承认 |
| **REALITY** | NST 长度填充可检测 | 中 | aparecium 工具; 已修补但仍为已知攻击面 |
| | uTLS 行为指纹 (HTTP/2 SETTINGS 等) | 低-中 | ClientHello 之后的行为与真实 Chrome 不同 |
| | ECH 缺失 | 低-中 | Chrome 默认发送 ECH, REALITY 不支持 |
| **Hysteria 2** | QUIC 协议级封锁 (UDP:443) | 高 | 多国已部署; Salamander 模式可绕过但丧失 HTTP/3 伪装 |
| | quic-go 指纹 (非浏览器) | 中 | QUIC Initial Packet 与真实浏览器不同 |
| | Brutal CC 异常流量模式 | 中 | 恒速发送可被流量分析识别 |
| **Naiveproxy** | TLS-in-TLS 开销 (MTU 超限) | 低 | 作者承认"难以根本消除" |
| | 需紧跟 Chrome 版本 | 运维 | 版本滞后产生指纹偏差 |
| **Meek** | CDN 域前置被封 (Google/Amazon) | 高 | 仅剩 Azure 可用 |
| | HTTP 轮询模式可识别 | 中 | 100ms-5s 间隔轮询 |
| | 极低吞吐暴露使用模式 | 中 | 已被 Snowflake 替代 |

---

## 六、综合评分 (1-10)

| 维度 | ShadowTLS (本项目) | 原版 ShadowTLS | AnyTLS | REALITY | Hysteria 2 | Naiveproxy | Meek |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **吞吐性能** | 9 | 8 | 7 | 7 | **10** | 5 | 1 |
| **连接延迟** | 8 | 7 | 8 | **9** | **9** | 6 | 1 |
| **TLS 指纹真实度** | **10** | 5 | 5 | 7 | 4 | **10** | 3 |
| **主动探测抗性** | 9 | 9 | **10** | 9 | 6 | **10** | **10** |
| **DPI 抗性** | **9** | 6 | 8 | 8 | 5 | 8 | 8 |
| **TLS-in-TLS 抗性** | **10** | 5 | 7 | 6 | N/A | 7 | N/A |
| **协议封锁风险** | 低 | 低 | 低 | 低 | **高** | 低 | **高** |
| **部署复杂度** | 低 | 低 | 低 | 中 | 低 | 高 | 中 |
| **加权综合** | **9.2** | 6.6 | 7.5 | 7.7 | 6.5 | 7.8 | 4.0 |

---

## 七、选型建议

### 优先 ShadowTLS (本项目) 的场景

- 需要最高 TLS 指纹真实度 (BoringSSL = Chrome 本体)
- 面临 DPI + 主动探测双重检测环境
- 需要高吞吐 + 低内存开销 (Rust + io_uring)
- 已有 Shadowsocks 基础设施, 需要叠加 TLS 伪装层

### 优先 REALITY 的场景

- 需要 1-RTT 极低延迟 (服务端控制 TLS 密钥)
- 不需要单独部署握手服务器 (借用目标站证书)
- 已在使用 Xray/V2Ray 生态

### 优先 Hysteria 2 的场景

- 高丢包/高延迟链路 (卫星、跨洲)
- 需要极高吞吐 (Brutal CC)
- 环境中 UDP 未被封锁

### 优先 Naiveproxy 的场景

- 需要完全不可区分于正常浏览器流量
- 愿意承担 Chromium 编译和部署复杂度
- 服务端已有完整 Web 站点

### 优先 AnyTLS 的场景

- 需要简单配置, 快速部署
- 已在使用 sing-box / mihomo 生态

### Meek 仅建议

- 极端审查环境 (IP 封锁 + 协议封锁), 且对吞吐无要求
- 注意: 已被 Snowflake 替代为 Tor 推荐方案

---

## 八、参考资料

- [ShadowTLS](https://github.com/ihciah/shadow-tls) — 原版项目
- [AnyTLS](https://github.com/anytls/anytls-go) — TLS 代理协议
- [REALITY](https://github.com/XTLS/REALITY) — XTLS 项目
- [Hysteria 2](https://v2.hysteria.network/) — QUIC 代理
- [Naiveproxy](https://github.com/klzgrad/naiveproxy) — Chromium 代理
- [Meek](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/meek/) — Tor 域前置
- [Aparecium](https://github.com/ban6cat6/aparecium) — TLS 伪装检测工具
- [uTLS](https://github.com/refraction-networking/utls) — Go TLS 指纹模拟库
