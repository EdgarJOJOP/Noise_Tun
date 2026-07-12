# NoiseTun — 自适应全随机噪声流量混淆隧道

## 实验目的

验证通过持续发送**全随机 TCP/UDP 噪声包**，是否可以有效破坏中间人对流量模式的机器学习分析，防止攻击者从加密流量中推断用户的上网意图。

## 核心原理

```
应用/浏览器 → 系统 SOCKS5 代理 (localhost:1086)
                    │
            ┌───────▼────────┐
            │  ProxyServer   │  SOCKS5 + HTTP CONNECT 双协议
            │  真实流量转发    │
            └───────┬────────┘
                    │ on_connection 回调
            ┌───────▼────────┐
            │ NoiseInjector  │  统一噪声注入器
            │                │
            │ ┌────────────┐ │
            │ │ DensityCtrl│ │  自适应密度: 高20%/低50%/静默10%
            │ └────────────┘ │
            │ ┌────────────┐ │
            │ │ DoHResolver│ │  加密 DNS，解析真实域名取其他 IP
            │ └────────────┘ │
            │ ┌────────────┐ │
            │ │TCP/UDP Gen │ │  CSPRNG 全随机 + 真实 TLS 模板
            │ └────────────┘ │
            │ ┌────────────┐ │
            │ │FakeSNIGen  │ │  假 SNI 域名伪装
            │ └────────────┘ │
            └────────────────┘
```

### 噪声策略

- **TCP 噪声**：生成结构完整的 IP + TCP + TLS Client Hello 数据包，**每个字节均为 CSPRNG 全随机**，发送到 DoH 解析的真实 IP 后立即 RST
- **UDP 噪声**：生成 IP + UDP + 随机载荷数据包，全部字段 CSPRNG 随机
- **目标发现**：通过 DNS-over-HTTPS (DoH) 加密解析随机域名，不泄露 DNS 查询意图
- **自适应密度**：根据真实流量速率动态调整噪声注入密度
- **无 TUN 虚拟网卡**：纯 SOCKS5 代理，用户态运行，无需管理员权限

## 项目结构

```
├── main.py              # 主入口
├── config.yaml          # 配置文件
├── requirements.txt     # 依赖
├── README.md            # 本文件
│
├── core/
│   ├── config.py        # 配置管理
│   └── socks5_proxy.py  # SOCKS5 代理服务器
│
├── noise/
│   ├── packet_builder.py# IP/TCP/UDP/TLS 包构建器（全随机）
│   ├── tcp_noise.py     # TCP 噪声包生成器
│   └── udp_noise.py     # UDP 噪声包生成器
│
├── dns/
│   ├── resolver.py      # DoH 加密 DNS 解析器
│   └── domain_pool.py   # 随机域名池
│
└── scheduler/
    ├── density.py       # 自适应密度控制器
    └── injector.py      # 统一噪声注入器
```

## 使用方式

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行

```bash
# 启动 NoiseTunnel
python main.py

# 调试模式
python main.py -v
```

### 配置系统代理

启动 NoiseTunnel 后，将系统/浏览器的代理设为 **SOCKS5**：

| 平台 | 设置方式 |
|------|---------|
| **Windows** | 设置 → 网络和 Internet → 代理 → 使用 SOCKS5 代理 → `localhost:1086` |
| **Linux** | `export ALL_PROXY=socks5://localhost:1086` |
| **macOS** | 系统偏好设置 → 网络 → 高级 → 代理 → SOCKS5 代理 → `localhost:1086` |
| **浏览器** | 直接使用系统代理 |

### 配置

编辑 `config.yaml` 调整：

- **`density.*`**: 自适应密度参数（阈值、对应密度值）
- **`noise.doh_url`**: DNS-over-HTTPS 服务地址
- **`socks5.port`**: SOCKS5 代理端口

## 自适应密度策略

| 流量状态 | 判定条件 | 噪声密度 | 行为 |
|---------|---------|---------|------|
| 高流量 | >10 连接/10秒 | 20% | 噪声掺入真实流中 |
| 低流量 | 1-10 连接/10秒 | 50% | 提高噪声防静默指纹 |
| 完全静默 | 持续 5 秒无流量 | 10% | 心跳噪声模拟后台活动 |

## 安全声明

本项目为**实验性质**，仅用于研究流量模式混淆技术。请勿用于非法用途。
