"""NoiseTunnel 配置模块"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")


@dataclass
class Socks5Config:
    """SOCKS5 代理配置"""
    host: str = "localhost"
    port: int = 1086
    udp_enabled: bool = True
    username: str = ""
    password: str = ""


@dataclass
class AdditionalBindConfig:
    """局域网额外监听配置"""
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 1087
    username: str = ""
    password: str = ""


@dataclass
class NoiseConfig:
    """噪声引擎配置"""

    # TCP 噪声
    tcp_enabled: bool = True
    tcp_min_port: int = 1024
    tcp_max_port: int = 65535

    # UDP 噪声
    udp_enabled: bool = True
    udp_min_port: int = 1024
    udp_max_port: int = 65535

    # 噪声包大小范围（含体积模拟）
    min_payload_size: int = 20
    max_payload_size: int = 100000  # 100KB，模拟图片/API流量

    # 加密 DNS
    doh_url: str = "https://cloudflare-dns.com/dns-query"
    fallback_doh_url: str = ""
    doh_timeout: float = 5.0
    dns_cache_ttl: int = 300
    dns_cache_enabled: bool = True
    enforce_doh_only: bool = True


@dataclass
class DensityConfig:
    """自适应密度控制器配置"""

    # 滑动窗口（秒）
    window_seconds: float = 10.0

    # 密度阈值
    high_traffic_threshold: int = 10       # >10 连接/秒
    low_traffic_threshold: int = 1         # <1 连接/秒
    silence_seconds: float = 5.0           # 持续静默判定

    # 对应密度
    high_traffic_density: float = 0.20     # 高流量时 20%
    low_traffic_density: float = 0.50      # 低流量时 50%
    silence_density: float = 0.10          # 静默时 10%（心跳）


@dataclass
class Config:
    """全局配置"""
    socks5: Socks5Config = field(default_factory=Socks5Config)
    additional_bind: AdditionalBindConfig = field(default_factory=AdditionalBindConfig)
    noise: NoiseConfig = field(default_factory=NoiseConfig)
    density: DensityConfig = field(default_factory=DensityConfig)

    log_level: str = "INFO"

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        path = path or DEFAULT_CONFIG_PATH
        cfg = cls()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if "socks5" in data:
                for k, v in data["socks5"].items():
                    if hasattr(cfg.socks5, k):
                        setattr(cfg.socks5, k, v)
            if "noise" in data:
                for k, v in data["noise"].items():
                    if hasattr(cfg.noise, k):
                        setattr(cfg.noise, k, v)
            if "density" in data:
                for k, v in data["density"].items():
                    if hasattr(cfg.density, k):
                        setattr(cfg.density, k, v)
            if "additional_bind" in data:
                for k, v in data["additional_bind"].items():
                    if hasattr(cfg.additional_bind, k):
                        setattr(cfg.additional_bind, k, v)
            if "log_level" in data:
                cfg.log_level = data["log_level"]
        return cfg
