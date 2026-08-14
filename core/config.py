"""NoiseTunnel 配置模块"""

import logging
import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("noisetunnel.config")

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

    # Raw Socket 注入
    raw_injection_enabled: bool = True
    raw_injection_required: bool = False

    # 浏览器指纹伪装
    browser_fingerprints_enabled: bool = True

    # 真实流量分布采集
    traffic_profiling_enabled: bool = True

    # 域名池大小 (用于批量解析获取噪声目标 IP)
    domain_pool_size: int = 500

    # 进程重启间隔(秒), 默认86400(24h), 0=不重启
    refresh_interval: int = 86400

    # ★ 噪声专用 DoH（无域名拦截，用于解析 domain_sources / DomainPool）
    #   主 DoH（doh_url）有域名拦截功能，会拦截广告/追踪域名
    #   噪声域名本身就是广告/追踪列表，需要用无拦截的 DoH 才能解析到真实 IP
    noise_doh_url: str = "https://dns.alidns.com/dns-query"
    noise_fallback_doh_url: str = "https://1.1.1.1/dns-query"
    noise_doh_timeout: float = 5.0
    noise_dns_cache_ttl: int = 600
    noise_dns_cache_enabled: bool = True


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
class TrafficProfilingConfig:
    """真实流量分布采集配置"""
    enabled: bool = True
    max_samples: int = 10000
    max_interval_samples: int = 5000


@dataclass
class DomainSourceConfig:
    """域名源配置"""
    enabled: bool = True
    refresh_interval: int = 86400
    urls: list = None

    def __post_init__(self):
        if self.urls is None:
            self.urls = [
                "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/AdvertisingLite/AdvertisingLite.txt",
            ]


@dataclass
class Config:
    """全局配置"""
    socks5: Socks5Config = field(default_factory=Socks5Config)
    additional_bind: AdditionalBindConfig = field(default_factory=AdditionalBindConfig)
    noise: NoiseConfig = field(default_factory=NoiseConfig)
    density: DensityConfig = field(default_factory=DensityConfig)
    traffic_profiling: TrafficProfilingConfig = field(default_factory=TrafficProfilingConfig)
    domain_sources: DomainSourceConfig = field(default_factory=DomainSourceConfig)

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
            if "traffic_profiling" in data:
                for k, v in data["traffic_profiling"].items():
                    if hasattr(cfg.traffic_profiling, k):
                        setattr(cfg.traffic_profiling, k, v)
            if "domain_sources" in data:
                for k, v in data["domain_sources"].items():
                    if hasattr(cfg.domain_sources, k):
                        setattr(cfg.domain_sources, k, v)
            if "log_level" in data:
                cfg.log_level = data["log_level"]

        # === 配置校验 ===
        _errors = []

        # SOCKS5 端口范围
        if not (0 < cfg.socks5.port <= 65535):
            _errors.append(f"socks5.port 无效: {cfg.socks5.port}")
        if cfg.additional_bind.enabled and not (0 < cfg.additional_bind.port <= 65535):
            _errors.append(f"additional_bind.port 无效: {cfg.additional_bind.port}")

        # 噪声端口范围
        if not (0 <= cfg.noise.tcp_min_port <= 65535):
            _errors.append(f"tcp_min_port 无效: {cfg.noise.tcp_min_port}")
        if not (0 <= cfg.noise.tcp_max_port <= 65535):
            _errors.append(f"tcp_max_port 无效: {cfg.noise.tcp_max_port}")
        if cfg.noise.tcp_min_port > cfg.noise.tcp_max_port:
            _errors.append(f"tcp_min_port({cfg.noise.tcp_min_port}) > tcp_max_port({cfg.noise.tcp_max_port})")
        if not (0 <= cfg.noise.udp_min_port <= 65535):
            _errors.append(f"udp_min_port 无效: {cfg.noise.udp_min_port}")
        if not (0 <= cfg.noise.udp_max_port <= 65535):
            _errors.append(f"udp_max_port 无效: {cfg.noise.udp_max_port}")
        if cfg.noise.udp_min_port > cfg.noise.udp_max_port:
            _errors.append(f"udp_min_port({cfg.noise.udp_min_port}) > udp_max_port({cfg.noise.udp_max_port})")

        # 噪声密度范围
        for name, val in [("high_traffic_density", cfg.density.high_traffic_density),
                          ("low_traffic_density", cfg.density.low_traffic_density),
                          ("silence_density", cfg.density.silence_density)]:
            if not (0.0 <= val <= 1.0):
                _errors.append(f"density.{name}={val} 必须在 0.0-1.0 之间")

        # 载荷大小范围
        if cfg.noise.min_payload_size > cfg.noise.max_payload_size:
            _errors.append(f"min_payload_size({cfg.noise.min_payload_size}) > max_payload_size({cfg.noise.max_payload_size})")

        # 超时和缓存
        if cfg.noise.doh_timeout <= 0:
            _errors.append(f"doh_timeout={cfg.noise.doh_timeout} 必须 > 0")
        if cfg.noise.dns_cache_ttl <= 0:
            _errors.append(f"dns_cache_ttl={cfg.noise.dns_cache_ttl} 必须 > 0")

        # 域名池
        if cfg.noise.domain_pool_size < 10:
            _errors.append(f"domain_pool_size={cfg.noise.domain_pool_size} 过小，应 >= 10")

        if _errors:
            for e in _errors:
                logger.error(f"配置校验失败: {e}")
            raise ValueError(f"配置校验失败 ({len(_errors)} 项错误)，请修正 config.yaml")

        logger.info("配置校验通过")
        return cfg
