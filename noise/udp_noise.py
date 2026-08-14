"""UDP 全随机噪声包生成器（支持真实流量模板）"""

import struct
import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .traffic_profile import TrafficProfile

from .packet_builder import (
    randbytes, randint, randchoice, build_ip_header, build_ipv6_header, build_udp_header
)

logger = logging.getLogger("noisetunnel.udp_noise")


class UDPNoisePacketGenerator:
    """
    UDP 噪声包生成器

    支持两种模式：
    1. 模板模式：使用真实 UDP 流量载荷头 + CSPRNG 随机填充
    2. 全随机模式：无模板时，全随机生成
    """

    def __init__(self, tun_ip: str = "10.99.0.2",
                 src_port_min: int = 1024,
                 src_port_max: int = 65535,
                 min_payload: int = 20,
                 max_payload: int = 1400):
        self.tun_ip = tun_ip
        self.src_port_min = src_port_min
        self.src_port_max = src_port_max
        self.min_payload = min_payload
        self.max_payload = max_payload
        self._sampler = None  # UDPSampler 实例
        self._profile: Optional['TrafficProfile'] = None

    def set_traffic_profile(self, profile: 'TrafficProfile'):
        """设置真实流量分布采集器 (用于包大小采样)"""
        self._profile = profile

    def set_sampler(self, sampler):
        """设置 UDP 采样器（获取真实流量载荷模板）"""
        self._sampler = sampler

    def generate(self, dst_ip: str, dst_port: int,
                 use_port_coherence: bool = False) -> bytes:
        """
        生成一个完整 IP/UDP/随机载荷 噪声包

        如果已设置采样器且有模板，使用模板头部 + 随机填充；
        否则全随机生成。
        """
        src_port = randint(self.src_port_min, self.src_port_max)
        actual_dst_port = dst_port if use_port_coherence else randint(1, 65535)

        # 2. 随机载荷（优先使用模板）
        payload = self._random_udp_payload()

        # 3. 构建 UDP 头
        udp_header = build_udp_header(src_port, actual_dst_port, len(payload))

        # 4. 构建 IP 头 (IPv4 或 IPv6)
        ip_total_length = (20 if not self._is_ipv6(dst_ip) else 40) + len(udp_header) + len(payload)
        src_ip = self._random_src_ipv6() if self._is_ipv6(dst_ip) else self._random_src_ip()

        if self._is_ipv6(dst_ip):
            ip_header = build_ipv6_header(
                len(udp_header) + len(payload), 17, src_ip, dst_ip
            )
        else:
            ip_header = build_ip_header(
                total_length=ip_total_length, protocol=17,
                src_ip=src_ip, dst_ip=dst_ip
            )

        packet = ip_header + udp_header + payload
        return packet

    def _random_udp_payload(self) -> bytes:
        """生成 UDP 载荷：优先从真实流量分布采样, 其次模板头部 + 随机填充"""
        # 如果有 profile 且有足够数据, 从真实分布采样
        if self._profile and self._profile.has_data():
            sampled = self._profile.sample_packet_size("udp")
            if sampled > 0:
                length = sampled
            else:
                length = randint(self.min_payload, self.max_payload)
        else:
            # fallback: 硬编码概率 (保留原行为)
            r = randint(0, 100)
            if r < 40:
                length = randint(50, 200)
            elif r < 70:
                length = randint(500, 2000)
            elif r < 85:
                length = randint(10000, 50000)
            elif r < 95:
                length = randint(100000, 500000)
            else:
                length = randint(1000000, 5000000)

        length = max(self.min_payload, min(length, self.max_payload))

        # 有模板则用模板头 + 随机填充
        header = None
        if self._sampler:
            header = self._sampler.get_template()

        if header:
            if len(header) >= length:
                return header[:length]
            else:
                return header + randbytes(length - len(header))
        else:
            return randbytes(length)

    def _random_src_ip(self) -> str:
        """生成随机 IPv4 源 IP"""
        r = randint(0, 99)
        if r < 80:
            return f"10.99.{randint(0, 254)}.{randint(1, 254)}"
        else:
            parts = [randint(1, 254) for _ in range(4)]
            return ".".join(str(p) for p in parts)

    def _random_src_ipv6(self) -> str:
        """生成随机 IPv6 源地址"""
        r = randint(0, 99)
        if r < 70:
            return (f"fd{randint(0,255):02x}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(1,65535):04x}")
        else:
            prefix = randchoice(["2001", "2600", "2400", "2a00", "2c00"])
            return (f"{prefix}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(0,65535):04x}"
                    f":{randint(0,65535):04x}:{randint(1,65535):04x}")

    @staticmethod
    def _is_ipv6(ip: str) -> bool:
        return ":" in ip
