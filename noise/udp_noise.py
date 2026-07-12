"""UDP 全随机噪声包生成器（支持真实流量模板）"""

import struct
import logging
from typing import Optional

from .packet_builder import (
    randbytes, randint, build_ip_header, build_udp_header
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

        # 4. 构建 IP 头
        ip_total_length = 20 + len(udp_header) + len(payload)
        src_ip = self._random_src_ip()

        ip_header = build_ip_header(
            total_length=ip_total_length,
            protocol=17,  # UDP
            src_ip=src_ip,
            dst_ip=dst_ip
        )

        packet = ip_header + udp_header + payload
        return packet

    def _random_udp_payload(self) -> bytes:
        """生成 UDP 载荷：优先模板头部 + 随机填充 + 体积模拟"""
        # 体积模拟：按概率选择不同大小的噪声类型
        r = randint(0, 100)

        # 先确定目标长度
        if r < 40:       # 40%: 小包 (DNS-like, 50-200B)
            length = randint(50, 200)
        elif r < 70:     # 30%: 中包 (API调用, 500-2000B)
            length = randint(500, 2000)
        elif r < 85:     # 15%: 大包 (图片加载, 10-50KB)
            length = randint(10000, 50000)
        elif r < 95:     # 10%: 特大包 (视频切片, 100-500KB)
            length = randint(100000, 500000)
        else:            # 5%: 超大包 (文件下载, 1-5MB)
            length = randint(1000000, 5000000)

        # 限制在 min/max 范围内
        length = max(self.min_payload, min(length, self.max_payload))

        # 如果有模板，用模板头 + 随机填充剩余
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
        """生成随机源 IP"""
        r = randint(0, 99)
        if r < 80:
            return f"10.99.{randint(0, 254)}.{randint(1, 254)}"
        else:
            parts = [randint(1, 254) for _ in range(4)]
            return ".".join(str(p) for p in parts)
