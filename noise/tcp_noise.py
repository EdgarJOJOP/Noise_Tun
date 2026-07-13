"""TCP 全随机噪声包生成器 — 混合 TLS 1.2 / 1.3"""

import struct
import logging
from typing import Optional, Tuple

from .packet_builder import (
    randbytes, randint, build_ip_header, build_tcp_header,
    compute_tcp_checksum, build_fake_tls_client_hello,
    build_fake_tls13_client_hello,
)

logger = logging.getLogger("noisetunnel.tcp_noise")


class TCPNoisePacketGenerator:
    """
    全随机 TCP 噪声包生成器

    生成结构完整的 IP + TCP + TLS Client Hello 数据包，
    每个字段均为 CSPRNG 均匀随机，无任何可学习的分布偏置。

    ★ 增强：混合 TLS 1.2 和 TLS 1.3 ClientHello
    """

    def __init__(self, tun_ip: str = "10.99.0.2",
                 src_port_min: int = 1024,
                 src_port_max: int = 65535,
                 tls13_probability: float = 0.5):
        self.tun_ip = tun_ip
        self.src_port_min = src_port_min
        self.src_port_max = src_port_max
        # TLS CH 模板（从真实流量捕获）
        self._template: Optional[bytes] = None
        # ★ 新增：TLS 1.3 概率
        self._tls13_probability = tls13_probability

    def set_template(self, template: bytes):
        """设置从真实流量捕获的 TLS CH 模板"""
        if len(template) >= 50 and template[0] == 0x16:
            self._template = template
            logging.getLogger("noisetunnel.tcp_noise").debug(
                f"TLS CH template set: {len(template)} B")

    def _build_tls_from_template(self, fake_sni: Optional[str]) -> bytes:
        """
        基于真实浏览器 TLS CH 模板生成噪声 TLS CH
        混合 TLS 1.2 和 TLS 1.3
        """
        # ★ 决定 TLS 版本
        use_tls13 = randfloat() < self._tls13_probability

        if use_tls13:
            return build_fake_tls13_client_hello(fake_sni=fake_sni)

        # 以下是原有 TLS 1.2 逻辑
        r = randint(0, 100)

        # 20%: 完全随机
        if r >= 80 or not self._template:
            return build_fake_tls_client_hello(fake_sni=fake_sni)

        noise = bytearray(self._template)

        # 替换 Random (固定偏移 11-42，32 字节)
        noise[11:43] = randbytes(32)

        # 替换 Session ID 内容
        sid_len = self._template[43]
        if sid_len > 0 and 44 + sid_len <= len(noise):
            noise[44:44 + sid_len] = randbytes(sid_len)

        # 30%: 随机修改扩展区域字节
        if r >= 50:
            ext_start = self._find_extensions_start(bytes(noise))
            if ext_start and ext_start + 4 < len(noise):
                mod_count = randint(1, 3)
                for _ in range(mod_count):
                    pos = randint(ext_start + 2,
                                  max(ext_start + 2, len(noise) - 2))
                    if pos < len(noise) - 1:
                        noise[pos] = randbytes(1)[0]
                        noise[pos + 1] = randbytes(1)[0]

        return bytes(noise)

    def _find_extensions_start(self, data: bytes) -> Optional[int]:
        """查找 TLS CH 中 Extensions 区域的起始偏移"""
        if len(data) < 45:
            return None
        pos = 44 + data[43]  # 跳过 Session ID
        if pos + 2 > len(data):
            return None
        cs_len = (data[pos] << 8) | data[pos + 1]
        pos += 2 + cs_len  # 跳过 Cipher Suites
        if pos + 1 > len(data):
            return None
        pos += 1 + data[pos]  # 跳过 Compression Methods
        if pos + 2 > len(data):
            return None
        return pos

    def generate(self, dst_ip: str, dst_port: int,
                 use_port_coherence: bool = False,
                 fake_sni: Optional[str] = None) -> Tuple[bytes, int]:
        """
        生成一个完整 IP/TCP/TLS CH 噪声包

        参数:
            dst_ip: 目标 IP
            dst_port: 目标端口
            use_port_coherence: 是否使用与真实流量相同的端口
            fake_sni: 嵌入 TLS CH 的假域名，使噪声更逼真

        返回:
            (完整数据包, TCP头长度)
        """
        # 1. TLS Client Hello 载荷（有模板则用模板，否则全随机）
        if self._template:
            tls_payload = self._build_tls_from_template(fake_sni=fake_sni)
        else:
            # ★ 50% 概率用 TLS 1.3
            if randfloat() < self._tls13_probability:
                tls_payload = build_fake_tls13_client_hello(fake_sni=fake_sni)
            else:
                tls_payload = build_fake_tls_client_hello(fake_sni=fake_sni)

        # 2. 随机 TCP 参数
        src_port = randint(self.src_port_min, self.src_port_max)
        actual_dst_port = dst_port if use_port_coherence else randint(1, 65535)
        seq_num = randint(0, 0xFFFFFFFF)
        ack_num = 0

        # SYN 标志 + 可能的随机其他标志
        flags_choices = [0x02, 0x02, 0x02, 0x12, 0x02, 0x12]
        flags = flags_choices[randint(0, len(flags_choices) - 1)]

        # 随机 TCP 选项（MSS、WScale、SACK等）
        options = self._random_tcp_options()

        # 3. 构建 TCP 头（返回 header + 实际长度）
        tcp_header, tcp_header_len = build_tcp_header(
            src_port=src_port,
            dst_port=actual_dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            options=options
        )

        # 4. 构建 IP 头
        ip_total_length = 20 + len(tcp_header) + len(tls_payload)
        src_ip = self._random_src_ip()

        ip_header = build_ip_header(
            total_length=ip_total_length,
            protocol=6,  # TCP
            src_ip=src_ip,
            dst_ip=dst_ip
        )

        # 5. 计算 TCP 校验和
        ip_src = bytes(int(x) for x in src_ip.split("."))
        ip_dst = bytes(int(x) for x in dst_ip.split("."))
        tcp_checksum = compute_tcp_checksum(ip_src, ip_dst, tcp_header, tls_payload)

        # 替换 TCP 头中的校验和（偏移 16 字节处）
        tcp_header_full = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

        # 6. 完整数据包
        packet = ip_header + tcp_header_full + tls_payload

        return packet, tcp_header_len

    def _random_src_ip(self) -> str:
        """生成随机源 IP（TUN 网段内或随机）"""
        r = randint(0, 99)
        if r < 80:
            return f"10.99.{randint(0, 254)}.{randint(1, 254)}"
        else:
            parts = [randint(1, 254) for _ in range(4)]
            return ".".join(str(p) for p in parts)

    def _random_tcp_options(self) -> Optional[bytes]:
        """生成随机 TCP 选项（约 30% 概率携带选项）"""
        if randint(0, 100) >= 70:
            return None

        options = b""

        # MSS 选项
        if randint(0, 1):
            mss = randint(536, 1460)
            options += b"\x02\x04" + struct.pack("!H", mss)

        # Window Scale 选项
        if randint(0, 1):
            shift = randint(0, 14)
            options += b"\x03\x03" + bytes([shift])

        # SACK Permitted 选项
        if randint(0, 1):
            options += b"\x04\x02"

        # 时间戳选项
        if randint(0, 1):
            ts_val = randbytes(4)
            ts_ecr = randbytes(4)
            options += b"\x08\x0a" + ts_val + ts_ecr

        return options if options else None


# ★ 添加 randfloat 导入别名（供内部使用）
from .packet_builder import randfloat
