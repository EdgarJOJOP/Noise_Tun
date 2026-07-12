"""QUIC/HTTP3 噪声包生成器"""
import os
import struct
import logging
from typing import Optional

from .packet_builder import randint

logger = logging.getLogger("noisetunnel.quic_noise")


class QUICNoiseGenerator:
    """
    QUIC Initial 包噪声生成器

    生成结构合法的 QUIC 长头包（Version 1），
    模拟现代浏览器使用 QUIC/HTTP3 的流量。
    """

    def generate(self, size_hint: Optional[int] = None) -> bytes:
        """
        生成一个 QUIC Initial 噪声包

        返回:
            UDP 载荷（不含 IP/UDP 头）
        """
        # QUIC 长头包格式
        # 1. 第一个字节: Header Form(1) | Fixed Bit(1) | Long Packet Type(2) | Reserved(2) | Packet Number Len(2)
        #    0xc0 = 0b11000000: Long Header, Fixed Bit, Initial Type=0
        first_byte = bytes([0xc0])

        # 2. Version: 0x00000001 (QUIC v1)
        version = b'\x00\x00\x00\x01'

        # 3. DCID Length + DCID (随机 8 字节)
        dcid = os.urandom(8)
        dcid_field = bytes([len(dcid)]) + dcid

        # 4. SCID Length + SCID (随机 8 字节)
        scid = os.urandom(8)
        scid_field = bytes([len(scid)]) + scid

        # 5. Token Length + Token (QUIC Initial 通常有 token)
        token_len = randint(0, 32)
        if token_len > 0:
            token_field = struct.pack('!I', token_len) + os.urandom(token_len)
        else:
            token_field = b'\x00\x00\x00\x00'

        # 6. Payload (加密载荷，用随机字节模拟)
        payload_size = size_hint or randint(100, 500)
        payload = os.urandom(payload_size)

        # 组合
        packet = first_byte + version + dcid_field + scid_field + token_field + payload
        return packet
