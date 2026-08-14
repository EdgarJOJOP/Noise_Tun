"""WebSocket 噪声帧生成器 — RFC 6455 §5.5.2/3"""

import struct
import logging
from typing import Optional

from .packet_builder import randbytes, randint

logger = logging.getLogger("noisetunnel.websocket_noise")


class WebSocketNoiseGenerator:
    """
    WebSocket 噪声帧生成器

    生成 WebSocket ping/pong 帧，模拟真实 WebSocket 应用的心跳/保活流量。
    这些帧封装在 TLS Application Data 记录中作为 TCP 噪声的载荷。
    """

    def generate_ping(self) -> bytes:
        """WebSocket Ping 帧 (opcode=0x9, FIN=1)"""
        payload = randbytes(randint(0, 32))
        length = len(payload)
        if length < 126:
            return bytes([0x89, length]) + payload
        else:
            return bytes([0x89, 126]) + struct.pack("!H", length) + payload

    def generate_pong(self) -> bytes:
        """WebSocket Pong 帧 (opcode=0xA, FIN=1)"""
        payload = randbytes(randint(0, 32))
        length = len(payload)
        if length < 126:
            return bytes([0x8A, length]) + payload
        else:
            return bytes([0x8A, 126]) + struct.pack("!H", length) + payload
