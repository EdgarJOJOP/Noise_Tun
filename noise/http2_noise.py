"""HTTP/2 帧噪声生成器 — 模拟浏览器 HTTP/2 控制流量"""

import struct
import logging
from typing import Optional

from .packet_builder import randbytes, randint, randchoice

logger = logging.getLogger("noisetunnel.http2_noise")

# HTTP/2 帧类型
FRAME_SETTINGS = 0x04
FRAME_PING = 0x06
FRAME_GOAWAY = 0x07
FRAME_WINDOW_UPDATE = 0x08


class HTTP2NoiseGenerator:
    """
    HTTP/2 噪声帧生成器

    生成结构合法的 HTTP/2 控制帧（SETTINGS / PING / WINDOW_UPDATE / GOAWAY），
    模拟浏览器在 TLS 连接上发送的 HTTP/2 控制流量。
    这些帧封装在 TLS Application Data 记录中作为 TCP 噪声的载荷。
    """

    @staticmethod
    def _build_frame_header(frame_type: int, flags: int, length: int) -> bytes:
        """构建 HTTP/2 帧头（3 字节长度 + 1 字节类型 + 1 字节标志 + 4 字节流 ID）"""
        len_hi = (length >> 16) & 0xFF
        len_mid = (length >> 8) & 0xFF
        len_lo = length & 0xFF
        return bytes([len_hi, len_mid, len_lo, frame_type, flags, 0x00, 0x00, 0x00, 0x00])

    def generate_settings(self) -> bytes:
        """SETTINGS 帧（通常建立连接后立即发送）"""
        settings = b""
        num_params = randint(1, 4)
        known_ids = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08]
        for _ in range(num_params):
            param_id = randchoice(known_ids)
            param_val = randint(1, 16777216)
            settings += struct.pack("!HI", param_id, param_val)
        return self._build_frame_header(FRAME_SETTINGS, 0x00, len(settings)) + settings

    def generate_ping(self, ack: bool = False) -> bytes:
        """PING 帧（8 字节 opaque data）"""
        flags = 0x01 if ack else 0x00
        return self._build_frame_header(FRAME_PING, flags, 8) + randbytes(8)

    def generate_window_update(self, stream_id: int = 0) -> bytes:
        """WINDOW_UPDATE 帧"""
        increment = randint(1, 65536)
        return (self._build_frame_header(FRAME_WINDOW_UPDATE, 0x00, 4)
                + struct.pack("!I", increment))

    def generate_goaway(self) -> bytes:
        """GOAWAY 帧"""
        last_stream = randint(0, 100)
        error_code = randchoice([0, 0, 0, 0, 1, 2, 3, 5])
        debug = randbytes(randint(0, 16))
        payload = struct.pack("!II", last_stream, error_code) + debug
        return self._build_frame_header(FRAME_GOAWAY, 0x00, len(payload)) + payload

    def generate_noise(self) -> bytes:
        """生成一个随机 HTTP/2 控制帧"""
        r = randint(0, 100)
        if r < 45:
            return self.generate_settings()
        elif r < 75:
            return self.generate_ping(ack=(randint(0, 1) == 1))
        elif r < 90:
            return self.generate_window_update()
        else:
            return self.generate_goaway()
