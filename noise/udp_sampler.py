"""UDP 载荷采样器 — 从系统流量中捕获真实 UDP 载荷头"""

import asyncio
import logging
import os
import struct
import time
from typing import Optional

logger = logging.getLogger("noisetunnel.udp_sampler")

# 内置常见 UDP 协议载荷模板（前 N 字节）
_BUILTIN_TEMPLATES = [
    # DNS query header (12 bytes)
    b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00',
    # DNS response header
    b'\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00',
    # QUIC Initial v1
    b'\xc0\x00\x00\x00\x01\x08',
    # QUIC Initial v2
    b'\xc0\x6b\x33\x43\xcf\x08',
    # DTLS 1.2 ClientHello record
    b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    # DTLS 1.0 ClientHello record
    b'\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    # STUN Binding Request
    b'\x00\x01\x00\x00\x21\x12\xa4\x42',
    # STUN Binding Response
    b'\x01\x01\x00\x00\x21\x12\xa4\x42',
    # NTP client
    b'\x1b\x00\x00\x00\x00\x00\x00\x00',
    # HTTP/3 QUIC Initial
    b'\xc0\x00\x00\x00\x01\x00\x08\xf0\xf0\xf0\xf0',
    # Generic 16 random bytes (fallback)
    b'\x00' * 16,
]


class UDPSampler:
    """
    UDP 载荷采样器

    通过 raw socket 捕获系统真实 UDP 流量的载荷头，
    用于生成与真实流量统计分布相同的 UDP 噪声。
    如果 raw socket 不可用（无管理员权限），
    回退到内置常见 UDP 协议模板。

    ★ 增强：同时提取真实 UDP 目标 (dst_ip, dst_port) 用于噪声寻址
    """

    def __init__(self, max_samples: int = 100, header_bytes: int = 24):
        self.max_samples = max_samples
        self.header_bytes = header_bytes
        self._samples: list[bytes] = []
        self._has_real_samples = False
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # ★ 新增：真实 UDP 目标回调 + 缓存
        self._on_real_udp_target = None  # callable(dst_ip, dst_port)
        self._recent_udp_targets: list[tuple[str, int]] = []

    # ── 手动添加样本 ──

    def add_sample(self, data: bytes):
        """添加一个 UDP 载荷头部样本"""
        if len(data) < 4:
            return
        header = data[:min(len(data), self.header_bytes)]
        self._samples.append(header)
        if len(self._samples) > self.max_samples:
            self._samples.pop(0)
        self._has_real_samples = True

    # ── 获取模板 ──

    def get_template(self) -> Optional[bytes]:
        """返回一个随机模板：优先真实样本，其次内置模板"""
        if self._samples:
            idx = int.from_bytes(os.urandom(4), "big") % len(self._samples)
            return self._samples[idx]
        if _BUILTIN_TEMPLATES:
            idx = int.from_bytes(os.urandom(4), "big") % len(_BUILTIN_TEMPLATES)
            return _BUILTIN_TEMPLATES[idx]
        return None

    # ★ 新增：UDP 目标回调

    def set_on_real_udp_target(self, callback):
        """注册回调：捕获到真实 UDP 目标时通知 injector"""
        self._on_real_udp_target = callback

    def get_recent_udp_targets(self, count: int = 5) -> list[tuple[str, int]]:
        """返回最近捕获的 N 个 UDP 真实目标"""
        return self._recent_udp_targets[-count:]

    # ── Raw Socket 捕获 ──

    async def start_capture(self):
        self._running = True
        loop = asyncio.get_event_loop()
        self._task = asyncio.create_task(self._capture_loop(loop))

    async def stop_capture(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _capture_loop(self, loop):
        import socket as sock_mod
        sock = None
        try:
            sock = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_RAW, sock_mod.IPPROTO_UDP)
            sock.settimeout(0.5)
            logger.info("UDP raw socket 创建成功，开始采样")
        except PermissionError:
            logger.info("UDP raw socket 需管理员权限，使用内置模板")
            return
        except Exception as e:
            logger.debug(f"UDP raw socket 失败: {e}，使用内置模板")
            return

        def _blocking_recv():
            """在线程中运行的阻塞式 recv，不阻塞事件循环"""
            try:
                while self._running:
                    try:
                        packet, addr = sock.recvfrom(65535)
                        if len(packet) < 28:
                            continue
                        ip_hl = (packet[0] & 0x0F) * 4
                        if ip_hl + 8 > len(packet):
                            continue
                        payload_offset = ip_hl + 8
                        payload = packet[payload_offset:]
                        self.add_sample(payload)

                        # ★ 新增：记录真实 UDP 目标
                        dst_ip = ".".join(str(packet[16+i]) for i in range(4))
                        dst_port = (packet[ip_hl+2] << 8) | packet[ip_hl+3]
                        self._recent_udp_targets.append((dst_ip, dst_port))
                        if len(self._recent_udp_targets) > 20:
                            self._recent_udp_targets.pop(0)
                        if self._on_real_udp_target:
                            self._on_real_udp_target(dst_ip, dst_port)

                    except sock_mod.timeout:
                        continue
                    except Exception as e:
                        logger.debug(f"UDP 捕获异常: {e}")
                        return
            finally:
                if sock:
                    sock.close()

        await loop.run_in_executor(None, _blocking_recv)
