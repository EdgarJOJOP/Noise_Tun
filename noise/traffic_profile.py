"""真实流量分布采集器 — 实时统计包大小 & 连接间隔分布

采集方式:
  1. SOCKS5 代理转发数据时记录每个数据包的大小 (见 core/socks5_proxy.py)
  2. 连接建立/关闭时记录间隔

用途:
  - UDP 噪声包大小从真实分布采样 (替代硬编码概率桶)
  - TimingShaper 发送间隔从真实分布采样 (替代 RTT 单点估计)
"""

import logging
import math
import time
from collections import deque
from typing import Optional

logger = logging.getLogger("noisetunnel.traffic_profile")

# 对数分桶: 32 个桶覆盖 1B ~ 1MB
_BUCKET_COUNT = 32
_BUCKET_MIN = 1.0
_BUCKET_MAX = 1_048_576.0  # 1MB


def _log_bucket(value: float) -> int:
    """将对数域的值映射到桶索引 [0, _BUCKET_COUNT)"""
    if value <= _BUCKET_MIN:
        return 0
    if value >= _BUCKET_MAX:
        return _BUCKET_COUNT - 1
    ratio = value / _BUCKET_MIN
    log_ratio = math.log2(ratio)
    log_step = math.log2(_BUCKET_MAX / _BUCKET_MIN) / (_BUCKET_COUNT - 1)
    return min(_BUCKET_COUNT - 1, int(log_ratio / log_step))


def _bucket_midpoint(index: int) -> float:
    """返回桶的中位值 (字节)"""
    log_step = math.log2(_BUCKET_MAX / _BUCKET_MIN) / (_BUCKET_COUNT - 1)
    return _BUCKET_MIN * (2 ** ((index + 0.5) * log_step))


class TrafficProfile:
    """实时流量分布采集器

    维护两个滑动窗口:
      - 包大小直方图 (对数分桶)
      - 连接间隔时间序列

    线程安全: 所有操作在 asyncio 单线程中, 无需锁
    """

    def __init__(self,
                 max_packet_samples: int = 10000,
                 max_interval_samples: int = 5000):
        self.max_packet_samples = max_packet_samples
        self.max_interval_samples = max_interval_samples

        # 包大小: 直方图 (计数) + 原始值滑动窗口
        self._packet_histogram: list[int] = [0] * _BUCKET_COUNT
        self._packet_total: int = 0        # 总包数 (用于频率)
        self._packet_bytes: deque[int] = deque(maxlen=max_packet_samples)

        # 连接间隔
        self._intervals: deque[float] = deque(maxlen=max_interval_samples)
        self._last_conn_time: Optional[float] = None

        # 协议区分 (TCP / UDP)
        self._tcp_histogram: list[int] = [0] * _BUCKET_COUNT
        self._udp_histogram: list[int] = [0] * _BUCKET_COUNT

    # ------------------------------------------------------------------
    # 记录接口
    # ------------------------------------------------------------------

    def record_packet(self, protocol: str, data_len: int):
        """记录一个真实数据包的大小

        参数:
            protocol: "tcp" 或 "udp"
            data_len: 数据包字节数
        """
        if data_len <= 0:
            return
        bucket = _log_bucket(data_len)
        self._packet_histogram[bucket] += 1
        self._packet_total += 1
        self._packet_bytes.append(data_len)

        if protocol == "tcp":
            self._tcp_histogram[bucket] += 1
        elif protocol == "udp":
            self._udp_histogram[bucket] += 1

    def record_connection(self):
        """记录一次真实连接 (用于计算到达间隔)"""
        now = time.time()
        if self._last_conn_time is not None:
            interval = now - self._last_conn_time
            if 0.001 <= interval <= 300.0:  # 过滤异常值
                self._intervals.append(interval)
        self._last_conn_time = now

    # ------------------------------------------------------------------
    # 采样接口
    # ------------------------------------------------------------------

    def sample_packet_size(self, protocol: str = "tcp") -> int:
        """从真实分布中采样一个包大小

        先根据总频率分布采样桶, 再从桶内均匀采样。
        若无数据, 返回 0 (调用方回退到硬编码逻辑)。
        """
        if self._packet_total == 0:
            return 0

        # 选协议对应的直方图
        hist = self._tcp_histogram if protocol == "tcp" else self._udp_histogram
        if sum(hist) == 0:
            hist = self._packet_histogram
        if sum(hist) == 0:
            return 0

        # 按分布概率选桶
        r = self._randint(0, sum(hist) - 1)
        cumulative = 0
        for i, count in enumerate(hist):
            cumulative += count
            if r < cumulative:
                break
        else:
            i = 0

        # 在桶内均匀抖动
        low = _bucket_midpoint(max(0, i - 1))
        high = _bucket_midpoint(min(_BUCKET_COUNT - 1, i + 1))
        return int(low + self._randfloat() * (high - low))

    def sample_interval(self) -> float:
        """从真实连接间隔分布中采样一个等待时间 (秒)

        返回 0 表示无数据。
        """
        if not self._intervals:
            return 0.0
        return self._intervals[
            self._randint(0, len(self._intervals) - 1)
        ]

    def has_data(self) -> bool:
        """是否有包大小数据"""
        return self._packet_total > 200  # 至少 200 个样本

    def has_interval_data(self) -> bool:
        """是否有间隔数据"""
        return len(self._intervals) >= 10

    # ------------------------------------------------------------------
    # 统计信息
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """返回当前分布快照"""
        if self._packet_total == 0:
            return {"status": "empty", "packets": 0}

        # 计算几个关键百分位
        arr = sorted(self._packet_bytes)
        return {
            "status": "active",
            "packets": len(arr),
            "intervals": len(self._intervals),
            "p50": arr[len(arr) // 2] if arr else 0,
            "p95": arr[int(len(arr) * 0.95)] if arr else 0,
            "p99": arr[int(len(arr) * 0.99)] if arr else 0,
            "min": min(arr) if arr else 0,
            "max": max(arr) if arr else 0,
        }

    # ------------------------------------------------------------------
    # CSPRNG 随机 (与 packet_builder 一致)
    # ------------------------------------------------------------------

    @staticmethod
    def _randint(min_v: int, max_v: int) -> int:
        import os
        span = max_v - min_v + 1
        if span <= 0:
            return min_v
        num_bytes = (span.bit_length() + 7) // 8
        mask = (1 << (num_bytes * 8)) - 1
        while True:
            val = int.from_bytes(os.urandom(num_bytes), "big") & mask
            if val < span:
                return min_v + val

    @staticmethod
    def _randfloat() -> float:
        import os
        return int.from_bytes(os.urandom(7), "big") / (1 << 56)
