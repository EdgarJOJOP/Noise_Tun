"""时序混淆器 — 用真实 RTT 分布调制噪声发送间隔"""

import time
import logging
import math
from collections import deque
from typing import Optional

from noise.packet_builder import randint, randfloat

logger = logging.getLogger("noisetunnel.timing")


class RTTMonitor:
    """
    真实流量 RTT 采样器

    从 TCP 连接耗时中采集 RTT 样本，形成经验分布。
    用于生成与真实网络特征一致的噪声发送间隔。
    """

    def __init__(self, max_samples: int = 200):
        self.max_samples = max_samples
        self._samples: deque[float] = deque(maxlen=max_samples)
        # 内置保底分布（典型互联网 RTT: 20-200ms）
        self._fallback_min = 0.020
        self._fallback_max = 0.200

    def record_rtt(self, rtt_seconds: float):
        """记录一个 RTT 样本（来自 TCP 连接耗时）"""
        if 0.001 <= rtt_seconds <= 10.0:
            self._samples.append(rtt_seconds)

    def get_sample_rtt(self) -> float:
        """从经验分布中随机取一个 RTT 值"""
        if self._samples:
            return self._samples[randint(0, len(self._samples) - 1)]
        # 无样本时回退：对数均匀分布 20-200ms
        log_min = math.log(self._fallback_min)
        log_max = math.log(self._fallback_max)
        return math.exp(log_min + randfloat() * (log_max - log_min))

    def get_stats(self) -> dict:
        """返回当前 RTT 统计"""
        if not self._samples:
            return {"min": 0, "max": 0, "avg": 0, "count": 0}
        arr = list(self._samples)
        return {
            "min": min(arr),
            "max": max(arr),
            "avg": sum(arr) / len(arr),
            "p50": sorted(arr)[len(arr)//2],
            "count": len(arr),
        }


class TimingShaper:
    """
    噪声发送时序整形器

    核心思想：
    噪声不以恒定概率随机间隔发送，而是以真实 RTT 为基频，叠加：
    - RTT 抖动（模仿网络延迟变化）
    - burst-pause 模式（模仿 TCP 拥塞窗口行为）
    - 应用层思考间隙（模拟用户阅读/观看行为）
    """

    def __init__(self, rtt_monitor: RTTMonitor):
        self.rtt = rtt_monitor
        self._in_burst = False
        self._burst_remaining = 0
        self._pause_until = 0.0

    def next_interval(self, density: float) -> float:
        """
        返回下次发送的等待秒数

        参数:
            density: 当前噪声密度 (0.0 ~ 1.0)
        """
        now = time.time()

        # 1) burst 模式：连续发送多个包
        if self._in_burst:
            if self._burst_remaining > 0:
                self._burst_remaining -= 1
                base_rtt = self.rtt.get_sample_rtt()
                return base_rtt * (0.3 + randfloat() * 0.7)
            else:
                # burst 结束，进入 pause
                self._in_burst = False
                pause_dur = self.rtt.get_sample_rtt() * randint(5, 20)
                self._pause_until = now + pause_dur
                return pause_dur

        # 2) pause 中
        if now < self._pause_until:
            remaining = self._pause_until - now
            if remaining > 0:
                return min(remaining, 0.5)

        # 3) 开始新 burst
        self._in_burst = True
        burst_size = max(1, int(density * randint(3, 12)))
        self._burst_remaining = burst_size

        base_rtt = self.rtt.get_sample_rtt()
        modulated = base_rtt * (1.0 + (1.0 - density) * randint(2, 8))
        return max(0.010, modulated)

    def maybe_insert_think_gap(self) -> float:
        """
        模拟用户思考/阅读间隙（约 5% 概率触发）
        返回额外等待秒数，0 表示不插入
        """
        if randint(0, 100) >= 5:
            return 0.0
        gap = 1.0 + randfloat() * 14.0
        logger.debug(f"插入思考间隙: {gap:.1f}s")
        return gap
