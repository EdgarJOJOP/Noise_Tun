"""自适应噪声密度控制器

监测真实流量速率，动态调整噪声注入密度。
"""

import time
import logging
from collections import deque
from typing import Optional

logger = logging.getLogger("noisetunnel.density")


class TrafficState:
    """实时流量状态"""

    def __init__(self, connections: int = 0, rate: float = 0.0,
                 is_silent: bool = True, silence_duration: float = 0.0):
        self.connections = connections  # 窗口内连接数
        self.rate = rate                # 连接速率（连接/秒）
        self.is_silent = is_silent      # 是否处于静默状态
        self.silence_duration = silence_duration  # 已持续静默秒数

    def __repr__(self):
        return (f"TrafficState(conn={self.connections}, "
                f"rate={self.rate:.1f}/s, "
                f"silent={self.is_silent}, "
                f"silence_dur={self.silence_duration:.1f}s)")


class AdaptiveDensityController:
    """
    自适应噪声密度控制器

    核心策略：
    ├── 真实流量高（>10 连接/秒）→ 噪声密度 20%，融入真实流
    ├── 真实流量低（1-10 连接/秒）→ 噪声密度 50%，防止"静默指纹"
    └── 完全静默（0 连接/秒，持续 >5s）→ 低密度心跳 10%，模拟后台应用活动
    """

    def __init__(self,
                 window_seconds: float = 10.0,
                 high_threshold: int = 10,
                 low_threshold: int = 1,
                 silence_seconds: float = 5.0,
                 high_density: float = 0.20,
                 low_density: float = 0.50,
                 silence_density: float = 0.10):
        """
        参数:
            window_seconds: 滑动窗口大小（秒）
            high_threshold: 高流量阈值（连接数/窗口）
            low_threshold: 低流量阈值
            silence_seconds: 判定静默的持续秒数
            high_density: 高流量时噪声密度
            low_density: 低流量时噪声密度
            silence_density: 静默时噪声密度（心跳）
        """
        self.window_seconds = window_seconds
        self.high_threshold = high_threshold
        self.low_threshold = low_threshold
        self.silence_seconds = silence_seconds
        self.high_density = high_density
        self.low_density = low_density
        self.silence_density = silence_density

        # 连接时间戳滑动窗口
        self._connection_times: deque = deque()
        # 最后一次有流量的时间
        self._last_activity_time: Optional[float] = None

    def record_connection(self):
        """记录一次真实连接"""
        now = time.time()
        self._connection_times.append(now)
        self._last_activity_time = now
        # 清理窗口外的旧记录
        cutoff = now - self.window_seconds
        while self._connection_times and self._connection_times[0] < cutoff:
            self._connection_times.popleft()

    def get_state(self) -> TrafficState:
        """获取当前流量状态"""
        now = time.time()
        cutoff = now - self.window_seconds

        # 清理过期记录
        while self._connection_times and self._connection_times[0] < cutoff:
            self._connection_times.popleft()

        conn_count = len(self._connection_times)
        rate = conn_count / self.window_seconds if self.window_seconds > 0 else 0

        # 计算静默状态
        is_silent = False
        silence_duration = 0.0
        if self._last_activity_time is not None:
            silence_duration = now - self._last_activity_time
            is_silent = silence_duration >= self.silence_seconds
        else:
            is_silent = True
            silence_duration = float("inf")

        return TrafficState(
            connections=conn_count,
            rate=rate,
            is_silent=is_silent,
            silence_duration=silence_duration
        )

    def get_density(self) -> float:
        """
        根据当前流量状态计算噪声密度
        返回 0.0 ~ 1.0 的密度值
        """
        state = self.get_state()

        # 静默 → 低密度心跳
        if state.is_silent:
            density = self.silence_density
            logger.debug(f"密度决策: 静默({state.silence_duration:.1f}s) → {density:.0%} 心跳")
            return density

        if state.rate >= self.high_threshold:
            density = self.high_density
            logger.debug(f"密度决策: 高流量({state.connections} 连接/{self.window_seconds}s) → {density:.0%}")
            return density
        elif state.rate >= self.low_threshold:
            density = self.low_density
            logger.debug(f"密度决策: 低流量({state.connections} 连接/{self.window_seconds}s) → {density:.0%}")
            return density
        else:
            # 接近静默但还未判定为静默 → 用低密度
            density = self.silence_density
            logger.debug(f"密度决策: 极低流量 → {density:.0%}")
            return density

    @property
    def inject_interval_min(self) -> float:
        """最小注入间隔（秒）"""
        density = self.get_density()
        if density <= 0:
            return float("inf")
        # 密度越高，间隔越短
        return max(0.1, (1.0 - density) * 3.0)

    @property
    def inject_interval_max(self) -> float:
        """最大注入间隔（秒）"""
        density = self.get_density()
        if density <= 0:
            return float("inf")
        return max(0.3, (1.0 - density) * 6.0)
