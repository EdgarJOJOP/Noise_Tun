"""假域名生成器 — 为 TLS SNI 生成随机但逼真的假域名 (CSPRNG)"""

import os
import logging
from typing import List

logger = logging.getLogger("noisetunnel.fake_sni")

# CSPRNG 工具
def _randint(min_v, max_v):
    span = max_v - min_v + 1
    if span <= 0:
        return min_v
    num_bytes = (span.bit_length() + 7) // 8
    mask = (1 << (num_bytes * 8)) - 1
    while True:
        val = int.from_bytes(os.urandom(num_bytes), "big") & mask
        if val < span:
            return min_v + val

def _randfloat():
    return int.from_bytes(os.urandom(7), "big") / (1 << 56)

def _choice(seq):
    if not seq:
        raise IndexError("empty sequence")
    return seq[_randint(0, len(seq) - 1)]

def _sample(population, k):
    return [population[_randint(0, len(population) - 1)] for _ in range(k)]

# 常见 TLD
TLDS = [".com", ".org", ".net", ".io", ".app", ".dev",
        ".co", ".info", ".me", ".cloud", ".tech", ".online"]

# 词汇片段（用于生成逼真的随机域名）
WORDS = [
    "api", "cdn", "static", "assets", "media", "img", "video",
    "blog", "docs", "help", "support", "status", "portal",
    "app", "web", "mail", "auth", "login", "account",
    "search", "cloud", "data", "edge", "core", "hub",
    "alpha", "beta", "gamma", "delta", "omega", "nova",
    "sky", "star", "moon", "sun", "wave", "flow", "peak",
    "go", "run", "get", "set", "try", "use", "find",
    "fast", "safe", "secure", "quick", "smart", "pure",
    "one", "two", "hub", "lab", "box", "net", "pro",
    "svc", "worker", "proxy", "gateway", "backend", "frontend",
]


class FakeSNIGenerator:
    """
    生成随机但逼真的假域名，用于填入噪声 TLS CH 的 SNI 扩展
    """

    def generate(self) -> str:
        """生成一个随机假域名"""
        if _randfloat() < 0.5:
            name = _choice(WORDS)
        else:
            parts = _sample(WORDS, _randint(2, 3))
            name = "-".join(parts)

        tld = _choice(TLDS)
        if _randfloat() < 0.3:
            name += str(_randint(0, 999))

        return name + tld

    def generate_batch(self, count: int) -> List[str]:
        """生成一批不重复的假域名"""
        domains = set()
        while len(domains) < count:
            domains.add(self.generate())
        return list(domains)
