"""假域名生成器 — 为 TLS SNI 生成随机但逼真的假域名"""

import random
import logging
from typing import List

logger = logging.getLogger("noisetunnel.fake_sni")

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
        if random.random() < 0.5:
            name = random.choice(WORDS)
        else:
            parts = random.sample(WORDS, random.randint(2, 3))
            name = "-".join(parts)

        tld = random.choice(TLDS)
        if random.random() < 0.3:
            name += str(random.randint(0, 999))

        return name + tld

    def generate_batch(self, count: int) -> List[str]:
        """生成一批不重复的假域名"""
        domains = set()
        while len(domains) < count:
            domains.add(self.generate())
        return list(domains)
