"""随机域名池 — 提供噪声流量的目标域名"""

import random
import logging
from typing import List

logger = logging.getLogger("noisetunnel.domain_pool")

# 预置热门域名（来自 Alexa Top 等，作为种子）
PRE_SEED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
    "reddit.com", "netflix.com", "github.com", "stackoverflow.com",
    "microsoft.com", "apple.com", "cloudflare.com", "adobe.com",
    "bing.com", "live.com", "office.com", "whatsapp.com",
    "zoom.us", "spotify.com", "telegram.org", "discord.com",
    "twitch.tv", "aliexpress.com", "paypal.com", "ebay.com",
    "imdb.com", "cnn.com", "bbc.com", "nytimes.com",
    "dropbox.com", "notion.so", "figma.com", "vercel.com",
    "python.org", "npmjs.com", "docker.com", "kubernetes.io",
]

# 常见 TLD
TLDS = [".com", ".org", ".net", ".io", ".app", ".dev",
        ".co", ".info", ".me", ".cloud", ".tech", ".online"]

# 常见词汇片段（用于生成逼真的随机域名）
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
]


class DomainPool:
    """
    随机域名池

    提供用于噪声流量的目标域名，支持：
    - 从预置池中随机选取
    - 动态生成随机但逼真的域名
    - 域名 LRU 淘汰
    """

    def __init__(self, pool_size: int = 200):
        self.pool_size = pool_size
        self._domains: List[str] = []
        self._init_pool()

    def _init_pool(self):
        """初始化域名池"""
        # 填入预置域名
        self._domains = list(PRE_SEED_DOMAINS)
        # 补充随机生成
        while len(self._domains) < self.pool_size:
            self._domains.append(self._generate_random_domain())
        logger.info(f"域名池初始化完成: {len(self._domains)} 个域名")

    def get_random(self) -> str:
        """从池中随机选取一个域名"""
        return random.choice(self._domains)

    def get_batch(self, count: int) -> List[str]:
        """获取一批随机域名（不重复）"""
        return random.sample(self._domains, min(count, len(self._domains)))

    def refresh(self):
        """刷新池中的一部分域名"""
        refresh_count = max(1, self.pool_size // 10)
        for i in range(refresh_count):
            idx = random.randrange(len(self._domains))
            self._domains[idx] = self._generate_random_domain()

    def _generate_random_domain(self) -> str:
        """生成随机但逼真的域名"""
        # 50% 概率用单段，50% 用多段
        if random.random() < 0.5:
            name = random.choice(WORDS)
        else:
            parts = random.sample(WORDS, random.randint(2, 3))
            name = "-".join(parts)

        tld = random.choice(TLDS)
        # 偶尔加数字后缀
        if random.random() < 0.3:
            name += str(random.randint(0, 999))

        return name + tld
