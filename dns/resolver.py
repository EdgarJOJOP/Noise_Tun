"""DNS-over-HTTPS 解析器 — 支持 IPv4 + IPv6 分开查询"""

import asyncio
import logging
import time
from collections import OrderedDict
from typing import List, Optional, Tuple

import httpx

logger = logging.getLogger("noisetunnel.dns")

# 压制 httpx/httpcore 的 INFO 级噪音日志（每个 DoH 请求刷一行）
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# 最大缓存条目，超限后按 LRU 淘汰
_MAX_CACHE_SIZE = 500


class DoHResolver:
    """
    DNS-over-HTTPS 解析器

    通过加密 DNS 查询解析域名，同时获取 IPv4 和 IPv6 地址。
    支持主 DoH + 备用 DoH 双配置。
    """

    def __init__(self, doh_url: str = "https://cloudflare-dns.com/dns-query",
                 fallback_doh_url: str = "",
                 timeout: float = 5.0,
                 cache_ttl: int = 300,
                 cache_enabled: bool = True):
        self.doh_url = doh_url
        self.fallback_doh_url = fallback_doh_url
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_enabled = cache_enabled
        # 缓存: domain -> ((ipv4_list, ipv6_list), expiry)
        # OrderedDict 实现 LRU: 超限时淘汰最早写入的条目
        self._cache: OrderedDict[str, tuple[tuple[List[str], List[str]], float]] = OrderedDict()
        self._client: Optional[httpx.AsyncClient] = None

    async def ensure_client(self):
        """确保 HTTP 客户端已初始化（不走系统代理，使用自定连接）"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "NoiseTunnel/1.0",
                },
                # ★ 不走系统代理（DoH 是内部加密 DNS，不应经过 SOCKS5 代理）
                proxy=None,
                # ★ 允许自签名证书（用户可能使用自建 DoH 服务器）
                verify=False,
            )

    async def _do_query(self, url: str, domain: str, qtype: str) -> tuple:
        """向指定 DoH URL 发起一次查询，返回 (v4_list, v6_list)"""
        params = {"name": domain, "type": qtype, "do": "true"}
        response = await self._client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        v4_list: list[str] = []
        v6_list: list[str] = []

        if "Answer" in data:
            for ans in data["Answer"]:
                t = ans.get("type")
                if t in (1, "A", "1"):
                    v4_list.append(ans["data"])
                elif t in (28, "AAAA", "28"):
                    v6_list.append(ans["data"])
        return v4_list, v6_list

    async def resolve(self, domain: str) -> tuple[List[str], List[str]]:
        """
        异步解析域名，同时获取 IPv4 和 IPv6 地址

        先查主 DoH，如果无结果或失败且有备用 DoH URL 则自动切换。

        返回:
            (ipv4_list, ipv6_list)
        """
        now = time.time()
        if self.cache_enabled and domain in self._cache:
            (v4, v6), expiry = self._cache[domain]
            if now < expiry:
                return v4, v6

        await self.ensure_client()

        urls_to_try = [self.doh_url]
        if self.fallback_doh_url:
            urls_to_try.append(self.fallback_doh_url)

        all_v4: list[str] = []
        all_v6: list[str] = []

        for url in urls_to_try:
            try:
                # 先查 AAAA
                v4, v6 = await self._do_query(url, domain, "AAAA")
                all_v4.extend(v4); all_v6.extend(v6)

                # 再查 A（如果 AAAA 没返回 A 记录）
                if not all_v4:
                    v4, _ = await self._do_query(url, domain, "A")
                    all_v4.extend(v4)

                if all_v4 or all_v6:
                    break  # 有结果了，不再尝试下一个 URL
                logger.debug(f"DoH {url} 解析 {domain} 无结果"
                             f"{', 尝试备用' if url != urls_to_try[-1] else ''}")
            except Exception as e:
                logger.warning(f"DoH {url} 解析 {domain} 失败: {e}"
                               f"{', 尝试备用' if url != urls_to_try[-1] else ''}")

        # 缓存结果（cache_enabled=false 时不缓存，每次都查 DoH）
        if self.cache_enabled:
            ttl = self.cache_ttl
            if domain in self._cache:
                self._cache.move_to_end(domain)
            self._cache[domain] = ((all_v4, all_v6), now + ttl)
            while len(self._cache) > _MAX_CACHE_SIZE:
                self._cache.popitem(last=False)

        logger.debug(f"DoH 解析 {domain}: IPv4={all_v4}, IPv6={all_v6}")
        return all_v4, all_v6

    async def close(self):
        """关闭 HTTP 客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
