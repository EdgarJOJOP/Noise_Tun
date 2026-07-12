"""DNS-over-HTTPS 解析器 — 支持 IPv4 + IPv6 分开查询"""

import asyncio
import logging
import time
from collections import OrderedDict
from typing import List, Optional, Tuple

import httpx

logger = logging.getLogger("noisetunnel.dns")

# 最大缓存条目，超限后按 LRU 淘汰
_MAX_CACHE_SIZE = 500


class DoHResolver:
    """
    DNS-over-HTTPS 解析器

    通过加密 DNS 查询解析域名，同时获取 IPv4 和 IPv6 地址。
    """

    def __init__(self, doh_url: str = "https://cloudflare-dns.com/dns-query",
                 timeout: float = 5.0,
                 cache_ttl: int = 300):
        self.doh_url = doh_url
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        # 缓存: domain -> ((ipv4_list, ipv6_list), expiry)
        # OrderedDict 实现 LRU: 超限时淘汰最早写入的条目
        self._cache: OrderedDict[str, tuple[tuple[List[str], List[str]], float]] = OrderedDict()
        self._client: Optional[httpx.AsyncClient] = None

    async def ensure_client(self):
        """确保 HTTP 客户端已初始化"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "NoiseTunnel/1.0",
                }
            )

    async def resolve(self, domain: str) -> tuple[List[str], List[str]]:
        """
        异步解析域名，同时获取 IPv4 和 IPv6 地址

        返回:
            (ipv4_list, ipv6_list)
        """
        now = time.time()
        if domain in self._cache:
            (v4, v6), expiry = self._cache[domain]
            if now < expiry:
                return v4, v6

        await self.ensure_client()

        try:
            # 先查 AAAA（IPv6），Cloudflare 响应常同时包含 A 记录
            params = {
                "name": domain,
                "type": "AAAA",
                "do": "true",
            }
            response = await self._client.get(self.doh_url, params=params)
            response.raise_for_status()
            data = response.json()

            v4_list: list[str] = []
            v6_list: list[str] = []

            if "Answer" in data:
                for ans in data["Answer"]:
                    if ans.get("type") == 1:   # A (IPv4)
                        v4_list.append(ans["data"])
                    elif ans.get("type") == 28:  # AAAA (IPv6)
                        v6_list.append(ans["data"])

            # 如果没拿到 A 记录，单独查一次 A
            if not v4_list:
                params["type"] = "A"
                response = await self._client.get(self.doh_url, params=params)
                response.raise_for_status()
                data = response.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        if ans.get("type") == 1:
                            v4_list.append(ans["data"])

            # 缓存
            ttl = self.cache_ttl
            if "Answer" in data and data["Answer"]:
                ttl = min(self.cache_ttl, data["Answer"][0].get("TTL", self.cache_ttl))

            # 缓存（带 LRU 淘汰）
            if domain in self._cache:
                self._cache.move_to_end(domain)
            self._cache[domain] = ((v4_list, v6_list), now + ttl)
            # 超限淘汰最旧条目
            while len(self._cache) > _MAX_CACHE_SIZE:
                self._cache.popitem(last=False)
            logger.debug(f"DoH 解析 {domain}: IPv4={v4_list}, IPv6={v6_list}")
            return v4_list, v6_list

        except Exception as e:
            logger.debug(f"DoH 解析 {domain} 失败: {e}")
            if domain in self._cache:
                return self._cache[domain][0]
            return [], []

    async def close(self):
        """关闭 HTTP 客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
