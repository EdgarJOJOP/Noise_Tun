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
        # ★ 容错：连续失败计数 & 自动重建 httpx 客户端
        #   解决 DoH 服务重启后连接池失效的问题
        self._failed_attempts: int = 0
        self._max_failures: int = 3
        self._last_success_time: float = 0
        # ★ 重建冷却期：每次重建后至少等待 _recreate_cooldown 秒才再次重建
        self._last_recreate_time: float = 0
        self._recreate_cooldown: float = 60.0

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
        for attempt in range(2):
            try:
                response = await self._client.get(url, params=params)
                response.raise_for_status()
                break  # 成功
            except Exception as e:
                if attempt == 0 and "400" in str(e):
                    # 尝试1: 去掉 do=true (某些服务器不支持 DNSSEC)
                    params = {"name": domain, "type": qtype}
                    continue
                elif attempt == 1 and "400" in str(e) and "/dns-query" in url:
                    # 尝试2: 某些服务器(阿里/DNSPod)使用 /resolve 而非 /dns-query
                    alt_url = url.replace("/dns-query", "/resolve")
                    params = {"name": domain, "type": qtype}
                    try:
                        response = await self._client.get(alt_url, params=params)
                        response.raise_for_status()
                        break
                    except Exception:
                        pass
                raise  # 所有尝试都失败了
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
        had_connection_error = False  # ★ 区分真正的连接失败 vs 解析成功但无结果

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
                had_connection_error = True  # ★ 只有走到这里才是真正的连接失败
                err_msg = repr(e) if not str(e).strip() else e
                logger.warning(f"DoH {url} 解析 {domain} 失败: {err_msg}"
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
        # ★ 记录成功/失败，触发容错（只将真正的连接失败计入失败计数）
        #   域名正常解析但无记录（如 data.bilibili.com 无 A/AAAA）不算失败
        if all_v4 or all_v6:
            self._record_success()
        elif had_connection_error:
            await self._record_failure()
        # 请求成功但域名无记录 → 不算故障，不计失败计数

        return all_v4, all_v6

    async def _recreate_client(self):
        """关闭旧 httpx 客户端并重建（解决 DoH 服务重启后连接池失效问题）
        先创建新客户端再替换 self._client，消除并发协程访问 None 的竞态条件。
        """
        # 先创建新客户端，确保 self._client 不会出现 None
        old_client = self._client
        try:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "NoiseTunnel/1.0",
                },
                proxy=None,
                verify=False,
            )
            self._last_recreate_time = time.time()
            self._failed_attempts = 0
            logger.info("DoH HTTP 客户端已重建，将使用新连接")
        except Exception as e:
            # 创建新客户端失败，恢复旧客户端
            self._client = old_client
            logger.error(f"重建 HTTP 客户端失败: {e}")
            return
        # 最后关闭旧客户端，不影响正在使用旧客户端的请求
        if old_client:
            try:
                await old_client.aclose()
            except Exception:
                pass

    def _record_success(self):
        """记录一次成功解析，重置失败计数"""
        self._failed_attempts = 0
        self._last_success_time = time.time()

    async def _record_failure(self):
        """记录一次解析失败，达到阈值且冷却期已过时自动重建 HTTP 客户端"""
        self._failed_attempts += 1
        if self._failed_attempts >= self._max_failures:
            # 检查冷却期：距离上次重建不足 cooldown 秒则不重建，仅重置计数
            now = time.time()
            if now - self._last_recreate_time < self._recreate_cooldown:
                logger.warning(
                    f"DoH 连续失败 {self._failed_attempts} 次，但距上次重建仅 "
                    f"{now - self._last_recreate_time:.0f}s < 冷却期 "
                    f"{self._recreate_cooldown:.0f}s，跳过重建"
                )
                self._failed_attempts = 0
                return
            logger.warning(
                f"DoH 连续失败 {self._failed_attempts} 次，重建 HTTP 客户端"
            )
            await self._recreate_client()

    @property
    def is_healthy(self) -> bool:
        """检测 DoH 是否健康（连续失败未超阈值）"""
        return self._failed_attempts < self._max_failures

    async def close(self):
        """关闭 HTTP 客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
