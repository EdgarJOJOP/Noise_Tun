"""统一噪声注入器 — 同域名同协议族选不同 IP 发噪声（UDP/TCP 双协议）"""

import asyncio
import logging
import struct
import time
import ipaddress
from collections import OrderedDict
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from noise.traffic_profile import TrafficProfile

from noise.packet_builder import randint, randchoice, randfloat

from noise.tcp_noise import TCPNoisePacketGenerator
from noise.udp_noise import UDPNoisePacketGenerator
from noise.raw_socket import RawInjector
from dns.resolver import DoHResolver
from dns.fake_sni import FakeSNIGenerator
from .density import AdaptiveDensityController
from .timing import RTTMonitor, TimingShaper
from dns.domain_pool import DomainPool

logger = logging.getLogger("noisetunnel.injector")


class _ResolvedDomain:
    """一个域名解析后的结果"""
    __slots__ = ("domain", "ipv4", "ipv6", "resolved_time")

    def __init__(self, domain: str, ipv4: list[str], ipv6: list[str]):
        self.domain = domain
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.resolved_time = time.time()


class _RealTarget:
    """一次真实流量的记录"""
    __slots__ = ("domain", "used_ip", "port", "family", "timestamp")

    def __init__(self, domain: str, used_ip: str, port: int):
        self.domain = domain
        self.used_ip = used_ip
        self.port = port
        self.family = 6 if ":" in used_ip else 4
        self.timestamp = time.time()


def _ip_family(ip: str) -> int:
    return 6 if ":" in ip else 4


class NoiseInjector:
    """
    噪声注入器 — 从真实流量提取目标

    核心策略:
    1. 用户访问 example.com:443 -> SOCKS5 解析到 1.2.3.4 (IPv4)
    2. 记录: domain=example.com, used_ip=1.2.3.4, port=443, family=4
    3. DoH 解析 example.com -> IPv4=[1.2.3.4, 5.6.7.8], IPv6=[2606::1]
    4. TCP 噪声 -> 选同域名同协议族其他 IP(5.6.7.8):443
    5. UDP 噪声 -> 从 UDP raw socket 捕获的真实目标中选，同端口不同 IP
    6. TCP 噪声含假 SNI(不是 example.com)
    """

    def __init__(self,
                 density_controller: AdaptiveDensityController,
                 doh_resolver: DoHResolver,
                 fake_sni_gen: FakeSNIGenerator,
                 tcp_generator: Optional[TCPNoisePacketGenerator] = None,
                 udp_generator: Optional[UDPNoisePacketGenerator] = None,
                 domain_pool_size: int = 500,
                 noise_doh_resolver: Optional[DoHResolver] = None):
        self.density = density_controller
        self.doh = doh_resolver
        self._noise_doh = noise_doh_resolver  # ★ 噪声专用 DoH（无域名拦截）
        self.sni_gen = fake_sni_gen
        self.tcp_gen = tcp_generator or TCPNoisePacketGenerator()
        self.udp_gen = udp_generator or UDPNoisePacketGenerator()

        self._raw_injector = RawInjector()
        self._profile: Optional['TrafficProfile'] = None

        self._real_targets: list[_RealTarget] = []
        self._resolved: dict[str, _ResolvedDomain] = {}
        self._last_resolve_time: float = 0

        self._target_ttl: float = 600.0
        self._resolve_interval: float = 300.0
        self._max_real_targets: int = 50

        # 全局 IP 池 (Risk 3): 所有已解析域名的全部 IP + DomainPool 批量解析
        self._global_ip_pool: dict[str, set[str]] = {}  # ip -> {domain1, domain2, ...}
        # ★ 噪声专用 IP 池：用噪声 DoH 解析 domain_sources/DomainPool 得到的 IP
        #   完全隔离，不参与 _max_real_targets / _global_ip_pool 的大小统计
        #   仅用于发噪声包，不进入 domain_pool_size 等统计
        self._noise_only_ip_pool: dict[str, set[str]] = {}
        self._domain_pool = DomainPool(pool_size=domain_pool_size)
        self._last_pool_resolve_time: float = 0
        self._pool_resolve_interval: float = 60.0        # 每分钟解析一批

        # 冷启动 fallback (仅前 30 秒使用)
        self._startup_time: float = time.time()
        self._startup_duration: float = 30.0
        self._fallback_targets: list[tuple[str, int]] = [
            ("1.1.1.1", 443), ("8.8.8.8", 443),
            ("1.1.1.1", 53), ("8.8.8.8", 53),
        ]

        self._running = False
        self._tasks: list[asyncio.Task] = []

        # 时序混淆
        self._rtt_monitor = RTTMonitor()
        self._timing_shaper = TimingShaper(self._rtt_monitor)

        # 应用层噪声生成器（延迟导入）
        self._quic_gen = None
        self._http2_gen = None
        self._ws_gen = None

        # curl_cffi 真实连接噪声 (解决"只发不收"问题)
        self._curl_session = None        # AsyncSession 实例
        self._curl_available = None      # None=未检查, False=不可用, True=可用

        # Metric 计数器
        self._real_conn_count = 0        # 真实连接数
        self._noise_pkt_count = 0        # 噪声注入次数

        # 批量解析追踪
        self._resolved_domains_cache: set[str] = set()
        self._batch_resolve_sem = asyncio.Semaphore(20)  # 并发 20

        # ★ 近期真实流量 IP 排除集（60 秒内不用这些 IP 发噪声，避免自干扰）
        self._recent_real_ips: dict[str, float] = {}   # ip -> timestamp
        self._real_ip_exclude_ttl: float = 60.0

        # ★ DoH 健康状态追踪：DoH 持续不可用时暂停噪声注入
        self._doh_unhealthy_since: Optional[float] = None
        self._doh_pause_threshold: float = 30.0     # DoH 不可用超过 30 秒则暂停噪声
        self._noise_paused: bool = False

    def get_real_conn_count(self) -> int:
        return self._real_conn_count

    def get_noise_pkt_count(self) -> int:
        return self._noise_pkt_count

    def _lazy_init_app_noise(self):
        if self._quic_gen is None:
            from noise.quic_noise import QUICNoiseGenerator
            from noise.http2_noise import HTTP2NoiseGenerator
            from noise.websocket_noise import WebSocketNoiseGenerator
            self._quic_gen = QUICNoiseGenerator()
            self._http2_gen = HTTP2NoiseGenerator()
            self._ws_gen = WebSocketNoiseGenerator()

    async def _ensure_curl(self):
        """延迟初始化 curl_cffi AsyncSession (用于真实 TLS 连接噪声)"""
        if self._curl_available is not None:
            return  # 已检查过
        try:
            from curl_cffi import AsyncSession
            self._curl_session = AsyncSession(
                impersonate="chrome",
                timeout=10.0,
                verify=False,          # 目标 IP 无有效证书
                proxy=None,            # 不经过本机代理
            )
            self._curl_available = True
            logger.info("curl_cffi 真实连接噪声就绪 (50% TCP 噪声走真实 TLS)")
        except ImportError:
            self._curl_available = False
            logger.info("curl_cffi 未安装, TCP 噪声全部使用假包")
        except Exception as e:
            self._curl_available = False
            logger.warning(f"curl_cffi 初始化失败: {e}, 使用假包降级")

    def set_traffic_profile(self, profile: 'TrafficProfile'):
        """设置真实流量分布采集器"""
        self._profile = profile

    def set_domain_source_urls(self, urls: list[str]):
        """设置域名源 URL 列表 (来自 config.yaml)"""
        self._domain_source_urls = urls

    def set_fetch_interval(self, interval: int):
        """设置域名抓取间隔 (秒), 默认 86400"""
        self._fetch_interval = interval

    async def start(self):
        self._running = True
        self._loop = asyncio.get_event_loop()
        # 初始化 RawInjector
        await self._raw_injector.start()
        self._lazy_init_app_noise()
        self._tasks = [
            asyncio.create_task(self._inject_loop("tcp")),
            asyncio.create_task(self._inject_loop("udp")),
            asyncio.create_task(self._resolve_loop()),
        ]
        logger.info("噪声注入器已启动 (UDP/TCP 双协议 + 时序混淆 + 应用层噪声)")

    async def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self._raw_injector.stop()
        logger.info("噪声注入器已停止")

    # ------------------------------------------------------------------
    # 真实流量记录
    # ------------------------------------------------------------------

    def record_real_connection(self, domain: str, resolved_ip: str,
                               port: int, protocol: str):
        """记录一次真实连接（TCP 和 UDP 均记录）"""
        self._real_conn_count += 1
        self.density.record_connection()

        # 修复：不再限制 protocol == "tcp"
        if domain and port:
            now = time.time()
            self._real_targets = [
                t for t in self._real_targets
                if not (t.domain == domain and t.used_ip == resolved_ip
                        and t.port == port and t.family == _ip_family(resolved_ip))
            ]
            self._real_targets.append(_RealTarget(domain, resolved_ip, port))
            if len(self._real_targets) > self._max_real_targets:
                self._real_targets = self._real_targets[-self._max_real_targets:]
            logger.debug(f"真实流量[{protocol.upper()}]: {domain} "
                         f"({resolved_ip}:{port}, IPv{_ip_family(resolved_ip)})")

            # ★ 记录此 IP 为"近期正在使用"，噪声选择时排除
            self._recent_real_ips[resolved_ip] = time.time()

    def record_real_udp_target(self, dst_ip: str, dst_port: int):
        """从 UDPSampler 捕获的真实 UDP 包中提取目标"""
        if not dst_ip or not dst_port:
            return
        pseudo_domain = f"{dst_ip}:{dst_port}"
        now = time.time()
        self._real_targets = [
            t for t in self._real_targets
            if not (t.domain == pseudo_domain and t.used_ip == dst_ip
                    and t.port == dst_port)
        ]
        self._real_targets.append(_RealTarget(pseudo_domain, dst_ip, dst_port))
        if len(self._real_targets) > self._max_real_targets:
            self._real_targets = self._real_targets[-self._max_real_targets:]
        logger.debug(f"UDP 真实目标: {dst_ip}:{dst_port}")
        self._recent_real_ips[dst_ip] = time.time()

    @property
    def rtt_monitor(self):
        return self._rtt_monitor

    # ------------------------------------------------------------------
    # 后台解析
    # ------------------------------------------------------------------

    async def _resolve_loop(self):
        while self._running:
            try:
                await self._fetch_live_domains()  # 每日抓取 Cloudflare Radar Top 域名
                await self._resolve_domains()
                await self._resolve_pool_domains()  # Tier 2: 域名池批量解析
                self._cleanup_expired()
                await asyncio.sleep(30.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"解析异常: {e}")
                await asyncio.sleep(10.0)

    async def _resolve_pool_domains(self):
        """从 DomainPool 中批量解析域名, 注入噪声专用 IP 池（不参与全局统计）"""
        now = time.time()
        if now - self._last_pool_resolve_time < self._pool_resolve_interval:
            return
        self._last_pool_resolve_time = now

        resolver = self._noise_doh if self._noise_doh else self.doh
        batch = self._domain_pool.get_batch(10)  # 每次 10 个
        for domain in batch:
            try:
                v4, v6 = await resolver.resolve(domain)
                for ip in (v4 or []) + (v6 or []):
                    self._noise_only_ip_pool.setdefault(ip, set()).add(domain)
            except Exception:
                pass

        # 10% 概率滚动替换域名池中的一部分
        if randfloat() < 0.1:
            self._domain_pool.refresh()

        pool_size = len(self._global_ip_pool) + len(self._noise_only_ip_pool)
        if pool_size > 0:
            logger.info(f"全局 IP 池: {len(self._global_ip_pool)} 个 (真实) + "
                         f"{len(self._noise_only_ip_pool)} 个 (噪声DNS)")

    async def _fetch_live_domains(self):
        """从配置的域名源抓取真实域名，并立即批量并行解析（2s 超时，失败/超时自动丢弃）"""
        # 确保 curl_cffi session 已初始化
        await self._ensure_curl()
        if not self._curl_session:
            return
        now = time.time()
        if now - getattr(self, '_last_fetch_time', 0) < getattr(self, '_fetch_interval', 86400):
            return
        self._last_fetch_time = now

        # 从配置获取 URL 列表
        try:
            urls = self._domain_source_urls
        except AttributeError:
            return

        total_new = 0
        for url in urls:
            try:
                resp = await self._curl_session.get(url, timeout=30.0)
                text = resp.content.decode('utf-8')
                count = 0
                for line in text.splitlines():
                    line = line.strip()
                    # 仅匹配 ||domain.com^ 格式, 不使用 regex
                    if line.startswith('||') and line.endswith('^'):
                        domain = line[2:-1]
                        if domain.count('.') >= 1 and len(domain) < 100:
                            if self._domain_pool.add(domain):
                                count += 1
                total_new += count
                logger.info(f"域名源获取 {count} 个新域名")
            except Exception as e:
                logger.debug(f"域名源 {url[:60]}... 失败: {e}")

        # ★ 抓取后立即批量并行解析新域名（2s 超时，只保留成功的 IP）
        if total_new > 0:
            await self._batch_resolve_new_domains()

    async def _batch_resolve_new_domains(self):
        """批量并行解析域名池中新域名，2s 超时，失败/超时自动丢弃
        主/备用 DoH 同时发起，谁先返回用谁"""
        domains = [d for d in self._domain_pool._domains
                   if d not in self._resolved_domains_cache][:200]
        if not domains:
            return

        async def _resolve_one(domain):
            async with self._batch_resolve_sem:
                # 主 DoH + 备用 DoH 同时发起，谁先返回用谁
                async def _try_doh(doh):
                    try:
                        return await asyncio.wait_for(
                            doh.resolve(domain), timeout=2.0)
                    except:
                        return None, None

                tasks = []
                if self._noise_doh:
                    tasks.append(asyncio.create_task(
                        _try_doh(self._noise_doh)))
                    # 仅当 noise_fallback_doh_url 有配置时才并行尝试备用
                    if self._noise_doh.fallback_doh_url:
                        fb = DoHResolver(
                            doh_url=self._noise_doh.fallback_doh_url,
                            timeout=2.0, cache_enabled=False)
                        tasks.append(asyncio.create_task(
                            _try_doh(fb)))

                if not tasks:
                    return False

                done, pending = await asyncio.wait(
                    tasks, timeout=2.5, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()

                for t in done:
                    v4, v6 = t.result()
                    if v4 or v6:
                        for ip in (v4 or []) + (v6 or []):
                            self._noise_only_ip_pool.setdefault(ip, set()).add(domain)
                        self._resolved_domains_cache.add(domain)
                        return True
                return False

        logger.info(f"批量解析 {len(domains)} 个域名 (2s 超时, 并发 20)...")
        results = await asyncio.gather(*[_resolve_one(d) for d in domains])
        success = sum(1 for r in results if r)
        logger.info(f"批量解析完成: {success}/{len(domains)} 成功, "
                     f"噪声 IP 池: {len(self._noise_only_ip_pool)} 个")

    async def _resolve_domains(self):
        now = time.time()
        if now - self._last_resolve_time < self._resolve_interval:
            return
        self._last_resolve_time = now

        seen_domains: set[str] = set()
        domains_to_resolve: list[str] = []
        for t in sorted(self._real_targets, key=lambda x: x.timestamp, reverse=True):
            if t.domain not in seen_domains:
                seen_domains.add(t.domain)
                domains_to_resolve.append(t.domain)
                if len(domains_to_resolve) >= 5:
                    break

        for domain in domains_to_resolve:
            try:
                v4, v6 = await self.doh.resolve(domain)
                if v4 or v6:
                    self._resolved[domain] = _ResolvedDomain(domain, v4, v6)
                    # 注入全局 IP 池 (IPv4 + IPv6)
                    for ip in (v4 or []) + (v6 or []):
                        self._global_ip_pool.setdefault(ip, set()).add(domain)
                    logger.debug(f"解析 {domain}: IPv4={v4}, IPv6={v6}")
            except Exception as e:
                logger.debug(f"解析 {domain} 失败: {e}")

        if self._resolved:
            sample = list(self._resolved.keys())[:3]
            logger.info(f"已解析域名: {len(self._resolved)} 个 ({sample}...)")

    def _cleanup_expired(self):
        now = time.time()
        self._real_targets = [t for t in self._real_targets
                              if now - t.timestamp < self._target_ttl]
        stale_domains = [d for d, r in self._resolved.items()
                         if now - r.resolved_time > self._target_ttl * 2]
        for d in stale_domains:
            # 从全局 IP 池中移除关联
            if d in self._resolved:
                r = self._resolved[d]
                for ip in (r.ipv4 or []) + (r.ipv6 or []):
                    if ip in self._global_ip_pool:
                        self._global_ip_pool[ip].discard(d)
                        if not self._global_ip_pool[ip]:
                            del self._global_ip_pool[ip]
            del self._resolved[d]

        # 限制全局 IP 池大小
        if len(self._global_ip_pool) > 2000:
            # 保留最新的 2000 个
            self._global_ip_pool = dict(list(self._global_ip_pool.items())[-2000:])

        # ★ 限制噪声专用 IP 池大小（防止无限膨胀，不参与 _max_real_targets 统计）
        if len(self._noise_only_ip_pool) > 2000:
            self._noise_only_ip_pool = dict(list(self._noise_only_ip_pool.items())[-2000:])

        # ★ 清理过期排除 IP（超过 60 秒的移除，下次可再打噪声）
        for ip in list(self._recent_real_ips.keys()):
            if now - self._recent_real_ips[ip] > self._real_ip_exclude_ttl:
                del self._recent_real_ips[ip]

    # ------------------------------------------------------------------
    # 噪声目标选择（Risk 3: 全局 IP 池 + 跨域）
    # ------------------------------------------------------------------

    def _pick_noise_target(self, protocol: str = "tcp"
                           ) -> tuple[Optional[str], Optional[int], Optional[str]]:
        # 冷启动期 (<30s): 使用 fallback
        if time.time() - self._startup_time < self._startup_duration:
            ip, port = randchoice(self._fallback_targets)
            return ip, port, self.sni_gen.generate()

        if protocol == "tcp":
            return self._pick_tcp_noise_target()
        else:
            return self._pick_udp_noise_target()

    def _pick_tcp_noise_target(self):
        # 合并两个 IP 池（真实 DNS + 噪声 DNS）
        combined_pool = {}
        combined_pool.update(self._global_ip_pool)
        combined_pool.update(self._noise_only_ip_pool)

        # ★ 排除近期被真实流量使用的 IP（30秒内不重复打同一IP）
        now = time.time()
        exclude_ips = {ip for ip, ts in self._recent_real_ips.items()
                       if now - ts < self._real_ip_exclude_ttl}
        filtered = {ip: domains for ip, domains in combined_pool.items()
                    if ip not in exclude_ips}

        # 70%: 从过滤后的合并池中随机选
        if filtered and randfloat() < 0.7:
            ip = randchoice(list(filtered.keys()))
            port = randchoice([443, 80, 8443, 8080, 53, 22])
            return ip, port, self.sni_gen.generate()

        # 20%: 同域名其他 IP (增强局部真实性，也要排除正在使用的IP)
        for real in reversed(self._real_targets):
            if real.used_ip in exclude_ips:
                continue  # ★ 这个真实目标正在被使用，跳过
            resolved = self._resolved.get(real.domain)
            if not resolved:
                continue
            if real.family == 4 and resolved.ipv4:
                others = [ip for ip in resolved.ipv4
                          if ip != real.used_ip and ip not in exclude_ips]
                if others:
                    return randchoice(others), real.port, self.sni_gen.generate()
            elif real.family == 6 and resolved.ipv6:
                others = [ip for ip in resolved.ipv6
                          if ip != real.used_ip and ip not in exclude_ips]
                if others:
                    return randchoice(others), real.port, self.sni_gen.generate()

        # 10%: fallback
        ip, port = randchoice(self._fallback_targets)
        return ip, port, self.sni_gen.generate()

    def _pick_udp_noise_target(self):
        # 合并两个 IP 池
        combined_pool = {}
        combined_pool.update(self._global_ip_pool)
        combined_pool.update(self._noise_only_ip_pool)

        # ★ 排除近期被真实流量使用的 IP
        now = time.time()
        exclude_ips = {ip for ip, ts in self._recent_real_ips.items()
                       if now - ts < self._real_ip_exclude_ttl}
        filtered = {ip: domains for ip, domains in combined_pool.items()
                    if ip not in exclude_ips}

        # 70%: 过滤后的合并池
        if filtered and randfloat() < 0.7:
            ip = randchoice(list(filtered.keys()))
            port = randchoice([443, 53, 123, 51820, 3478])
            return ip, port, self.sni_gen.generate()

        # 20%: 从 UDP 真实目标中选（排除正在使用的）
        udp_targets = [t for t in self._real_targets if ":" in t.domain]
        if udp_targets:
            filtered_udp = [t for t in udp_targets
                           if t.used_ip not in exclude_ips]
            if filtered_udp:
                real = randchoice(filtered_udp)
                return real.used_ip, real.port, self.sni_gen.generate()

        # 10%: fallback
        ip, port = randchoice(self._fallback_targets)
        return ip, port, self.sni_gen.generate()

    # ------------------------------------------------------------------
    # 噪声注入（集成时序混淆 + 应用层噪声）
    # ------------------------------------------------------------------

    async def _inject_loop(self, protocol: str):
        # 风险 2: 启动随机相位偏移, 打破"噪声紧跟真实流量"的模式
        startup_offset = randfloat() * 15.0 + randfloat() * 15.0
        await asyncio.sleep(startup_offset)

        while self._running:
            try:
                # ★ DoH 健康检查：DoH 持续不可用时暂停噪声，恢复后自动恢复
                doh_ok = self.doh.is_healthy if hasattr(self.doh, 'is_healthy') else True
                if not doh_ok:
                    if self._doh_unhealthy_since is None:
                        self._doh_unhealthy_since = time.time()
                        logger.warning("DoH 不可用，开始监控噪声暂停条件 (阈值 30s)")
                    elif time.time() - self._doh_unhealthy_since >= self._doh_pause_threshold:
                        if not self._noise_paused:
                            self._noise_paused = True
                            logger.warning("⚠ DoH 持续不可用超过 30 秒，噪声注入已暂停")
                        await asyncio.sleep(2.0)
                        continue
                else:
                    if self._noise_paused:
                        self._noise_paused = False
                        self._doh_unhealthy_since = None
                        logger.info("DoH 已恢复，噪声注入恢复正常")
                    elif self._doh_unhealthy_since is not None:
                        self._doh_unhealthy_since = None

                density = self.density.get_density()
                if density <= 0:
                    await asyncio.sleep(1.0)
                    continue

                interval = self._timing_shaper.next_interval(density)
                await asyncio.sleep(interval)

                think_gap = self._timing_shaper.maybe_insert_think_gap()
                if think_gap > 0:
                    logger.debug(f"思考间隙 {think_gap:.1f}s")
                    await asyncio.sleep(think_gap)
                    continue

                burst = randint(1, 3)
                for _ in range(burst):
                    await self._inject_one(protocol)
                    if burst > 1:
                        await asyncio.sleep(
                            self._rtt_monitor.get_sample_rtt() * 0.5
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"注入异常 ({protocol}): {e}")
                logger.debug("注入异常详细追踪:", exc_info=True)
                await asyncio.sleep(1.0)

    async def _inject_one(self, protocol: str):
        dst_ip, dst_port, fake_sni = self._pick_noise_target(protocol=protocol)
        if not dst_ip or not dst_port:
            return
        if protocol == "tcp":
            await self._inject_tcp(dst_ip, dst_port, fake_sni)
        else:
            await self._inject_udp(dst_ip, dst_port)

    async def _inject_tcp(self, dst_ip: str, dst_port: int,
                          fake_sni: Optional[str]):
        """TCP 噪声: 50% 真实 TLS 连接 (仅 443/8443) + 50% Raw Socket 假包"""
        await self._ensure_curl()

        # 仅 TLS 端口走 curl_cffi 真实连接, 其他端口直接假包
        tls_ports = {443, 8443, 8442}
        if (self._curl_available and randfloat() < 0.5
                and dst_port in tls_ports):
            await self._inject_tcp_real(dst_ip, dst_port, fake_sni)
        else:
            await self._inject_tcp_fake(dst_ip, dst_port, fake_sni)

    async def _inject_tcp_real(self, dst_ip: str, dst_port: int,
                                fake_sni: Optional[str]):
        """轨道 A: curl_cffi 真实 HTTPS 连接 — 完整 TLS 握手, 双向流量"""
        if not self._curl_session:
            return await self._inject_tcp_fake(dst_ip, dst_port, fake_sni)

        try:
            # IPv6 地址需加方括号, 否则冒号与端口冲突
            if ":" in dst_ip:
                url = f"https://[{dst_ip}]:{dst_port}/"
            else:
                url = f"https://{dst_ip}:{dst_port}/"
            headers = {"Host": fake_sni or dst_ip}

            # 5 秒超时保护, 防止慢服务器阻塞事件循环
            async with asyncio.timeout(5.0):
                resp = await self._curl_session.get(
                    url, headers=headers,
                )
                # 访问 resp.content 确保 TLS 握手完成 + 响应下载
                content = resp.content
                content_len = len(content)
                # 保持连接 0.5-5 秒模拟真实浏览 (randfloat = os.urandom 硬件熵)
                await asyncio.sleep(0.5 + randfloat() * 4.5)

            logger.debug(f"真实 TLS 噪声 -> {dst_ip}:{dst_port} "
                         f"({fake_sni or dst_ip}, 双向, {content_len}B)")
            self._noise_pkt_count += 1
            logger.debug(f"curl_cffi 噪声已计入统计")
        except asyncio.TimeoutError:
            logger.debug(f"真实 TLS 噪声超时 ({dst_ip}:{dst_port})")
        except Exception as e:
            logger.debug(f"真实 TLS 噪声失败 ({dst_ip}:{dst_port}): {e}")
            await self._inject_tcp_fake(dst_ip, dst_port, fake_sni)

    async def _inject_tcp_fake(self, dst_ip: str, dst_port: int,
                                fake_sni: Optional[str]):
        """轨道 B: Raw Socket 假包 — 混合策略（方案C + 全套模拟）

        分配策略:
          - 20% SYN-only（仿真端口扫描行为）
          - 40% 三次握手 + TLS CH（轻量，4包）
          - 35% 全套 HTTPS 会话模拟（11-15包，双向流量）← 新增
          - 5%  HTTP/2 或其他假包
        """
        self._lazy_init_app_noise()

        r = randfloat()

        if r < 0.20:
            # ── 20% SYN-only ──
            packet, tcp_hdr_len = self.tcp_gen.generate_syn_only(
                dst_ip, dst_port
            )
            await self._send_packet(packet, dst_ip, dst_port, "tcp", tcp_hdr_len)
            self._noise_pkt_count += 1
            logger.debug(f"SYN-only 噪声 -> {dst_ip}:{dst_port}")

        elif r < 0.60:
            # ── 40% 三次握手包序列（轻量）──
            packets = self.tcp_gen.generate_full_handshake(
                dst_ip, dst_port, fake_sni=fake_sni
            )
            for pkt, hdr_len in packets:
                await self._send_packet(pkt, dst_ip, dst_port, "tcp", hdr_len)
                await asyncio.sleep(0.0005 + randfloat() * 0.001)
            self._noise_pkt_count += 1
            logger.debug(f"三次握手噪声 -> {dst_ip}:{dst_port} "
                         f"({fake_sni or dst_ip}, 4包)")

        elif r < 0.95:
            # ── 35% 全套 HTTPS 会话模拟（双向流量）──
            packets = self.tcp_gen.generate_full_session(
                dst_ip, dst_port, fake_sni=fake_sni
            )
            for i, (pkt, hdr_len) in enumerate(packets):
                await self._send_packet(pkt, dst_ip, dst_port, "tcp", hdr_len)
                # 包间隔模拟：网络延迟 + TLS 处理延迟
                if i == 3:  # TLS CH 后延迟稍长（模拟服务器处理）
                    await asyncio.sleep(0.005 + randfloat() * 0.015)
                elif i == 6:  # TLS Finished 后
                    await asyncio.sleep(0.002 + randfloat() * 0.005)
                elif i < len(packets) - 1:  # 其他中间包
                    await asyncio.sleep(0.0005 + randfloat() * 0.002)
            self._noise_pkt_count += 1
            logger.debug(f"全套会话噪声 -> {dst_ip}:{dst_port} "
                         f"({fake_sni or dst_ip}, {len(packets)}包双向)")

        else:
            # ── 5% HTTP/2 或其他假包 ──
            use_http2 = randfloat() < 0.2
            if use_http2 and self._http2_gen:
                h2_frame = self._http2_gen.generate_noise()
                tls_record = (
                    bytes([0x17]) +
                    bytes([0x03, 0x03]) +
                    struct.pack("!H", len(h2_frame)) +
                    h2_frame
                )
                packet, tcp_hdr_len = self.tcp_gen.generate(
                    dst_ip, dst_port, fake_sni=None
                )
                payload_start = 20 + tcp_hdr_len
                packet = packet[:payload_start] + tls_record
                await self._send_packet(packet, dst_ip, dst_port, "tcp", tcp_hdr_len)
                self._noise_pkt_count += 1
                logger.debug(f"HTTP/2 假包 -> {dst_ip}:{dst_port}")
            else:
                packet, tcp_hdr_len = self.tcp_gen.generate(
                    dst_ip, dst_port, fake_sni=fake_sni
                )
                await self._send_packet(packet, dst_ip, dst_port, "tcp", tcp_hdr_len)
                self._noise_pkt_count += 1
                logger.debug(f"TLS 假包 -> {dst_ip}:{dst_port} "
                             f"(SNI={fake_sni}, IPv{_ip_family(dst_ip)})")

    async def _inject_udp(self, dst_ip: str, dst_port: int):
        self._lazy_init_app_noise()
        use_quic = randfloat() < 0.3

        if use_quic and self._quic_gen:
            quic_payload = self._quic_gen.generate(size_hint=randint(100, 500))
            packet = self.udp_gen.generate(
                dst_ip, dst_port, use_port_coherence=True
            )
            packet = packet[:28] + quic_payload
            logger.debug(f"QUIC 噪声 -> {dst_ip}:{dst_port} (IPv{_ip_family(dst_ip)})")
            self._noise_pkt_count += 1
        else:
            packet = self.udp_gen.generate(
                dst_ip, dst_port, use_port_coherence=True
            )
            logger.debug(f"UDP 噪声 -> {dst_ip}:{dst_port} "
                         f"(IPv{_ip_family(dst_ip)}, port_coherent)")
            self._noise_pkt_count += 1

        await self._send_packet(packet, dst_ip, dst_port, "udp", 0)

    async def _send_packet(self, packet: bytes, dst_ip: str,
                           dst_port: int, protocol: str,
                           tcp_header_len: int = 20):
        try:
            if protocol == "tcp":
                await self._raw_injector.send_ipv4_tcp(packet, dst_ip, dst_port)
            else:
                await self._raw_injector.send_ipv4_udp(packet, dst_ip, dst_port)
        except Exception as e:
            logger.debug(f"发送噪声到 {dst_ip}:{dst_port} 失败: {e}")
