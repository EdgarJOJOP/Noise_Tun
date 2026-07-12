"""统一噪声注入器 — 同域名同协议族选不同 IP 发噪声"""

import asyncio
import logging
import struct
import time
import ipaddress
from collections import OrderedDict
from typing import Optional

from noise.packet_builder import randint, randchoice, randfloat

from noise.tcp_noise import TCPNoisePacketGenerator
from noise.udp_noise import UDPNoisePacketGenerator
from dns.resolver import DoHResolver
from dns.fake_sni import FakeSNIGenerator
from .density import AdaptiveDensityController

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
        self.used_ip = used_ip  # 真实连接实际使用的 IP
        self.port = port
        # 判断 IP 协议族
        self.family = 6 if ":" in used_ip else 4
        self.timestamp = time.time()


def _ip_family(ip: str) -> int:
    """返回 IP 协议族: 4=IPv4, 6=IPv6"""
    return 6 if ":" in ip else 4


class NoiseInjector:
    """
    噪声注入器 — 从真实流量提取目标

    核心策略:
    1. 用户访问 example.com:443 → SOCKS5 解析到 1.2.3.4 (IPv4)
    2. 记录: domain=example.com, used_ip=1.2.3.4, port=443, family=4
    3. DoH 解析 example.com → IPv4=[1.2.3.4, 5.6.7.8], IPv6=[2606::1]
    4. 噪声 → 选同域名同协议族其他 IP(5.6.7.8):443
    5. TCP 噪声含假 SNI(不是 example.com)
    """

    def __init__(self,
                 density_controller: AdaptiveDensityController,
                 doh_resolver: DoHResolver,
                 fake_sni_gen: FakeSNIGenerator,
                 tcp_generator: Optional[TCPNoisePacketGenerator] = None,
                 udp_generator: Optional[UDPNoisePacketGenerator] = None):
        self.density = density_controller
        self.doh = doh_resolver
        self.sni_gen = fake_sni_gen
        self.tcp_gen = tcp_generator or TCPNoisePacketGenerator()
        self.udp_gen = udp_generator or UDPNoisePacketGenerator()

        # 真实流量记录: [(domain, used_ip, port), ...]
        self._real_targets: list[_RealTarget] = []
        # 域名解析缓存: domain -> _ResolvedDomain
        self._resolved: dict[str, _ResolvedDomain] = {}
        # 域名解析时间戳（限频用）
        self._last_resolve_time: float = 0

        self._target_ttl: float = 600.0       # 目标过期时间
        self._resolve_interval: float = 300.0  # DoH 解析限频
        self._max_real_targets: int = 50       # 最多跟踪 50 个目标

        # 保底目标
        self._fallback_targets: list[tuple[str, int]] = [
            ("1.1.1.1", 443), ("8.8.8.8", 443),
            ("1.1.1.1", 53), ("8.8.8.8", 53),
        ]

        self._running = False
        self._tasks: list[asyncio.Task] = []
        # 持久 UDP socket（复用，无需每次新建）
        self._udp_sock = None
        self._loop = None

    async def start(self):
        self._running = True
        self._loop = asyncio.get_event_loop()
        # 创建持久 UDP socket
        try:
            import socket as sock_mod
            self._udp_sock = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_DGRAM)
        except Exception:
            self._udp_sock = None
        self._tasks = [
            asyncio.create_task(self._inject_loop("tcp")),
            asyncio.create_task(self._inject_loop("udp")),
            asyncio.create_task(self._resolve_loop()),
        ]
        logger.info("噪声注入器已启动 (同域名同协议族不同IP噪声)")

    async def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        # 关闭 UDP socket
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
            self._udp_sock = None
        logger.info("噪声注入器已停止")

    # ------------------------------------------------------------------
    # 真实流量记录
    # ------------------------------------------------------------------

    def record_real_connection(self, domain: str, resolved_ip: str,
                               port: int, protocol: str):
        """
        记录一次真实连接

        参数:
            domain: 用户访问的域名
            resolved_ip: 实际连接到的 IP（由 SOCKS5 代理提供）
            port: 端口号
            protocol: "tcp" 或 "udp"
        """
        self.density.record_connection()

        if protocol == "tcp" and domain and port:
            now = time.time()

            # 去重
            self._real_targets = [
                t for t in self._real_targets
                if not (t.domain == domain and t.used_ip == resolved_ip and t.port == port)
            ]

            self._real_targets.append(_RealTarget(domain, resolved_ip, port))

            # 限长
            if len(self._real_targets) > self._max_real_targets:
                self._real_targets = self._real_targets[-self._max_real_targets:]

            logger.debug(f"真实流量: {domain} ({resolved_ip}:{port}, IPv{_ip_family(resolved_ip)})")

    # ------------------------------------------------------------------
    # 后台解析
    # ------------------------------------------------------------------

    async def _resolve_loop(self):
        """后台解析任务"""
        while self._running:
            try:
                await self._resolve_domains()
                self._cleanup_expired()
                await asyncio.sleep(30.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"解析异常: {e}")
                await asyncio.sleep(10.0)

    async def _resolve_domains(self):
        """解析待处理的域名"""
        now = time.time()
        if now - self._last_resolve_time < self._resolve_interval:
            return
        self._last_resolve_time = now

        # 取最近活跃的不同域名（最多 5 个）
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
                    logger.debug(f"解析 {domain}: IPv4={v4}, IPv6={v6}")
            except Exception as e:
                logger.debug(f"解析 {domain} 失败: {e}")

        if self._resolved:
            sample = list(self._resolved.keys())[:3]
            logger.info(f"已解析域名: {len(self._resolved)} 个 ({sample}...)")

    def _cleanup_expired(self):
        """清理过期记录"""
        now = time.time()
        self._real_targets = [t for t in self._real_targets
                              if now - t.timestamp < self._target_ttl]
        stale_domains = [d for d, r in self._resolved.items()
                         if now - r.resolved_time > self._target_ttl * 2]
        for d in stale_domains:
            del self._resolved[d]

    # ------------------------------------------------------------------
    # 噪声目标选择（核心策略）
    # ------------------------------------------------------------------

    def _pick_noise_target(self) -> tuple[Optional[str], Optional[int], Optional[str]]:
        """
        选择一个噪声目标

        返回:
            (ip, port, fake_sni)  或  (None, None, None) 无可用目标

        策略:
        1. 从最近真实流量中找一个
        2. 取同域名的 DoH 解析结果
        3. 从同协议族(IPv4/IPv6)中选一个不同于真实流量的 IP
        4. 如果没其他 IP，尝试其他域名
        """
        if not self._real_targets:
            ip, port = randchoice(self._fallback_targets)
            return ip, port, self.sni_gen.generate()

        # 从最新流量开始找
        for real in reversed(self._real_targets):
            resolved = self._resolved.get(real.domain)
            if not resolved:
                continue

            # 选同协议族的其他 IP
            if real.family == 4 and resolved.ipv4:
                others = [ip for ip in resolved.ipv4 if ip != real.used_ip]
                if others:
                    ip = randchoice(others)
                    return ip, real.port, self.sni_gen.generate()

            elif real.family == 6 and resolved.ipv6:
                others = [ip for ip in resolved.ipv6 if ip != real.used_ip]
                if others:
                    ip = randchoice(others)
                    return ip, real.port, self.sni_gen.generate()

        # 找不到同域名的其他 IP，用保底
        ip, port = randchoice(self._fallback_targets)
        return ip, port, self.sni_gen.generate()

    # ------------------------------------------------------------------
    # 噪声注入
    # ------------------------------------------------------------------

    async def _inject_loop(self, protocol: str):
        while self._running:
            try:
                density = self.density.get_density()
                if density <= 0:
                    await asyncio.sleep(1.0)
                    continue

                base_interval = (1.0 - density) * 2.0 + 0.3
                interval = base_interval * (0.5 + randfloat())
                await asyncio.sleep(interval)

                burst = randint(1, 3)
                for _ in range(burst):
                    await self._inject_one(protocol)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"注入异常 ({protocol}): {e}")
                await asyncio.sleep(1.0)

    async def _inject_one(self, protocol: str):
        dst_ip, dst_port, fake_sni = self._pick_noise_target()
        if not dst_ip or not dst_port:
            return

        if protocol == "tcp":
            packet, tcp_hdr_len = self.tcp_gen.generate(
                dst_ip, dst_port, fake_sni=fake_sni
            )
            logger.debug(f"TCP 噪声 → {dst_ip}:{dst_port} "
                         f"(SNI={fake_sni}, IPv{_ip_family(dst_ip)})")
        else:
            packet = self.udp_gen.generate(dst_ip, dst_port)
            tcp_hdr_len = 0
            logger.debug(f"UDP 噪声 → {dst_ip}:{dst_port} (IPv{_ip_family(dst_ip)})")

        await self._send_packet(packet, dst_ip, dst_port, protocol, tcp_hdr_len)

    async def _send_packet(self, packet: bytes, dst_ip: str,
                           dst_port: int, protocol: str,
                           tcp_header_len: int = 20):
        try:
            if protocol == "tcp":
                loop = self._loop or asyncio.get_event_loop()

                def _send_tcp():
                    import socket as sock
                    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                    s.settimeout(3.0)
                    s.setsockopt(sock.SOL_SOCKET, sock.SO_LINGER,
                                 struct.pack("ii", 1, 0))
                    try:
                        s.connect((dst_ip, dst_port))
                        payload_offset = 20 + tcp_header_len
                        tls_part = packet[payload_offset:]
                        if tls_part:
                            s.send(tls_part)
                    except Exception:
                        pass
                    finally:
                        s.close()

                await loop.run_in_executor(None, _send_tcp)

            else:
                # UDP：使用持久 socket，无需新建/线程池
                if self._udp_sock:
                    try:
                        udp_part = packet[20:]
                        self._udp_sock.sendto(udp_part, (dst_ip, dst_port))
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"发送噪声到 {dst_ip}:{dst_port} 失败: {e}")
