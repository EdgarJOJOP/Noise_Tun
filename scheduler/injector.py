"""统一噪声注入器 — 同域名同协议族选不同 IP 发噪声（UDP/TCP 双协议）"""

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
from .timing import RTTMonitor, TimingShaper

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
                 udp_generator: Optional[UDPNoisePacketGenerator] = None):
        self.density = density_controller
        self.doh = doh_resolver
        self.sni_gen = fake_sni_gen
        self.tcp_gen = tcp_generator or TCPNoisePacketGenerator()
        self.udp_gen = udp_generator or UDPNoisePacketGenerator()

        self._real_targets: list[_RealTarget] = []
        self._resolved: dict[str, _ResolvedDomain] = {}
        self._last_resolve_time: float = 0

        self._target_ttl: float = 600.0
        self._resolve_interval: float = 300.0
        self._max_real_targets: int = 50

        self._fallback_targets: list[tuple[str, int]] = [
            ("1.1.1.1", 443), ("8.8.8.8", 443),
            ("1.1.1.1", 53), ("8.8.8.8", 53),
        ]

        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._udp_sock = None
        self._loop = None

        # 时序混淆
        self._rtt_monitor = RTTMonitor()
        self._timing_shaper = TimingShaper(self._rtt_monitor)

        # 应用层噪声生成器（延迟导入）
        self._quic_gen = None
        self._http2_gen = None
        self._ws_gen = None

    def _lazy_init_app_noise(self):
        if self._quic_gen is None:
            from noise.quic_noise import QUICNoiseGenerator
            from noise.http2_noise import HTTP2NoiseGenerator
            from noise.websocket_noise import WebSocketNoiseGenerator
            self._quic_gen = QUICNoiseGenerator()
            self._http2_gen = HTTP2NoiseGenerator()
            self._ws_gen = WebSocketNoiseGenerator()

    async def start(self):
        self._running = True
        self._loop = asyncio.get_event_loop()
        try:
            import socket as sock_mod
            self._udp_sock = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_DGRAM)
        except Exception:
            self._udp_sock = None
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
        """记录一次真实连接（TCP 和 UDP 均记录）"""
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

    @property
    def rtt_monitor(self):
        return self._rtt_monitor

    # ------------------------------------------------------------------
    # 后台解析
    # ------------------------------------------------------------------

    async def _resolve_loop(self):
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
            del self._resolved[d]

    # ------------------------------------------------------------------
    # 噪声目标选择（支持按协议过滤）
    # ------------------------------------------------------------------

    def _pick_noise_target(self, protocol: str = "tcp"
                           ) -> tuple[Optional[str], Optional[int], Optional[str]]:
        if not self._real_targets:
            ip, port = randchoice(self._fallback_targets)
            return ip, port, self.sni_gen.generate()
        if protocol == "tcp":
            return self._pick_tcp_noise_target()
        else:
            return self._pick_udp_noise_target()

    def _pick_tcp_noise_target(self):
        for real in reversed(self._real_targets):
            resolved = self._resolved.get(real.domain)
            if not resolved:
                continue
            if real.family == 4 and resolved.ipv4:
                others = [ip for ip in resolved.ipv4 if ip != real.used_ip]
                if others:
                    return randchoice(others), real.port, self.sni_gen.generate()
            elif real.family == 6 and resolved.ipv6:
                others = [ip for ip in resolved.ipv6 if ip != real.used_ip]
                if others:
                    return randchoice(others), real.port, self.sni_gen.generate()
        ip, port = randchoice(self._fallback_targets)
        return ip, port, self.sni_gen.generate()

    def _pick_udp_noise_target(self):
        udp_targets = [t for t in self._real_targets
                       if ":" in t.domain]
        if not udp_targets:
            ip, port = randchoice(self._fallback_targets)
            return ip, port, self.sni_gen.generate()

        for real in reversed(udp_targets):
            port = real.port
            matched_domain = None
            for domain, resolved in self._resolved.items():
                all_ips = (resolved.ipv4 or []) + (resolved.ipv6 or [])
                if real.used_ip in all_ips:
                    matched_domain = domain
                    others = [ip for ip in all_ips if ip != real.used_ip]
                    if others:
                        return randchoice(others), port, self.sni_gen.generate()
                    break
            if not matched_domain:
                ip = f"{randint(1,254)}.{randint(0,254)}.{randint(0,254)}.{randint(1,254)}"
                return ip, port, self.sni_gen.generate()

        ip, port = randchoice(self._fallback_targets)
        return ip, port, self.sni_gen.generate()

    # ------------------------------------------------------------------
    # 噪声注入（集成时序混淆 + 应用层噪声）
    # ------------------------------------------------------------------

    async def _inject_loop(self, protocol: str):
        while self._running:
            try:
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
        self._lazy_init_app_noise()
        use_http2 = randfloat() < 0.2

        if use_http2 and self._http2_gen:
            h2_frame = self._http2_gen.generate_noise()
            tls_record = (
                bytes([0x17]) +  # Application Data
                bytes([0x03, 0x03]) +
                struct.pack("!H", len(h2_frame)) +
                h2_frame
            )
            packet, tcp_hdr_len = self.tcp_gen.generate(
                dst_ip, dst_port, fake_sni=None
            )
            payload_start = 20 + tcp_hdr_len
            packet = packet[:payload_start] + tls_record
            logger.debug(f"HTTP/2 噪声 -> {dst_ip}:{dst_port}")
        else:
            packet, tcp_hdr_len = self.tcp_gen.generate(
                dst_ip, dst_port, fake_sni=fake_sni
            )
            logger.debug(f"TCP 噪声 -> {dst_ip}:{dst_port} "
                         f"(SNI={fake_sni}, IPv{_ip_family(dst_ip)})")

        await self._send_packet(packet, dst_ip, dst_port, "tcp", tcp_hdr_len)

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
        else:
            packet = self.udp_gen.generate(
                dst_ip, dst_port, use_port_coherence=True
            )
            logger.debug(f"UDP 噪声 -> {dst_ip}:{dst_port} "
                         f"(IPv{_ip_family(dst_ip)}, port_coherent)")

        await self._send_packet(packet, dst_ip, dst_port, "udp", 0)

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
                if self._udp_sock:
                    try:
                        udp_part = packet[20:]
                        self._udp_sock.sendto(udp_part, (dst_ip, dst_port))
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"发送噪声到 {dst_ip}:{dst_port} 失败: {e}")
