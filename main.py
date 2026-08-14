#!/usr/bin/env python3
"""
NoiseTunnel — 自适应全随机噪声流量混淆隧道

系统设置 SOCKS5 代理指向本程序，代理转发真实流量，
同时持续注入全随机 TCP/UDP 噪声包，使 ML 模型无法从流量模式
学习出上网意图。

用法:
    python main.py                    # 使用默认配置启动
    python main.py --config custom.yaml
    python main.py -v                 # 调试模式
"""

import argparse
import asyncio
import logging
import sys
import signal
import os
import subprocess
import time

# ── 管理员权限自提升（Windows，静默） ──
def _ensure_admin():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        return

    import ctypes
    script = os.path.abspath(sys.argv[0])
    args = " ".join(sys.argv[1:])
    workdir = os.path.dirname(script)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, '"%s" %s' % (script, args), workdir, 1
    )
    sys.exit(0)

_ensure_admin()

# 定时重启
_restart_timer: float = 0  # 启动时间, 在 main() 中设置

def _trigger_restart():
    """重启 NoiseTun 进程"""
    logger.info("=" * 50)
    logger.info("定时重启 NoiseTun...")
    logger.info("=" * 50)
    if os.name == 'posix':
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            logger.error("execv restart failed: %s", e)
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True)
            os._exit(0)
    else:
        try:
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True)
        except Exception as e:
            logger.error("重启失败: %s", e)
            return
        os._exit(0)

from core.config import Config
from core.socks5_proxy import ProxyServer
from dns.resolver import DoHResolver
from dns.fake_sni import FakeSNIGenerator
from scheduler.density import AdaptiveDensityController
from noise.tcp_noise import TCPNoisePacketGenerator
from noise.udp_noise import UDPNoisePacketGenerator
from noise.udp_sampler import UDPSampler
from noise.quic_noise import QUICNoiseGenerator
from noise.traffic_profile import TrafficProfile
from scheduler.injector import NoiseInjector

logger = logging.getLogger("noisetunnel")


async def main():
    parser = argparse.ArgumentParser(description="NoiseTunnel — 流量混淆隧道")
    parser.add_argument("--config", "-c", default=None,
                        help="配置文件路径")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="详细日志")
    args = parser.parse_args()

    # 加载配置
    config = Config.load(args.config)

    # 日志
    log_level = logging.DEBUG if args.verbose else getattr(logging, config.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("=" * 50)
    logger.info("NoiseTunnel 启动")
    logger.info(f"  SOCKS5:   {config.socks5.host}:{config.socks5.port}")
    logger.info(f"  DoH:      {config.noise.doh_url} (主, 域名拦截)")
    logger.info(f"  噪声 DoH: {config.noise.noise_doh_url} (无拦截, 域名源/DomainPool)")
    logger.info(f"  密度策略: 高流量={config.density.high_traffic_density:.0%}, "
                f"低流量={config.density.low_traffic_density:.0%}, "
                f"静默={config.density.silence_density:.0%}")
    logger.info(f"  使用方式: 系统代理设为 SOCKS5 {config.socks5.host}:{config.socks5.port}")
    logger.info("=" * 50)

    # 初始化组件
    # DNS — 主 DoH（带域名拦截，用于用户真实流量）
    doh = DoHResolver(
        doh_url=config.noise.doh_url,
        fallback_doh_url=config.noise.fallback_doh_url,
        timeout=config.noise.doh_timeout,
        cache_ttl=config.noise.dns_cache_ttl,
        cache_enabled=config.noise.dns_cache_enabled,
    )
    # ★ 噪声专用 DoH（无域名拦截，用于解析 domain_sources / DomainPool）
    #   主 DoH 会拦截广告/毒域名，噪声域名本身就是广告列表，需用无拦截的 DoH
    noise_doh = DoHResolver(
        doh_url=config.noise.noise_doh_url,
        fallback_doh_url=config.noise.noise_fallback_doh_url,
        timeout=config.noise.noise_doh_timeout,
        cache_ttl=config.noise.noise_dns_cache_ttl,
        cache_enabled=config.noise.noise_dns_cache_enabled,
    )
    domain_pool = FakeSNIGenerator()

    # 真实流量分布采集器 (用于包大小 & 发送间隔建模)
    traffic_profile = TrafficProfile(
        max_packet_samples=config.traffic_profiling.max_samples,
        max_interval_samples=config.traffic_profiling.max_samples // 2,
    ) if config.traffic_profiling.enabled else None

    # 密度控制器
    density_ctrl = AdaptiveDensityController(
        window_seconds=config.density.window_seconds,
        high_threshold=config.density.high_traffic_threshold,
        low_threshold=config.density.low_traffic_threshold,
        silence_seconds=config.density.silence_seconds,
        high_density=config.density.high_traffic_density,
        low_density=config.density.low_traffic_density,
        silence_density=config.density.silence_density,
    )

    # TCP/UDP 噪声生成器（传入配置值）
    tcp_gen = TCPNoisePacketGenerator(
        src_port_min=config.noise.tcp_min_port,
        src_port_max=config.noise.tcp_max_port,
    )
    udp_gen = UDPNoisePacketGenerator(
        src_port_min=config.noise.udp_min_port,
        src_port_max=config.noise.udp_max_port,
        min_payload=config.noise.min_payload_size,
        max_payload=config.noise.max_payload_size,
    )

    # 将 TrafficProfile 注入噪声生成器
    if traffic_profile:
        udp_gen.set_traffic_profile(traffic_profile)

    # 假域名生成器（用于噪声 TLS CH 的 SNI 字段）
    domain_pool = FakeSNIGenerator()

    # 噪声注入器
    injector = NoiseInjector(
        density_controller=density_ctrl,
        doh_resolver=doh,
        fake_sni_gen=domain_pool,
        tcp_generator=tcp_gen,
        udp_generator=udp_gen,
        domain_pool_size=config.noise.domain_pool_size,
        noise_doh_resolver=noise_doh,  # ★ 噪声专用 DoH（无域名拦截）
    )
    if traffic_profile:
        injector.set_traffic_profile(traffic_profile)

    # 传入域名源 URL (从 config.yaml 读取)
    if config.domain_sources.enabled and config.domain_sources.urls:
        injector.set_domain_source_urls(config.domain_sources.urls)
        injector.set_fetch_interval(config.noise.refresh_interval or 86400)

    # UDP 采样器（捕获系统真实 UDP 载荷头做模板）
    udp_sampler = UDPSampler()
    udp_gen.set_sampler(udp_sampler)

    # ★ 新增：UDP 真实目标 → injector
    def on_udp_real_target(dst_ip, dst_port):
        injector.record_real_udp_target(dst_ip, dst_port)
    udp_sampler.set_on_real_udp_target(on_udp_real_target)

    # 连接回调：注入器记录真实流量（含解析到的真实 IP）
    def on_connection(host, resolved_ip, port, proto):
        injector.record_real_connection(host, resolved_ip, port, proto)

    # TLS 模板回调：捕获浏览器 TLS CH 作为噪声模板
    def on_tls_template(template):
        tcp_gen.set_template(template)

    # SOCKS5 代理
    extra_bind = None
    if config.additional_bind.enabled:
        extra_bind = (config.additional_bind.host, config.additional_bind.port)

    proxy = ProxyServer(
        host=config.socks5.host,
        port=config.socks5.port,
        on_connection=on_connection,
        on_tls_template=on_tls_template,
        additional_bind=extra_bind,
        username=config.socks5.username,
        password=config.socks5.password,
        doh_resolver=doh,
        enforce_doh_only=config.noise.enforce_doh_only,
        traffic_profile=traffic_profile,
    )

    # 检查端口是否被旧进程占用
    import socket as _sock
    _sc = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    try:
        _sc.bind((config.socks5.host, config.socks5.port))
        _sc.close()
    except OSError:
        logger.error("端口 %d 已被占用！先关闭旧进程: taskkill /F /IM python.exe", config.socks5.port)
        _sc.close()
        await injector.stop()
        await doh.close()
        return

    # ---- 启动 ----
    start_time = time.time()
    try:
        # 1. 启动代理
        await proxy.start()

        # 1b. 初始化 curl_cffi 浏览器指纹 (若配置启用)
        if config.noise.browser_fingerprints_enabled:
            await tcp_gen.init_curl_cffi()
            await tcp_gen.start_refresh_loop()

        # 1c. 检查 Raw Socket 注入状态 (风险 1)
        if config.noise.raw_injection_required and not injector._raw_injector.is_raw:
            logger.error("✕ raw_injection_required=true 但 Npcap 不可用!")
            logger.error("  请安装 Npcap: https://npcap.com/")
            raise RuntimeError("Npcap required but not available for raw socket injection")

        # 2. 启动噪声注入
        await injector.start()

        # 3. 启动 UDP 采样（需要管理员权限，失败则静默使用内置模板）
        await udp_sampler.start_capture()

        # 4. 等待终止信号 + 重启定时器
        stop_event = asyncio.Event()

        # 重启监视器: 运行时间超过 refresh_interval 则重启
        async def _restart_watcher():
            while not stop_event.is_set():
                await asyncio.sleep(60)
                elapsed = time.time() - start_time
                if elapsed >= config.noise.refresh_interval:
                    logger.info(f"运行 {elapsed:.0f}s, 达到重启间隔, 执行重启")
                    stop_event.set()
                    # 给 finally 块一点时间做清理 (injector.stop 等)
                    await asyncio.sleep(0.5)
                    _trigger_restart()
        
        restart_task = asyncio.create_task(_restart_watcher())

        # Metric 报告器: 每 5 分钟输出统计
        async def _metrics_reporter():
            while not stop_event.is_set():
                await asyncio.sleep(300)
                try:
                    real_count = injector.get_real_conn_count()
                    noise_count = injector.get_noise_pkt_count()
                    ratio = noise_count / max(real_count, 1)
                    logger.info(f"📊 统计 | 真实连接: {real_count} | 噪声注入: {noise_count} | 比率: {ratio:.2f}")
                except Exception as e:
                    logger.debug(f"Metric 报告异常: {e}")

        metrics_task = asyncio.create_task(_metrics_reporter())

        def _signal_handler():
            logger.info("收到终止信号，正在关闭...")
            stop_event.set()

        if sys.platform != "win32":
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _signal_handler)

        logger.info("NoiseTunnel 运行中 (Ctrl+C 停止)")
        logger.info(f"→ 请将系统代理设为 SOCKS5 {config.socks5.host}:{config.socks5.port}")
        logger.info(f"→ 定时重启: {config.noise.refresh_interval}s")
        await stop_event.wait()

    except asyncio.CancelledError:
        pass
    finally:
        logger.info("正在关闭 NoiseTunnel...")
        await injector.stop()
        await udp_sampler.stop_capture()
        await proxy.stop()
        await doh.close()
        await noise_doh.close()  # ★ 关闭噪声专用 DoH
        # 取消重启监视器
        if 'restart_task' in dir():
            restart_task.cancel()
        logger.info("NoiseTunnel 已关闭")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
