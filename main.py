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

from core.config import Config
from core.socks5_proxy import ProxyServer
from dns.resolver import DoHResolver
from dns.fake_sni import FakeSNIGenerator
from scheduler.density import AdaptiveDensityController
from noise.tcp_noise import TCPNoisePacketGenerator
from noise.udp_noise import UDPNoisePacketGenerator
from noise.udp_sampler import UDPSampler
from noise.quic_noise import QUICNoiseGenerator
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
    logger.info(f"  DoH:      {config.noise.doh_url}")
    logger.info(f"  密度策略: 高流量={config.density.high_traffic_density:.0%}, "
                f"低流量={config.density.low_traffic_density:.0%}, "
                f"静默={config.density.silence_density:.0%}")
    logger.info(f"  使用方式: 系统代理设为 SOCKS5 {config.socks5.host}:{config.socks5.port}")
    logger.info("=" * 50)

    # 初始化组件
    # DNS
    doh = DoHResolver(
        doh_url=config.noise.doh_url,
        fallback_doh_url=config.noise.fallback_doh_url,
        timeout=config.noise.doh_timeout,
        cache_ttl=config.noise.dns_cache_ttl,
        cache_enabled=config.noise.dns_cache_enabled,
    )
    domain_pool = FakeSNIGenerator()

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

    # 假域名生成器（用于噪声 TLS CH 的 SNI 字段）
    domain_pool = FakeSNIGenerator()

    # 噪声注入器
    injector = NoiseInjector(
        density_controller=density_ctrl,
        doh_resolver=doh,
        fake_sni_gen=domain_pool,
        tcp_generator=tcp_gen,
        udp_generator=udp_gen,
    )

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
    try:
        # 1. 启动代理
        await proxy.start()

        # 2. 启动噪声注入
        await injector.start()

        # 3. 启动 UDP 采样（需要管理员权限，失败则静默使用内置模板）
        await udp_sampler.start_capture()

        # 4. 等待终止信号
        stop_event = asyncio.Event()

        def _signal_handler():
            logger.info("收到终止信号，正在关闭...")
            stop_event.set()

        if sys.platform != "win32":
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _signal_handler)

        logger.info("NoiseTunnel 运行中 (Ctrl+C 停止)")
        logger.info(f"→ 请将系统代理设为 SOCKS5 {config.socks5.host}:{config.socks5.port}")
        await stop_event.wait()

    except asyncio.CancelledError:
        pass
    finally:
        logger.info("正在关闭 NoiseTunnel...")
        await injector.stop()
        await udp_sampler.stop_capture()
        await proxy.stop()
        await doh.close()
        logger.info("NoiseTunnel 已关闭")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
