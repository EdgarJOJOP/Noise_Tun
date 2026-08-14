"""代理服务器 — 自动检测 SOCKS5 / HTTP CONNECT（支持用户名密码认证 + DoH 防 DNS 泄漏）"""

import asyncio
import logging
import struct
import ipaddress
import base64
import socket as _socket
from typing import Optional, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from noise.traffic_profile import TrafficProfile

logger = logging.getLogger("noisetunnel.proxy")

# SOCKS5 常量
SOCKS5_VER = 0x05
ATYP_IPv4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPv6 = 0x04
CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03
REP_SUCCESS = 0x00


def _is_ip_address(host: str) -> bool:
    """判断字符串是否为 IP 地址（而非域名）"""
    try:
        ipaddress.IPv4Address(host)
        return True
    except ipaddress.AddressValueError:
        pass
    try:
        ipaddress.IPv6Address(host)
        return True
    except ipaddress.AddressValueError:
        pass
    return False


class ProxyServer:
    """
    代理服务器 — 自动检测 SOCKS5 / HTTP CONNECT

    - Windows 系统代理 → HTTP CONNECT
    - 浏览器/扩展配代理 → SOCKS5
    - 自动识别，无需选择
    - 支持 SOCKS5 用户名密码认证 (RFC 1929)
    - 支持 HTTP Proxy-Authorization Basic
    - ★ 所有域名解析强制走 DoH，杜绝明文 DNS 泄漏
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1086,
                 on_connection: Optional[Callable] = None,
                 on_tls_template: Optional[Callable] = None,
                 additional_bind: Optional[tuple] = None,
                 username: str = "",
                 password: str = "",
                 doh_resolver: Optional[object] = None,
                 enforce_doh_only: bool = True,
                 traffic_profile: Optional['TrafficProfile'] = None):
        """
        additional_bind: 可选 (host, port) 元组，监听额外地址供局域网使用
        username/password: SOCKS5/HTTP 认证凭据，留空则不启用认证
        doh_resolver: DoHResolver 实例，用于加密 DNS 解析
        enforce_doh_only: True=DoH失败时阻断连接，False=回退系统 DNS（可能泄漏）
        traffic_profile: TrafficProfile 实例，用于记录真实流量统计
        """
        self.host = host
        self.port = port
        self.on_connection = on_connection
        self.on_tls_template = on_tls_template
        self._server: Optional[asyncio.AbstractServer] = None
        self._server2: Optional[asyncio.AbstractServer] = None
        self._additional_bind = additional_bind
        self.username = username
        self.password = password
        self._doh = doh_resolver
        self._enforce_doh_only = enforce_doh_only
        self._profile = traffic_profile
        # 跟踪所有客户端连接 task，用于优雅关闭
        self._client_tasks: set[asyncio.Task] = set()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        listeners = self._server.sockets
        addr = listeners[0].getsockname() if listeners else (self.host, self.port)
        auth_info = f" (auth={bool(self.username)})" if self.username else ""
        doh_info = " (DoH)" if self._doh else " (⚠️ 无 DoH)"
        enforce_info = " (阻断明文dns使用)" if self._enforce_doh_only else " (回退系统DNS)"
        logger.info(f"代理已启动 (SOCKS5 + HTTP CONNECT): {addr[0]}:{addr[1]}{auth_info}{doh_info}{enforce_info}")

        # 额外局域网监听
        if self._additional_bind:
            extra_host, extra_port = self._additional_bind
            self._server2 = await asyncio.start_server(
                self._handle_client, extra_host, extra_port
            )
            logger.info(f"局域网代理已启动: {extra_host}:{extra_port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._server2:
            self._server2.close()
            await self._server2.wait_closed()
        # ★ 取消并等待所有正在处理的客户端连接，防止 Task was destroyed
        for t in list(self._client_tasks):
            t.cancel()
        if self._client_tasks:
            await asyncio.gather(*self._client_tasks, return_exceptions=True)
        self._client_tasks.clear()
        logger.info("代理已停止")

    # ------------------------------------------------------------------
    # DoH 解析（防 DNS 泄漏核心）
    # ------------------------------------------------------------------

    async def _resolve_via_doh(self, host: str) -> Optional[str]:
        """
        通过 DoH 解析域名 → IP，杜绝明文 DNS 泄漏

        如果 host 已经是 IP 地址，直接返回；
        否则用 DoH 解析，返回 IPv4 地址（优先）或 IPv6。

        返回:
            IP 地址字符串，或 None（enforce_doh_only=True 时解析失败返回 None）
        """
        if _is_ip_address(host):
            return host
        if not self._doh:
            logger.warning("未配置 DoH 解析器！无法安全解析 %s，连接已阻断", host)
            return None
        try:
            v4, v6 = await self._doh.resolve(host)
            if v4:
                return v4[0]
            if v6:
                return v6[0]
            if self._enforce_doh_only:
                logger.debug("DoH 解析 %s 无结果（域名可能被加密DNS拦截），连接已阻断", host)
                return None
            logger.debug("DoH 解析 %s 无结果，无回退 DNS，连接已阻断", host)
            return None
        except Exception as e:
            if self._enforce_doh_only:
                logger.debug("DoH 解析 %s 失败: %s，连接已阻断", host, e)
                return None
            logger.debug("DoH 解析 %s 失败: %s，无回退 DNS，连接已阻断", host, e)
            return None

    # ------------------------------------------------------------------
    # 协议自动检测
    # ------------------------------------------------------------------

    async def _handle_client(self, reader, writer):
        """处理一个客户端连接，注册到 _client_tasks 以便优雅关闭时清理"""
        task = asyncio.current_task()
        self._client_tasks.add(task)
        try:
            first = await reader.readexactly(1)
            if first == b'\x05':
                await self._handle_socks5(reader, writer)
            else:
                await self._handle_http_connect(reader, writer, first)
        except Exception as e:
            logger.debug(f"客户端异常: {e}")
            try:
                writer.close()
            except Exception:
                pass
        finally:
            self._client_tasks.discard(task)

    # ------------------------------------------------------------------
    # SOCKS5（支持 RFC 1929 用户名密码认证 + DoH 解析）
    # ------------------------------------------------------------------

    async def _handle_socks5(self, reader, writer):
        # 握手（首字节已读）
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)

        if self.username and self.password:
            if 0x02 in methods:
                writer.write(struct.pack("!BB", SOCKS5_VER, 0x02))
                await writer.drain()
                subver = (await reader.readexactly(1))[0]
                if subver != 0x01:
                    writer.write(b"\x01\xFF")
                    await writer.drain()
                    writer.close()
                    return
                ulen = (await reader.readexactly(1))[0]
                uname = await reader.readexactly(ulen)
                plen = (await reader.readexactly(1))[0]
                passwd = await reader.readexactly(plen)
                if (uname.decode("utf-8", errors="replace") == self.username
                        and passwd.decode("utf-8", errors="replace") == self.password):
                    writer.write(b"\x01\x00")
                else:
                    writer.write(b"\x01\xFF")
                    await writer.drain()
                    writer.close()
                    return
                await writer.drain()
            else:
                writer.write(struct.pack("!BB", SOCKS5_VER, 0xFF))
                await writer.drain()
                writer.close()
                return
        else:
            writer.write(struct.pack("!BB", SOCKS5_VER, 0x00))
            await writer.drain()

        # 请求
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))

        if atyp == ATYP_IPv4:
            raw = await reader.readexactly(4)
            dst_host = str(ipaddress.IPv4Address(raw))
        elif atyp == ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            dst_host = (await reader.readexactly(length)).decode()
        elif atyp == ATYP_IPv6:
            raw = await reader.readexactly(16)
            dst_host = str(ipaddress.IPv6Address(raw))
        else:
            raise ValueError(f"不支持的 ATYP: {atyp}")

        dst_port = struct.unpack("!H", await reader.readexactly(2))[0]

        # ★ 强制 DoH 解析，堵死 DNS 泄漏
        resolved_ip = await self._resolve_via_doh(dst_host)
        if not resolved_ip:
            # DoH 解析失败，阻断连接（不泄漏到系统 DNS）
            logger.debug("DNS 解析阻断: %s（enforce_doh_only）", dst_host)
            writer.write(struct.pack("!BBBB", SOCKS5_VER, 4, 0, ATYP_IPv4))
            writer.write(b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        if cmd == CMD_CONNECT:
            await self._tcp_tunnel(reader, writer, resolved_ip, dst_port,
                                   http_mode=False, original_host=dst_host)
        elif cmd == CMD_UDP_ASSOCIATE:
            await self._handle_udp_associate(reader, writer, dst_host, dst_port)
        else:
            logger.warning(f"不支持的 SOCKS5 命令: {cmd}")
            writer.write(struct.pack("!BBBB", SOCKS5_VER, 0x07, 0, ATYP_IPv4))
            writer.write(b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()

    # ------------------------------------------------------------------
    # HTTP CONNECT（支持 Proxy-Authorization Basic + DoH 解析）
    # ------------------------------------------------------------------

    async def _handle_http_connect(self, reader, writer, first_byte):
        data = first_byte + await reader.readuntil(b"\r\n")
        line = data.decode("utf-8", errors="replace").strip()
        logger.debug(f"HTTP CONNECT: {line}")

        if not line.upper().startswith("CONNECT "):
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        parts = line[8:].split(" ")
        hostport = parts[0]
        if ":" in hostport:
            dst_host, port_str = hostport.rsplit(":", 1)
            dst_port = int(port_str)
        else:
            dst_host = hostport
            dst_port = 443

        # 读取请求头，检查 Proxy-Authorization
        auth_ok = (not self.username and not self.password)
        while True:
            h = await reader.readuntil(b"\r\n")
            if h in (b"\r\n", b"\n"):
                break
            if self.username and self.password:
                hl = h.decode("utf-8", errors="replace").strip().lower()
                if hl.startswith("proxy-authorization:"):
                    parts = hl.split(" ", 2)
                    if len(parts) >= 3:
                        try:
                            decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                            u, _, p = decoded.partition(":")
                            auth_ok = (u == self.username and p == self.password)
                        except Exception:
                            auth_ok = False

        if self.username and self.password and not auth_ok:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"NoiseTunnel\"\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # ★ 强制 DoH 解析，堵死 DNS 泄漏
        resolved_ip = await self._resolve_via_doh(dst_host)
        if not resolved_ip:
            # DoH 解析失败，阻断连接
            logger.debug("DNS 解析阻断: %s（enforce_doh_only）", dst_host)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        await self._tcp_tunnel(reader, writer, resolved_ip, dst_port,
                               http_mode=True, original_host=dst_host)

    # ------------------------------------------------------------------
    # TCP 隧道（SOCKS5 + HTTP CONNECT 共用）
    # ------------------------------------------------------------------

    async def _handle_udp_associate(self, reader, writer,
                                     dst_host: str, dst_port: int):
        """SOCKS5 UDP ASSOCIATE — 完整的 UDP 双向中继实现"""
        try:
            loop = asyncio.get_event_loop()

            class _UDPRelayProtocol(asyncio.DatagramProtocol):
                def __init__(self, proxy, sock_reader, sock_writer):
                    self._proxy = proxy
                    self._reader = sock_reader
                    self._writer = sock_writer
                    self._transport = None
                    self._client_addr = None  # (ip, port) — 首次接收数据时记录
                    # 记录客户端→目标映射，用于把响应转发回正确客户端
                    self._target_map: dict[tuple, tuple] = {}

                def connection_made(self, transport):
                    self._transport = transport

                def datagram_received(self, data, addr):
                    # 判断方向：如果已有客户端地址，来自客户端的请求带 SOCKS5 头
                    if self._client_addr is None:
                        # 首个数据报，记录客户端地址
                        self._client_addr = addr
                    
                    if addr == self._client_addr:
                        # 方向 A: 客户端 → 目标（带 SOCKS5 UDP 请求头）
                        self._handle_client_to_target(data)
                    elif self._client_addr is not None:
                        # 方向 B: 目标 → 客户端（不带头，直接转发回去）
                        self._handle_target_to_client(data, addr)

                def _handle_client_to_target(self, data):
                    """解析 SOCKS5 UDP 请求头并转发到目标"""
                    if len(data) < 7 or data[0:2] != b'\x00\x00':
                        return
                    frag = data[2]
                    if frag != 0x00:
                        return
                    atyp = data[3]
                    offset = 4
                    try:
                        if atyp == ATYP_IPv4:
                            dst_ip = ".".join(str(b) for b in data[offset:offset+4])
                            offset += 4
                        elif atyp == ATYP_DOMAIN:
                            dlen = data[offset]
                            dst_ip = data[offset+1:offset+1+dlen].decode()
                            offset += 1 + dlen
                        elif atyp == ATYP_IPv6:
                            dst_ip = str(ipaddress.IPv6Address(data[offset:offset+16]))
                            offset += 16
                        else:
                            return
                        udp_dst_port = (data[offset] << 8) | data[offset+1]
                        offset += 2
                        payload = data[offset:]

                        target_key = (dst_ip, udp_dst_port)
                        self._target_map[target_key] = self._client_addr

                        # 转发到真实目标
                        self._transport.sendto(payload, (dst_ip, udp_dst_port))
                    except Exception as e:
                        logger.debug(f"UDP 中继 → 目标失败: {e}")

                def _handle_target_to_client(self, data, src_addr):
                    """将目标服务器的响应转发回 SOCKS5 客户端（带 UDP 头封装）
                    RFC 1928 §7: UDP 响应头必须包含数据来源地址（目标服务器），非客户端"""
                    try:
                        # 查找对应的客户端地址
                        client_addr = self._target_map.get(src_addr, self._client_addr)
                        if not client_addr:
                            return

                        # 响应头使用目标服务器地址（src_addr 即目标服务器）
                        srv_ip, srv_port = src_addr
                        if ":" in srv_ip:
                            atyp = ATYP_IPv6
                            addr_bytes = ipaddress.IPv6Address(srv_ip).packed
                        else:
                            atyp = ATYP_IPv4
                            addr_bytes = ipaddress.IPv4Address(srv_ip).packed

                        resp_header = b'\x00\x00\x00' + bytes([atyp]) + addr_bytes + struct.pack("!H", srv_port)
                        response = resp_header + data
                        self._transport.sendto(response, client_addr)
                    except Exception as e:
                        logger.debug(f"UDP 中继 → 客户端失败: {e}")

                def error_received(self, exc):
                    logger.debug(f"UDP 中继错误: {exc}")

                def connection_lost(self, exc):
                    logger.debug("UDP 中继连接关闭")
                    try:
                        self._writer.close()
                    except Exception:
                        pass

            relay_proto = _UDPRelayProtocol(self, reader, writer)
            # 绑定到代理主机，系统分配端口
            transport, _ = await loop.create_datagram_endpoint(
                lambda: relay_proto,
                local_addr=(self.host, 0),
                allow_broadcast=False,
            )

            udp_port = transport.get_extra_info("sockname")[1]
            bind_addr = transport.get_extra_info("sockname")[0]

            # 返回成功响应，告诉客户端 UDP 中继地址
            resp = struct.pack("!BBBB", SOCKS5_VER, REP_SUCCESS, 0x00, ATYP_IPv4)
            resp += ipaddress.IPv4Address(bind_addr).packed
            resp += struct.pack("!H", udp_port)
            writer.write(resp)
            await writer.drain()

            # 保持 TCP 连接存活直到客户端关闭
            try:
                await reader.read()
            except Exception:
                pass
            finally:
                transport.close()
                try:
                    writer.close()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"UDP ASSOCIATE 失败: {e}")
            try:
                writer.write(struct.pack("!BBBB", SOCKS5_VER, 0x01, 0, ATYP_IPv4))
                writer.write(b"\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
            except Exception:
                pass

    async def _tcp_tunnel(self, reader, writer,
                          dst_ip: str, dst_port: int,
                          http_mode: bool = False,
                          original_host: Optional[str] = None):
        """
        建立 TCP 连接到目标（★ dst_ip 已通过 DoH 解析，不会触发明文 DNS）
        original_host: 原始域名（用于回调，非 None 表示经过了 DoH 解析）
        """
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(dst_ip, dst_port),
                timeout=10.0
            )
        except Exception as e:
            logger.debug(f"连接 {dst_ip}:{dst_port} 失败: {e}")
            if http_mode:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            else:
                writer.write(struct.pack("!BBBB", SOCKS5_VER, 4, 0, ATYP_IPv4))
                writer.write(b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            try:
                writer.close()
            except Exception:
                pass
            return

        # 获取实际解析到的 IP（此时 dst_ip 已经是 DoH 解析结果）
        peername = remote_writer.get_extra_info("peername")
        resolved_ip = peername[0] if peername else dst_ip

        # ★ 回调传入原始域名（供 injector 做同域名策略），而非 DoH 解析后的 IP
        callback_host = original_host or dst_ip
        if self.on_connection:
            self.on_connection(callback_host, resolved_ip, dst_port, "tcp")

        # 记录连接事件到 TrafficProfile
        if self._profile:
            self._profile.record_connection()

        # 回复成功
        if http_mode:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            bind = remote_writer.get_extra_info("sockname")
            resp = struct.pack("!BBBB", SOCKS5_VER, REP_SUCCESS, 0x00, ATYP_IPv4)
            resp += ipaddress.IPv4Address(bind[0]).packed
            resp += struct.pack("!H", bind[1] if bind else 0)
            writer.write(resp)
        await writer.drain()

        # ★ 双向转发 — 使用 FIRST_COMPLETED 避免 TCP-over-TCP 死锁
        # ★ TLS 模板捕获（在 relay 启动前顺序执行，避免与 relay 竞争 reader）
        if dst_port == 443 and self.on_tls_template:
            try:
                first_chunk = await asyncio.wait_for(
                    reader.read(2048), timeout=0.5)
                if first_chunk:
                    if len(first_chunk) >= 5 and first_chunk[0] == 0x16:
                        self.on_tls_template(first_chunk)
                        logger.debug(f"TLS CH 模板已捕获: {len(first_chunk)} 字节")
                    # 无论是否 TLS 模板，都将已读取的数据写入远程
                    remote_writer.write(first_chunk)
                    await remote_writer.drain()
            except (asyncio.TimeoutError, Exception):
                pass

        relay_task = asyncio.create_task(
            self._relay(reader, remote_writer, "upload"))
        download_task = asyncio.create_task(
            self._relay(remote_reader, writer, "download"))

        # ★ 任一 relay 完成后就关闭对应端，防止双方互等死锁
        done, pending = await asyncio.wait(
            [relay_task, download_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if relay_task in done:
            # 上传已完成（客户端发完关闭），通知服务器端也关闭
            try:
                remote_writer.close()
            except Exception:
                pass
        if download_task in done:
            # 下载已完成（服务器发完关闭），通知客户端也关闭
            try:
                writer.close()
            except Exception:
                pass

        # 取消并清理另一个未完成的 relay
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # 确保所有连接已关闭
        try:
            writer.close()
        except Exception:
            pass
        try:
            remote_writer.close()
        except Exception:
            pass

    async def _relay(self, reader, writer, direction: str = ""):
        try:
            while not reader.at_eof():
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                # ★ 传输中不 drain = 数据平滑不间断
                if self._profile:
                    self._profile.record_packet("tcp", len(data))
        except Exception as e:
            logger.debug(f"中继结束 ({direction}): {e}")
        finally:
            # ★ 无论循环正常结束还是异常退出，都 drain 一次确保缓冲数据发完
            try:
                await writer.drain()
            except Exception:
                pass
