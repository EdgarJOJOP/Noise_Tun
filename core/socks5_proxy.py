"""代理服务器 — 自动检测 SOCKS5 / HTTP CONNECT（支持用户名密码认证 + DoH 防 DNS 泄漏）"""

import asyncio
import logging
import struct
import ipaddress
import base64
from typing import Optional, Callable

logger = logging.getLogger("noisetunnel.proxy")

# SOCKS5 常量
SOCKS5_VER = 0x05
ATYP_IPv4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPv6 = 0x04
CMD_CONNECT = 0x01
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
                 enforce_doh_only: bool = True):
        """
        additional_bind: 可选 (host, port) 元组，监听额外地址供局域网使用
        username/password: SOCKS5/HTTP 认证凭据，留空则不启用认证
        doh_resolver: DoHResolver 实例，用于加密 DNS 解析
        enforce_doh_only: True=DoH失败时阻断连接，False=回退系统 DNS（可能泄漏）
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
            if self._enforce_doh_only:
                logger.warning("未配置 DoH 解析器！无法安全解析 %s，连接已阻断", host)
                return None
            else:
                logger.warning("未配置 DoH 解析器，域名 %s 将使用系统 DNS（可能泄漏）", host)
                return host
        try:
            v4, v6 = await self._doh.resolve(host)
            if v4:
                return v4[0]
            if v6:
                return v6[0]
            if self._enforce_doh_only:
                logger.debug("DoH 解析 %s 无结果（域名可能被加密DNS拦截），连接已阻断", host)
                return None
            else:
                logger.warning("DoH 解析 %s 无结果，使用系统 DNS 回退（可能泄漏）", host)
                return host
        except Exception as e:
            if self._enforce_doh_only:
                logger.debug("DoH 解析 %s 失败: %s，连接已阻断", host, e)
                return None
            else:
                logger.warning("DoH 解析 %s 失败: %s，使用系统 DNS 回退（可能泄漏）", host, e)
                return host

    # ------------------------------------------------------------------
    # 协议自动检测
    # ------------------------------------------------------------------

    async def _handle_client(self, reader, writer):
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
        else:
            bind = writer.get_extra_info("sockname")
            resp = struct.pack("!BBBB", SOCKS5_VER, REP_SUCCESS, 0x00, ATYP_IPv4)
            resp += ipaddress.IPv4Address(bind[0]).packed
            resp += struct.pack("!H", bind[1] if bind else 0)
            writer.write(resp)
            await writer.drain()
            try:
                await reader.read()
            except Exception:
                pass

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

        # 捕获 TLS Client Hello 作为噪声模板（仅限 443 端口）
        if dst_port == 443 and self.on_tls_template:
            try:
                first_chunk = await asyncio.wait_for(reader.read(2048), timeout=0.5)
                if len(first_chunk) >= 5 and first_chunk[0] == 0x16:
                    self.on_tls_template(first_chunk)
                    logger.debug(f"TLS CH 模板已捕获: {len(first_chunk)} 字节")
                if first_chunk:
                    remote_writer.write(first_chunk)
            except asyncio.TimeoutError:
                pass

        # 双向转发
        await asyncio.gather(
            self._relay(reader, remote_writer),
            self._relay(remote_reader, writer),
            return_exceptions=True,
        )

    async def _relay(self, reader, writer):
        try:
            while not reader.at_eof():
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"中继结束: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass
