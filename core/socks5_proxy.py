"""代理服务器 — 自动检测 SOCKS5 / HTTP CONNECT"""

import asyncio
import logging
import struct
import ipaddress
from typing import Optional, Callable

logger = logging.getLogger("noisetunnel.proxy")

# SOCKS5 常量
SOCKS5_VER = 0x05
ATYP_IPv4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPv6 = 0x04
CMD_CONNECT = 0x01
REP_SUCCESS = 0x00


class ProxyServer:
    """
    代理服务器 — 自动检测 SOCKS5 / HTTP CONNECT

    - Windows 系统代理 → HTTP CONNECT
    - 浏览器/扩展配代理 → SOCKS5
    - 自动识别，无需选择
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1086,
                 on_connection: Optional[Callable] = None,
                 on_tls_template: Optional[Callable] = None,
                 additional_bind: Optional[tuple] = None):
        """
        additional_bind: 可选 (host, port) 元组，监听额外地址供局域网使用
        """
        self.host = host
        self.port = port
        self.on_connection = on_connection
        self.on_tls_template = on_tls_template
        self._server: Optional[asyncio.AbstractServer] = None
        self._server2: Optional[asyncio.AbstractServer] = None
        self._additional_bind = additional_bind

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        listeners = self._server.sockets
        addr = listeners[0].getsockname() if listeners else (self.host, self.port)
        logger.info(f"代理已启动 (SOCKS5 + HTTP CONNECT): {addr[0]}:{addr[1]}")

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
    # SOCKS5
    # ------------------------------------------------------------------

    async def _handle_socks5(self, reader, writer):
        # 握手（首字节已读）
        nmethods = (await reader.readexactly(1))[0]
        await reader.readexactly(nmethods)
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

        if cmd == CMD_CONNECT:
            await self._tcp_tunnel(reader, writer, dst_host, dst_port,
                                   http_mode=False)
        else:
            # UDP ASSOCIATE / 其他
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
    # HTTP CONNECT
    # ------------------------------------------------------------------

    async def _handle_http_connect(self, reader, writer, first_byte):
        # 读取剩余请求行
        data = first_byte + await reader.readuntil(b"\r\n")
        line = data.decode("utf-8", errors="replace").strip()
        logger.debug(f"HTTP CONNECT: {line}")

        if not line.upper().startswith("CONNECT "):
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # 解析 CONNECT host:port HTTP/1.1
        parts = line[8:].split(" ")
        hostport = parts[0]
        if ":" in hostport:
            dst_host, port_str = hostport.rsplit(":", 1)
            dst_port = int(port_str)
        else:
            dst_host = hostport
            dst_port = 443

        # 丢弃剩余请求头
        while True:
            h = await reader.readuntil(b"\r\n")
            if h in (b"\r\n", b"\n"):
                break

        await self._tcp_tunnel(reader, writer, dst_host, dst_port,
                               http_mode=True)

    # ------------------------------------------------------------------
    # TCP 隧道（SOCKS5 + HTTP CONNECT 共用）
    # ------------------------------------------------------------------

    async def _tcp_tunnel(self, reader, writer,
                          dst_host: str, dst_port: int,
                          http_mode: bool = False):
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(dst_host, dst_port),
                timeout=10.0
            )
        except Exception as e:
            logger.debug(f"连接 {dst_host}:{dst_port} 失败: {e}")
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

        # 获取实际解析到的 IP
        peername = remote_writer.get_extra_info("peername")
        resolved_ip = peername[0] if peername else dst_host

        if self.on_connection:
            self.on_connection(dst_host, resolved_ip, dst_port, "tcp")

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
                    # 是 TLS 握手，保存为模板（不含 SNI 等隐私）
                    self.on_tls_template(first_chunk)
                    logger.debug(f"TLS CH 模板已捕获: {len(first_chunk)} 字节")
                # 转发给远程
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
