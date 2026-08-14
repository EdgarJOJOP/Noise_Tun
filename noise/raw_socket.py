"""Raw Socket 注入器 — 通过 Npcap 直接发送预构建 IP 包

三级降级策略:
  1. Npcap ctypes (pcap_sendpacket) — 最优先, 需安装 Npcap
  2. pypcap (pcap.pcap) — 次优先, 需 pip install pypcap
  3. 普通 socket fallback — 保留当前行为, 发出警告

所有路径最终调用 send_ipv4_tcp / send_ipv4_udp 接口。
"""

import asyncio
import ctypes
import ctypes.wintypes
import logging
import struct
from typing import Optional

logger = logging.getLogger("noisetunnel.raw_socket")

# ======================================================================
# Npcap 适配器封装 (ctypes 调用 wpcap.dll)
# ======================================================================

class _NpcapAdapter:
    """通过 Npcap wpcap.dll 发送 L2 帧"""

    def __init__(self):
        self._wpcap = None
        self._adapter = None
        self._available = False
        self.local_mac: Optional[bytes] = None  # 本机真实 MAC
        self.gateway_mac: Optional[bytes] = None  # 网关 MAC（通过 ARP）

    def _resolve_local_mac(self) -> Optional[bytes]:
        """通过 uuid.getnode() 获取本机 MAC（纯 Python，最可靠）"""
        try:
            import uuid
            mac_int = uuid.getnode()
            # getnode() 返回 48 位整数
            # 第 40 位为 0 表示是真实 MAC（非随机生成）
            if mac_int is not None and (mac_int >> 40) % 2 == 0:
                mac_bytes = mac_int.to_bytes(6, 'big')
                if mac_bytes != b'\x00' * 6:
                    return mac_bytes
        except Exception:
            pass

        # 备选：通过注册表读取网络适配器地址
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}')
            for i in range(99):
                try:
                    subkey = winreg.OpenKeyEx(key, f'{i:04d}')
                    try:
                        mac_str = winreg.QueryValueEx(subkey, 'NetworkAddress')[0]
                        mac_bytes = bytes.fromhex(mac_str.replace('-', '').replace(':', ''))
                        if len(mac_bytes) == 6 and mac_bytes != b'\x00' * 6:
                            return mac_bytes
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                except FileNotFoundError:
                    continue
            winreg.CloseKey(key)
        except Exception:
            pass

        return None

    def try_init(self) -> bool:
        """尝试加载 wpcap.dll 并打开第一个可用适配器"""
        try:
            self._wpcap = ctypes.CDLL("wpcap.dll")
        except OSError:
            logger.info("Npcap (wpcap.dll) 未安装, 跳过 Raw Socket 注入")
            return False

        # pcap_findalldevs_ex 获取适配器列表
        errbuf = ctypes.create_string_buffer(256)
        alldevs = ctypes.c_void_p(0)

        self._wpcap.pcap_findalldevs_ex.argtypes = [
            ctypes.c_char_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p,
        ]
        self._wpcap.pcap_findalldevs_ex.restype = ctypes.c_int

        ret = self._wpcap.pcap_findalldevs_ex(
            b"rpcap://",
            None,
            ctypes.byref(alldevs),
            errbuf,
        )
        if ret != 0 or not alldevs:
            logger.warning(f"Npcap 找不到网络适配器: {errbuf.value.decode()}")
            return False

        # 遍历适配器链表, 找到第一个名称含 "Adapter" 的
        try:
            adapter_name = self._find_first_adapter(alldevs)
            if not adapter_name:
                logger.warning("Npcap 找不到可用适配器")
                return False

            # 打开适配器
            self._wpcap.pcap_open.argtypes = [
                ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p,
            ]
            self._wpcap.pcap_open.restype = ctypes.c_void_p

            self._adapter = self._wpcap.pcap_open(
                adapter_name,
                65535,          # snaplen
                1,              # promisc
                1000,           # timeout ms
                None,
                errbuf,
            )
            if not self._adapter:
                logger.warning(f"Npcap 打开适配器失败: {errbuf.value.decode()}")
                return False

            # 设置 pcap_sendpacket 参数
            self._wpcap.pcap_sendpacket.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
            ]
            self._wpcap.pcap_sendpacket.restype = ctypes.c_int

            self._available = True
            # 获取本机真实 MAC 地址
            self.local_mac = self._resolve_local_mac()
            if self.local_mac:
                mac_str = ":".join(f"{b:02x}" for b in self.local_mac)
                logger.info(f"Npcap Raw Socket 就绪 (适配器: {adapter_name.decode()}, MAC: {mac_str})")
            else:
                logger.warning("无法获取本机 MAC, 以太网帧将使用默认地址")
                logger.info(f"Npcap Raw Socket 就绪 (适配器: {adapter_name.decode()})")
            return True

        finally:
            if alldevs and self._wpcap:
                self._wpcap.pcap_freealldevs.argtypes = [ctypes.c_void_p]
                self._wpcap.pcap_freealldevs(alldevs)

    def _find_first_adapter(self, alldevs) -> Optional[bytes]:
        """遍历 pcap 设备链表找第一个适配器名称"""
        # 使用 ctypes Structure 明确定义 pcap_if
        class _pcap_if(ctypes.Structure):
            pass
        _pcap_if._fields_ = [
            ("next", ctypes.POINTER(_pcap_if)),
            ("name", ctypes.c_char_p),
            ("description", ctypes.c_char_p),
            ("addresses", ctypes.c_void_p),
            ("flags", ctypes.c_uint),
        ]

        ptr = ctypes.cast(alldevs, ctypes.POINTER(_pcap_if))
        for _ in range(20):
            if not ptr:
                break
            if ptr.contents.name:
                return ptr.contents.name
            ptr = ptr.contents.next
        return None

    def send(self, packet: bytes) -> bool:
        """发送 L2 帧 (已包含以太网头)"""
        if not self._available or not self._wpcap or not self._adapter:
            return False
        try:
            ret = self._wpcap.pcap_sendpacket(
                self._adapter,
                packet,
                len(packet),
            )
            return ret == 0
        except Exception as e:
            logger.debug(f"Npcap 发送失败: {e}")
            return False

    def close(self):
        if self._adapter and self._wpcap:
            self._wpcap.pcap_close.argtypes = [ctypes.c_void_p]
            self._wpcap.pcap_close(self._adapter)
            self._adapter = None
        self._available = False


# ======================================================================
# Raw Socket 注入器 (主类)
# ======================================================================

class RawInjector:
    """三级降级 Raw Socket 注入器

    使用方式:
        raw = RawInjector()
        await raw.start()
        await raw.send_ipv4_tcp(full_packet, dst_ip, dst_port)
        await raw.stop()
    """

    def __init__(self):
        self._npcap = _NpcapAdapter()
        self._mode = 0   # 0=uninit, 1=npcap, 2=pypcap, 3=fallback
        self._loop = None
        self._fallback_udp_sock = None
        self._pcap = None

    async def start(self):
        """初始化注入器, 检测可用后端"""
        self._loop = asyncio.get_event_loop()

        # 1) 尝试 Npcap
        if self._npcap.try_init():
            self._mode = 1
            logger.info("RawInjector: 使用 Npcap 模式 (L2 注入)")
            return

        # 2) 尝试 pypcap
        try:
            import pypcap
            self._pcap = pypcap.pcap()
            self._pcap.open()
            self._mode = 2
            logger.info("RawInjector: 使用 pypcap 模式")
            return
        except (ImportError, Exception):
            pass

        # 3) Fallback: 保留原行为
        import socket as _sock
        try:
            self._fallback_udp_sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            logger.warning("⚠️ Raw Socket 不可用, 使用普通 socket fallback")
            logger.warning("   噪声包的 IP/TCP 头将被内核重写, 抗 ML 效果大减!")
            logger.warning("   请安装 Npcap: https://npcap.com/")
        except Exception:
            pass
        self._mode = 3

    async def stop(self):
        if self._npcap:
            self._npcap.close()
        if self._fallback_udp_sock:
            try:
                self._fallback_udp_sock.close()
            except Exception:
                pass
        self._mode = 0

    @property
    def is_raw(self) -> bool:
        """是否真正的 Raw 模式 (Npcap/pypcap)"""
        return self._mode in (1, 2)

    # ------------------------------------------------------------------
    # 发送接口
    # ------------------------------------------------------------------

    async def send_ipv4_tcp(self, full_packet: bytes,
                            dst_ip: str, dst_port: int):
        """发送已构建的完整 IPv4+TCP 包"""
        if self._mode == 1:
            await self._send_npcap(full_packet)
        elif self._mode == 2:
            await self._send_pypcap(full_packet)
        else:
            await self._send_fallback_tcp(full_packet, dst_ip, dst_port)

    async def send_ipv4_udp(self, full_packet: bytes,
                            dst_ip: str, dst_port: int):
        """发送已构建的完整 IPv4+UDP 包"""
        if self._mode == 1:
            await self._send_npcap(full_packet)
        elif self._mode == 2:
            await self._send_pypcap(full_packet)
        else:
            await self._send_fallback_udp(full_packet, dst_ip, dst_port)

    # ------------------------------------------------------------------
    # 内部发送实现
    # ------------------------------------------------------------------

    async def _send_npcap(self, packet: bytes):
        """通过 Npcap 发送完整以太网帧"""
        # 从 IP 头第一个字节判断 IPv4(0x45) 或 IPv6(0x60)
        is_ipv6 = len(packet) > 0 and (packet[0] >> 4) == 6
        eth_type = b"\x86\xDD" if is_ipv6 else b"\x08\x00"
        # 使用本机真实 MAC 作为源，网关 MAC 作为目标
        src_mac = self._npcap.local_mac if self._npcap.local_mac else b"\x00" * 6
        # 获取网关 MAC（优先使用 ARP 缓存的网关 MAC，否则使用本机 MAC）
        dst_mac = getattr(self._npcap, 'gateway_mac', None) or src_mac
        eth_header = (
            dst_mac                          # dst MAC (本机)
            + src_mac                         # src MAC (本机)
            + eth_type                        # EtherType
        )
        frame = eth_header + packet
        self._npcap.send(frame)

    async def _send_pypcap(self, packet: bytes):
        """通过 pypcap 发送"""
        try:
            self._pcap.send(packet)
        except Exception as e:
            logger.debug(f"pypcap 发送失败: {e}")

    async def _send_fallback_tcp(self, packet: bytes,
                                 dst_ip: str, dst_port: int):
        """普通 TCP socket fallback (仅 TLS 载荷到达线路, 双栈)"""
        def _send():
            import socket as _sock
            try:
                is6 = ":" in dst_ip
                family = _sock.AF_INET6 if is6 else _sock.AF_INET
                s = _sock.socket(family, _sock.SOCK_STREAM)
                s.settimeout(3.0)
                s.setsockopt(_sock.SOL_SOCKET, _sock.SO_LINGER,
                             struct.pack("ii", 1, 0))
                s.connect((dst_ip, dst_port))
                # 跳过 IP 头 (IPv4=20, IPv6=40) + TCP 头 (20)
                payload_offset = 60 if is6 else 40
                tls_part = packet[payload_offset:]
                if tls_part:
                    s.send(tls_part)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        await self._loop.run_in_executor(None, _send)

    async def _send_fallback_udp(self, packet: bytes,
                                 dst_ip: str, dst_port: int):
        """普通 UDP socket fallback"""
        if self._fallback_udp_sock:
            try:
                udp_part = packet[20:]  # 跳过 IP 头
                self._fallback_udp_sock.sendto(udp_part, (dst_ip, dst_port))
            except Exception:
                pass
