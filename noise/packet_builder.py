"""IP/TCP/UDP/TLS 数据包构建器 — 全随机算法"""

import os
import struct
import logging
from typing import Optional

logger = logging.getLogger("noisetunnel.packet_builder")

# CSPRNG 随机字节生成
_rand = os.urandom


def randbytes(n: int) -> bytes:
    """返回 n 个密码学安全随机字节"""
    return _rand(n)


def randint(min_v: int, max_v: int) -> int:
    """返回 [min_v, max_v] 范围的随机整数（CSPRNG 硬件熵）"""
    span = max_v - min_v + 1
    if span <= 0:
        return min_v
    num_bytes = (span.bit_length() + 7) // 8
    mask = (1 << (num_bytes * 8)) - 1
    while True:
        val = int.from_bytes(randbytes(num_bytes), "big") & mask
        if val < span:
            return min_v + val


def randchoice(seq) -> object:
    """从序列中随机选一个元素（CSPRNG 硬件熵）"""
    if not seq:
        raise IndexError("Cannot choose from empty sequence")
    return seq[randint(0, len(seq) - 1)]


def randfloat() -> float:
    """返回 [0.0, 1.0) 随机浮点数（CSPRNG 硬件熵）"""
    return int.from_bytes(randbytes(7), "big") / (1 << 56)


# ------------------------------------------------------------------
# IP 头构建
# ------------------------------------------------------------------

def build_ip_header(total_length: int, protocol: int,
                    src_ip: str = "10.99.0.2",
                    dst_ip: str = "1.1.1.1") -> bytes:
    """
    构建 IPv4 头（全随机字段 + 自动校验和）
    """
    version_ihl = 0x45  # 版本=4, IHL=5
    dscp_ecn = randbytes(1)[0] & 0xFC  # 随机 DSCP/ECN
    identification = int.from_bytes(randbytes(2), "big")
    flags_offset = int.from_bytes(randbytes(2), "big")
    ttl = randint(64, 255)
    header_checksum = 0  # 临时

    # 解析 IP
    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))

    # 格式: ver_ihl(1) + dscp_ecn(1) + total_len(2) + id(2) + flags(2) + ttl(1) + proto(1) + chk(2)
    header = struct.pack("!BBHHHBBH",
                         version_ihl, dscp_ecn,
                         total_length,
                         identification, flags_offset,
                         ttl, protocol,
                         header_checksum)
    header += src_bytes + dst_bytes

    # 计算校验和
    checksum = _ip_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]

    return header


def _ip_checksum(data: bytes) -> int:
    """计算 IP 首部校验和"""
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


# ------------------------------------------------------------------
# TCP 头构建
# ------------------------------------------------------------------

def build_tcp_header(src_port: int, dst_port: int,
                     seq_num: int, ack_num: int = 0,
                     flags: int = 0x02,  # SYN
                     window: Optional[int] = None,
                     options: Optional[bytes] = None) -> tuple:
    """
    构建 TCP 头

    返回:
        (tcp_header_bytes, header_length)
        header_length 是 TCP 头实际长度（含选项填充后的长度）
    """
    window = window if window is not None else randint(65535, 65535)
    data_offset = 5  # 5 * 4 = 20 字节，无选项
    reserved = 0
    urg_ptr = 0

    # 如果有选项，调整 data_offset
    if options:
        opt_len = len(options)
        opt_padded = options + b"\x00" * ((4 - opt_len % 4) % 4)
        data_offset = 5 + len(opt_padded) // 4
        options = opt_padded
    else:
        opt_padded = b""

    data_offset_reserved = (data_offset << 4) | reserved
    checksum = 0  # 临时

    header = struct.pack("!HHIIBBHHH",
                         src_port, dst_port,
                         seq_num, ack_num,
                         data_offset_reserved, flags,
                         window, checksum, urg_ptr)
    header += opt_padded

    header_length = data_offset * 4

    return header, header_length


def compute_tcp_checksum(ip_src: bytes, ip_dst: bytes,
                         tcp_header: bytes, payload: bytes) -> int:
    """计算 TCP 校验和（含伪首部）"""
    tcp_segment = tcp_header + payload
    pseudo = ip_src + ip_dst
    pseudo += struct.pack("!BBH", 0, 6, len(tcp_segment))
    if len(pseudo) % 2 == 1:
        pseudo += b"\x00"

    data = pseudo + tcp_segment
    if len(data) % 2 == 1:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


# ------------------------------------------------------------------
# UDP 头构建
# ------------------------------------------------------------------

def build_udp_header(src_port: int, dst_port: int,
                     payload_length: int) -> bytes:
    """构建 UDP 头"""
    length = 8 + payload_length
    checksum = 0  # 可选，置 0 表示不校验
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


# ------------------------------------------------------------------
# TLS Client Hello 构建（全随机结构）
# ------------------------------------------------------------------

def build_fake_tls_client_hello(fake_sni: Optional[str] = None) -> bytes:
    """
    构造一个结构完整的假 TLS Client Hello 记录
    所有字段均为 CSPRNG 随机

    参数:
        fake_sni: 如果提供，在 TLS 扩展中嵌入一个 SNI (server_name) 扩展
                  使噪声包在明文 SNI 场景下显得更真实
    """
    # --- TLS 记录层 ---
    content_type = bytes([0x16])  # Handshake
    # 随机 TLS 版本
    tls_version = randbytes(2)
    # 确保版本合法
    if tls_version[0] == 0x03 and tls_version[1] in (0x00, 0x01, 0x02, 0x03, 0x04):
        pass
    else:
        tls_version = bytes([0x03, [0x01, 0x03, 0x04][randint(0, 2)]])

    # --- Handshake 层 ---
    handshake_type = bytes([0x01])  # Client Hello

    # --- 拼装 ---
    random_bytes = randbytes(32)
    session_id_len = randint(0, 32)
    session_id = randbytes(session_id_len)

    # 随机密码套件（偶数个）
    cs_count = randint(2, 16) * 2
    cipher_suites = randbytes(cs_count)

    compression_len = 1
    compression = bytes([randint(0, 255)])

    # 随机扩展 + 可选假 SNI
    ext_count = randint(0, 8)
    extensions = b""

    # 如果提供了假 SNI，先插入 SNI 扩展（type=0x0000）
    if fake_sni:
        sni_name = fake_sni.encode("utf-8")
        sni_ext_body = (
            # server_name_list length (2 bytes)
            struct.pack("!H", len(sni_name) + 3) +
            # NameType: host_name (0x00)
            b"\x00" +
            # Name length (2 bytes)
            struct.pack("!H", len(sni_name)) +
            sni_name
        )
        extensions += b"\x00\x00" + struct.pack("!H", len(sni_ext_body)) + sni_ext_body

    # 其他随机扩展
    for _ in range(ext_count):
        ext_type = randbytes(2)
        ext_len = randint(0, 100)
        ext_data = randbytes(ext_len)
        extensions += ext_type + struct.pack("!H", ext_len) + ext_data

    # 版本字段（ClientHello 内）
    ch_version = tls_version

    # 组装 ClientHello body
    ch_body = ch_version + random_bytes + bytes([session_id_len]) + session_id
    ch_body += struct.pack("!H", cs_count) + cipher_suites
    ch_body += bytes([compression_len]) + compression
    ch_body += struct.pack("!H", len(extensions)) + extensions

    # 再包 Handshake 层
    hs_body = handshake_type + len(ch_body).to_bytes(3, "big") + ch_body

    # 最后包记录层
    record_body = content_type + tls_version + struct.pack("!H", len(hs_body))
    record = record_body + hs_body

    return record
