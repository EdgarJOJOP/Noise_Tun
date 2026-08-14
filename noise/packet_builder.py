"""IP/TCP/UDP/TLS 数据包构建器 — 全随机算法"""

import os
import struct
import ipaddress
import logging
from typing import Optional, List

# 有效椭圆曲线公钥生成（用于 TLS key_share 扩展）
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

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
    # 常见 DSCP 值 (6-bit DSCP << 2, ECN=00):
    # BE(0x00), CS1(0x20), AF11(0x28), AF12(0x30), AF13(0x38),
    # AF21(0x48), AF22(0x50), AF23(0x58), AF31(0x68), AF41(0x88), EF(0xB8)
    dscp_ecn = bytes([randchoice([0x00, 0x20, 0x28, 0x30, 0x38, 0x48, 0x50, 0x58, 0x68, 0x88, 0xB8])])[0]
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


def build_ipv6_header(payload_length: int, protocol: int,
                      src_ip: str, dst_ip: str) -> bytes:
    """
    构建 IPv6 头（40 字节固定, 随机流标签 + 跳限）
    """
    version = 6
    # IPv6 流量类别使用与 IPv4 DSCP 相同的常见值
    traffic_class = randchoice([0x00, 0x20, 0x28, 0x30, 0x38, 0x48, 0x50, 0x58, 0x68, 0x88, 0xB8])
    flow_label = randint(0, 0xFFFFF)
    ver_tc_flow = (version << 28) | (traffic_class << 20) | flow_label
    next_header = protocol
    hop_limit = randint(64, 255)
    src_bytes = ipaddress.IPv6Address(src_ip).packed
    dst_bytes = ipaddress.IPv6Address(dst_ip).packed
    return (struct.pack("!I", ver_tc_flow) +
            struct.pack("!H", payload_length) +
            struct.pack("!BB", next_header, hop_limit) +
            src_bytes + dst_bytes)


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
                         tcp_header: bytes, payload: bytes,
                         is_ipv6: bool = False) -> int:
    """计算 TCP 校验和（含伪首部, 支持 IPv4 和 IPv6）"""
    tcp_segment = tcp_header + payload
    if is_ipv6:
        # IPv6 伪首部: src(16B) + dst(16B) + length(4B) + next_header(4B)
        pseudo = ip_src + ip_dst
        pseudo += struct.pack("!I", len(tcp_segment))
        pseudo += struct.pack("!BBBB", 0, 0, 0, 6)  # zeros + TCP proto=6
    else:
        # IPv4 伪首部: src(4B) + dst(4B) + zeros(1B) + proto(1B) + length(2B)
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

def build_fake_tls_client_hello(
        fake_sni: Optional[str] = None,
        cipher_suites: Optional[bytes] = None,
        extensions: Optional[List[tuple]] = None,
) -> bytes:
    """
    构造 TLS 1.2 Client Hello 记录

    参数:
        fake_sni: 可选, 嵌入 SNI 扩展的假域名
        cipher_suites: 可选, 密码套件字节序列。None=随机生成
        extensions: 可选, [(ext_type_int, ext_data_bytes), ...] 的扩展列表。
                    None=随机生成

    当提供 cipher_suites/extensions 时, 使用真实浏览器指纹参数;
    否则回退到全随机模式。
    """
    content_type = bytes([0x16])  # Handshake
    tls_version = randbytes(2)
    if tls_version[0] == 0x03 and tls_version[1] in (0x00, 0x01, 0x02, 0x03, 0x04):
        pass
    else:
        tls_version = bytes([0x03, [0x01, 0x03, 0x04][randint(0, 2)]])

    handshake_type = bytes([0x01])  # Client Hello
    random_bytes = randbytes(32)
    session_id_len = randint(0, 32)
    session_id = randbytes(session_id_len)

    # 密码套件: 指定或随机
    if cipher_suites is not None and len(cipher_suites) >= 2:
        cs_bytes = cipher_suites
        cs_count = len(cs_bytes)
    else:
        cs_count = randint(2, 16) * 2
        cs_bytes = randbytes(cs_count)

    compression_len = 1
    compression = bytes([0x00])  # TLS 1.2 通常用 null compression

    # 构建扩展
    ext_bytes = b""

    # SNI 扩展 (type=0x0000), 优先于传入的扩展列表
    if fake_sni:
        sni_name = fake_sni.encode("utf-8")
        sni_ext_body = (
            struct.pack("!H", len(sni_name) + 3) +
            b"\x00" +
            struct.pack("!H", len(sni_name)) +
            sni_name
        )
        ext_bytes += b"\x00\x00" + struct.pack("!H", len(sni_ext_body)) + sni_ext_body

    if extensions is not None:
        # 使用传入的真实扩展列表
        for ext_type, ext_data in extensions:
            ext_bytes += struct.pack("!H", ext_type) + struct.pack("!H", len(ext_data)) + ext_data
    else:
        # 随机扩展 (不含 SNI)
        ext_count = randint(0, 8)
        for _ in range(ext_count):
            ext_type = randbytes(2)
            ext_len = randint(0, 100)
            ext_data = randbytes(ext_len)
            ext_bytes += ext_type + struct.pack("!H", ext_len) + ext_data

    ch_version = tls_version

    ch_body = ch_version + random_bytes + bytes([session_id_len]) + session_id
    ch_body += struct.pack("!H", cs_count) + cs_bytes
    ch_body += bytes([compression_len]) + compression
    ch_body += struct.pack("!H", len(ext_bytes)) + ext_bytes

    hs_body = handshake_type + len(ch_body).to_bytes(3, "big") + ch_body
    record_body = content_type + tls_version + struct.pack("!H", len(hs_body))
    return record_body + hs_body


# ══════════════════════════════════════════════════════════════════════
# 有效椭圆曲线公钥生成（用于 TLS key_share 扩展）
# ══════════════════════════════════════════════════════════════════════

def _gen_x25519_pubkey() -> bytes:
    """生成真正的 X25519 公钥（32 字节 RFC 7748 格式）"""
    if _HAS_CRYPTOGRAPHY:
        priv = X25519PrivateKey.generate()
        return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # fallback: 随机字节（至少比全零好）
    return randbytes(32)


def _gen_p256_pubkey() -> bytes:
    """生成真正的 P-256 公钥（65 字节未压缩 X9.62 格式）"""
    if _HAS_CRYPTOGRAPHY:
        priv = generate_private_key(SECP256R1())
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    # fallback: 随机字节
    return randbytes(65)


# ══════════════════════════════════════════════════════════════════════
# TLS 1.3 ClientHello
# ══════════════════════════════════════════════════════════════════════

def build_fake_tls13_client_hello(
        fake_sni: Optional[str] = None,
        cipher_suites: Optional[bytes] = None,
        extensions: Optional[List[tuple]] = None,
) -> bytes:
    """
    构造 TLS 1.3 Client Hello

    参数:
        fake_sni: 可选, 嵌入 SNI 扩展的假域名
        cipher_suites: 可选, TLS 1.3 密码套件字节序列。None=使用默认
        extensions: 可选, [(ext_type_int, ext_data_bytes), ...] 的扩展列表。
                    None=使用内置真实浏览器扩展

    当提供参数时, 使用来自 curl_cffi 等指纹库的真实浏览器参数;
    否则使用内置的通用 TLS 1.3 配置。
    """
    content_type = bytes([0x16])  # Handshake
    tls_version = bytes([0x03, 0x03])  # 记录层版本仍用 1.2

    handshake_type = bytes([0x01])  # Client Hello

    random_bytes = randbytes(32)
    session_id_len = 32
    session_id = randbytes(session_id_len)

    # 密码套件
    if cipher_suites is not None and len(cipher_suites) >= 2:
        tls13_ciphers = cipher_suites
        cs_count = len(tls13_ciphers)
    else:
        tls13_ciphers = bytes([
            0x13, 0x01,  # TLS_AES_128_GCM_SHA256
            0x13, 0x02,  # TLS_AES_256_GCM_SHA384
            0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256
        ])
        cs_count = len(tls13_ciphers)

    compression_len = 1
    compression = bytes([0x00])  # TLS 1.3 只允许 null compression

    # ---- 构建扩展 ----
    ext_bytes = b""

    # SNI 扩展 (type=0x0000), 优先于传入列表
    if fake_sni:
        sni_name = fake_sni.encode("utf-8")
        sni_ext_body = (
            struct.pack("!H", len(sni_name) + 3) +
            b"\x00" +
            struct.pack("!H", len(sni_name)) +
            sni_name
        )
        ext_bytes += b"\x00\x00" + struct.pack("!H", len(sni_ext_body)) + sni_ext_body

    if extensions is not None:
        # 使用传入的真实扩展列表 (e.g. from curl_cffi)
        # 注意: 扩展列表应包含 supported_versions, key_share 等必备项
        for ext_type, ext_data in extensions:
            ext_bytes += struct.pack("!H", ext_type) + struct.pack("!H", len(ext_data)) + ext_data
    else:
        # 内置通用 TLS 1.3 扩展
        # supported_versions (type=0x002b)
        sv_body = bytes([0x03, 0x04])  # TLS 1.3 = 0x0304
        ext_bytes += b"\x00\x2b" + struct.pack("!H", len(sv_body)) + sv_body

        # key_share (type=0x0033) — 使用真正的椭圆曲线公钥
        ks_group = randchoice([b"\x00\x1d", b"\x00\x17"])
        ks_key = _gen_x25519_pubkey() if ks_group == b"\x00\x1d" else _gen_p256_pubkey()
        ks_entry = ks_group + struct.pack("!H", len(ks_key)) + ks_key
        ks_body = struct.pack("!H", len(ks_entry)) + ks_entry
        ext_bytes += b"\x00\x33" + struct.pack("!H", len(ks_body)) + ks_body

        # signature_algorithms (type=0x000d)
        sig_algs = bytes([0x04, 0x03, 0x08, 0x04, 0x08, 0x07, 0x04, 0x01])
        sig_body = struct.pack("!H", len(sig_algs)) + sig_algs
        ext_bytes += b"\x00\x0d" + struct.pack("!H", len(sig_body)) + sig_body

        # supported_groups (type=0x000a)
        groups = bytes([0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e])
        groups_body = struct.pack("!H", len(groups)) + groups
        ext_bytes += b"\x00\x0a" + struct.pack("!H", len(groups_body)) + groups_body

        # psk_key_exchange_modes (type=0x002d)
        psk_modes = bytes([0x01, 0x01])
        ext_bytes += b"\x00\x2d" + struct.pack("!H", len(psk_modes)) + psk_modes

    # ---- 组装 ----
    ch_body = tls_version + random_bytes + bytes([session_id_len]) + session_id
    ch_body += struct.pack("!H", cs_count) + tls13_ciphers
    ch_body += bytes([compression_len]) + compression
    ch_body += struct.pack("!H", len(ext_bytes)) + ext_bytes

    hs_body = handshake_type + len(ch_body).to_bytes(3, "big") + ch_body
    record_body = content_type + tls_version + struct.pack("!H", len(hs_body))
    return record_body + hs_body
