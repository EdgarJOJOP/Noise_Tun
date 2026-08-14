#!/usr/bin/env python3
"""上传吞吐验证测试 — 启动 test server + proxy（关噪声），测上传速度"""
import asyncio, logging, time, struct, socket

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TEST] %(message)s")
log = logging.getLogger("test")
logging.getLogger("noisetunnel").setLevel(logging.CRITICAL + 1)  # 关噪声日志

TEST_PORT = 18999
PROXY_PORT = 10860
UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

class UploadSink:
    """接收上传数据并计速"""
    async def handle(self, reader, writer):
        total = 0
        start = time.time()
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=10.0)
                if not data:
                    break
                total += len(data)
        except asyncio.TimeoutError:
            log.warning("SINK 读超时")
        except Exception:
            pass
        elapsed = time.time() - start
        mbps = total * 8 / elapsed / 1_000_000 if elapsed > 0 else 0
        log.info(f"SINK: 收到 {total/1024/1024:.1f}MB, {elapsed:.1f}s, {mbps:.1f} Mbps")
        try:
            writer.close()
        except Exception:
            pass

async def socks5_connect(reader, writer, host, port):
    """SOCKS5 CONNECT"""
    writer.write(bytes([0x05, 0x01, 0x00]))
    await writer.drain()
    resp = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
    assert resp == bytes([0x05, 0x00]), f"握手失败: {resp.hex()}"
    if ":" in host:
        atyp, host_bytes = 0x04, socket.inet_pton(socket.AF_INET6, host)
    elif host.replace(".", "").isdigit():
        atyp, host_bytes = 0x01, socket.inet_pton(socket.AF_INET, host)
    else:
        atyp, host_bytes = 0x03, bytes([len(host)]) + host.encode()
    req = bytes([0x05, 0x01, 0x00, atyp]) + host_bytes + struct.pack("!H", port)
    writer.write(req)
    await writer.drain()
    resp = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
    assert resp[1] == 0x00, f"CONNECT 失败: code={resp[1]}"
    atyp = resp[3]
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x03:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    else:
        await reader.readexactly(18)

async def send_all(writer, data, chunk_size=65536):
    """发送所有数据"""
    total = 0
    while total < len(data):
        chunk = data[total:total + chunk_size]
        writer.write(chunk)
        total += len(chunk)
    await writer.drain()

async def main():
    # 1. 启动 test server
    srv = await asyncio.start_server(UploadSink().handle, "127.0.0.1", TEST_PORT)
    log.info(f"Test server: 127.0.0.1:{TEST_PORT}")

    # 2. 启动 proxy
    from core.socks5_proxy import ProxyServer
    proxy = ProxyServer(host="127.0.0.1", port=PROXY_PORT)
    await proxy.start()
    log.info(f"Proxy: 127.0.0.1:{PROXY_PORT}")
    await asyncio.sleep(0.3)

    # 3. BASELINE: 直接连接 test server（不经过 proxy）
    log.info("开始 BASELINE 直连测试...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", TEST_PORT), timeout=5.0)
        data = b"x" * UPLOAD_SIZE
        start = time.time()
        await send_all(writer, data)
        # 发送 FIN 通知服务器结束
        writer.write_eof()
        await asyncio.sleep(0.5)
        writer.close()
        elapsed = time.time() - start
        baseline_mbps = UPLOAD_SIZE * 8 / elapsed / 1_000_000
        log.info(f"BASELINE 直连: {elapsed:.1f}s, {baseline_mbps:.1f} Mbps")
    except Exception as e:
        log.error(f"BASELINE 失败: {e}")
        baseline_mbps = 0

    await asyncio.sleep(1)

    # 4. PROXY: 通过 SOCKS5 proxy 上传
    log.info("开始 PROXY 上传测试...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", PROXY_PORT), timeout=5.0)
        await asyncio.wait_for(
            socks5_connect(reader, writer, "127.0.0.1", TEST_PORT), timeout=10.0)
        log.info("SOCKS5 CONNECT 成功，开始上传 5MB...")

        data = b"x" * UPLOAD_SIZE
        start = time.time()
        await send_all(writer, data)
        # 通知服务器结束
        writer.write_eof()
        await asyncio.sleep(0.5)
        writer.close()
        elapsed = time.time() - start
        proxy_mbps = UPLOAD_SIZE * 8 / elapsed / 1_000_000
        log.info(f"PROXY 上传:  {elapsed:.1f}s, {proxy_mbps:.1f} Mbps")
    except asyncio.TimeoutError:
        log.error("PROXY 测试超时")
        proxy_mbps = 0
    except Exception as e:
        log.error(f"PROXY 测试失败: {e}")
        proxy_mbps = 0

    log.info(f"===== 结果: baseline={baseline_mbps:.1f} Mbps, proxy={proxy_mbps:.1f} Mbps =====")

    await proxy.stop()
    srv.close()
    await srv.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
