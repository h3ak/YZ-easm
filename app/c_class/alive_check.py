import socket
import struct
import time

def make_icmp_packet() -> bytes:
    """
    构造 ICMP 请求数据包。
    :return: ICMP 数据包（字节流）。
    """
    icmp_type = 8  # ICMP Echo 请求
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 12345  # 标识符
    icmp_seq = 1  # 序列号

    # 构造 ICMP 头部
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    # 构造 ICMP 数据部分（可以包含时间戳）
    icmp_data = struct.pack("!d", time.time())

    # 计算校验和
    icmp_checksum = calculate_checksum(icmp_header + icmp_data)

    # 重新构造 ICMP 头部（包含正确的校验和）
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    # 返回完整的 ICMP 数据包
    return icmp_header + icmp_data

def calculate_checksum(data: bytes) -> int:
    """
    计算 ICMP 数据包的校验和。
    :param data: ICMP 数据包（字节流）。
    :return: 校验和（16 位整数）。
    """
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    return checksum

def get_os_from_ttl(ttl: int) -> str:
    """
    根据 TTL 值推断操作系统。
    :param ttl: ICMP 响应的 TTL 值。
    :return: 推断的操作系统类型。
    """
    if ttl <= 64:
        return "Linux"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Unknown"

def icmp_alive_with_os(host: str) -> tuple:
    """
    使用 ICMP 协议探测主机是否存活，并尝试识别操作系统。
    :param host: 目标主机的 IP 地址或域名。
    :return: (是否存活, 操作系统类型)
    """
    try:
        # 创建原始套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # 设置超时时间为 2 秒
        sock.settimeout(2)
        # 构造 ICMP 数据包
        packet = make_icmp_packet()
        # 发送 ICMP 请求
        sock.sendto(packet, (host, 0))
        # 接收响应
        receive, addr = sock.recvfrom(1024)
        # 提取 TTL 值（位于 IP 头部的第 9 字节）
        ttl = receive[8]
        # 解析 ICMP 响应
        icmp_header = receive[20:28]
        icmp_type, _, _, _, _ = struct.unpack("!BBHHH", icmp_header)
        # 如果收到 Echo 响应（类型为 0），表示主机存活
        if icmp_type == 0:
            os_type = get_os_from_ttl(ttl)
            return True, os_type
    except socket.timeout:
        return False, "Unknown"
    except Exception as e:
        print(f"Error while pinging {host}: {e}")
        return False, "Unknown"
    finally:
        # 关闭套接字
        sock.close()

# 示例使用
if __name__ == "__main__":
    target_host = "217.113.192.10"
    is_alive, os_type = icmp_alive_with_os(target_host)
    if is_alive:
        print(f"Host {target_host} is alive. OS: {os_type}")
    else:
        print(f"Host {target_host} is unreachable.")