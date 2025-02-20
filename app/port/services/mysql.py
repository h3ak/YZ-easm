import socket
import re
from loguru import logger

class MysqlScanner:
    DEFAULT_PORTS = {3306, 3307, 3308, 3316}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是MySQL服务
        """
        return port in MysqlScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            with socket.create_connection((target_ip, port), timeout=3) as sock:
                # MySQL服务器会主动发送握手包
                initial_packet = sock.recv(1024)
                
                if len(initial_packet) < 5:
                    return None
                
                # 检查包长度（前3字节）和包序号（第4字节）
                packet_length = int.from_bytes(initial_packet[0:3], byteorder='little')
                packet_number = initial_packet[3]
                
                if packet_length < 1 or packet_number != 0:
                    return None
                
                # 检查协议版本（第5字节）
                protocol_version = initial_packet[4]
                if protocol_version != 10:  # MySQL protocol version 10
                    return None
                
                # 尝试提取版本信息字符串
                try:
                    server_version = initial_packet[5:].split(b'\x00')[0].decode('ascii')
                    # MySQL版本字符串格式通常为: 5.7.xx 或 8.0.xx
                    if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+', server_version):
                        return "MYSQL"
                except (UnicodeDecodeError, IndexError):
                    # 如果无法解析版本号但前面的检查都通过了，仍然认为是MySQL
                    if len(initial_packet) > 5:
                        return "MYSQL"
                
        except socket.error as e:
            logger.debug(f"Error identifying MySQL on {target_ip}:{port}: {e}")
        
        return None

if __name__ == "__main__":
    print(MysqlScanner.detect(3306, "60.251.44.199"))


