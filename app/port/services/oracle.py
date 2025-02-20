import socket
from loguru import logger

class OracleScanner:
    DEFAULT_PORTS = {1521, 1522, 1526}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是Oracle服务
        """
        return port in OracleScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        # 最小化的TNS探测包
        tns_packet = (
            b"\x00\x5a"  # 包长度
            b"\x00\x00\x01\x00\x00\x00\x01\x36"
            b"\x01\x2c\x00\x00\x08\x00\x7f\xff"
            b"\x7f\x08\x00\x00\x00\x01\x00\x20"
            b"\x00\x3a\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x34\xe6\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x28\x43\x4f\x4e\x4e\x45\x43\x54"
            b"\x5f\x44\x41\x54\x41\x3d\x28\x43"
            b"\x4f\x4d\x4d\x41\x4e\x44\x3d\x76"
            b"\x65\x72\x73\x69\x6f\x6e\x29\x29"
        )

        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                sock.send(tns_packet)
                response = sock.recv(1024)
                
                # 转换响应为字符串，忽略解码错误
                resp_str = response.decode('ascii', errors='ignore').upper()
                
                # 检查关键字
                if any(keyword in resp_str for keyword in ['VERSION', 'TNSLSNR', 'ORACLE']):
                    return "ORACLE"
                    
                # 检查特定的响应字节模式
                if len(response) > 4 and response[4] in [2, 4, 5, 9]:
                    return "ORACLE"

        except socket.error as e:
            logger.debug(f"Error identifying Oracle on {target_ip}:{port}: {e}")
            return None

        return None

if __name__ == "__main__":
    print(OracleScanner.detect(1521, "47.111.106.184"))
