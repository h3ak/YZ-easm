import socket
import re
from loguru import logger

class RedisScanner:
    DEFAULT_PORTS = {6379, 16379, 26379}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是Redis服务
        """
        return port in RedisScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                # 发送PING命令
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                response = sock.recv(1024).decode(errors='ignore')
                
                # Redis的PING命令会返回 +PONG 或 -NOAUTH
                if re.match(r'^[+]PONG|^[-]NOAUTH', response.strip()):
                    return "REDIS"
                
                # 如果上面失败，尝试发送INFO命令
                sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
                response = sock.recv(1024).decode(errors='ignore')
                
                # Redis INFO命令的响应格式为 $<length>\r\n 或 -NOAUTH
                if re.match(r'^[$]\d+|^[-]NOAUTH', response.strip()):
                    return "REDIS"
                
        except socket.error as e:
            logger.debug(f"Error identifying Redis: {e}")

        return None
if __name__ == "__main__":
    print(RedisScanner.detect(6379, "114.34.92.188"))


