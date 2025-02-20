import socket
import re
from loguru import logger

class SshScanner:
    DEFAULT_PORTS = {22, 2222, 22222}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是SSH服务
        """
        return port in SshScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                # SSH服务器会主动发送版本信息
                response = sock.recv(1024).decode(errors='ignore')
                # SSH协议规定的版本字符串格式：SSH-2.0-ServerName 或 SSH-1.99-ServerName
                if re.match(r'^SSH-[12]\.\d{1,2}-', response.strip()):
                    return "SSH"
        except socket.error as e:
            logger.debug(f"Error identifying SSH: {e}")

        return None
if __name__ == "__main__":
    print(SshScanner.detect(22, "103.208.196.228"))


