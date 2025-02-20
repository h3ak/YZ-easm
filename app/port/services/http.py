from typing import Dict
import socket
import ssl
import re
from loguru import logger

class HttpScanner:
    # 定义该插件支持的默认端口
    DEFAULT_PORTS = {80, 443, 3000, 4567, 7001, 8001, 8080, 8443, 8000, 8080, 8081, 8888, 9001, 9080, 9090, 9100, 443, 8443, 9443}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是HTTP服务
        """
        return port in HttpScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        # 先尝试HTTP
        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                sock.sendall(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode())
                response = sock.recv(1024).decode(errors='ignore')
                if re.match(r'^HTTP/\d\.\d \d{3}', response.strip()):
                    return "HTTP"
        except socket.error:
            pass

        # 如果HTTP失败，尝试HTTPS
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    ssock.sendall(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode())
                    response = ssock.recv(1024).decode(errors='ignore')
                    if re.match(r'^HTTP/\d\.\d \d{3}', response.strip()):
                        return "HTTPS"
        except (ssl.SSLError, socket.error) as e:
            logger.debug(f"Error identifying HTTPS: {e}")

        return None
if __name__ == "__main__":
    print(HttpScanner.detect(80, "100al.com"))
