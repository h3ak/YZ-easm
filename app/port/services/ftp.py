# -*- coding:utf-8 -*-
"""
@Created on : 2025/2/14 16:12
@Auther: c
@Des: 
"""

import socket
import re
from loguru import logger

class FtpScanner:
    DEFAULT_PORTS = {21, 2121}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是FTP服务
        """
        return port in FtpScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        # 先尝试普通FTP
        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                # FTP服务器会主动发送欢迎信息
                response = sock.recv(1024).decode(errors='ignore')
                # FTP响应通常以220开头
                if re.match(r'^220[- ]', response.strip()):
                    return "FTP"
        except socket.error:
            pass

        # 如果普通FTP失败，尝试FTPS（FTP over SSL/TLS）
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    response = ssock.recv(1024).decode(errors='ignore')
                    if re.match(r'^220', response.strip()):
                        return "FTPS"
        except (ssl.SSLError, socket.error) as e:
            logger.debug(f"Error identifying FTPS: {e}")

        return None
if __name__ == "__main__":
    print(FtpScanner.detect(22, "211.75.137.8"))

