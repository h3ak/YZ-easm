import socket
import re
from loguru import logger

class TelnetScanner:
    DEFAULT_PORTS = {23, 2323}

    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是Telnet服务
        """
        return port in TelnetScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                # Telnet IAC (Interpret As Command) 协商包
                # IAC DO ECHO (255 253 1)
                # IAC DO SUPPRESS-GO-AHEAD (255 253 3)
                # IAC WILL TERMINAL-TYPE (255 251 24)
                negotiate_payload = bytes([
                    255, 253, 1,    # IAC DO ECHO
                    255, 253, 3,    # IAC DO SUPPRESS-GO-AHEAD
                    255, 251, 24    # IAC WILL TERMINAL-TYPE
                ])

                # 先读取服务器的初始响应
                response = sock.recv(1024)

                # 发送协商包
                sock.send(negotiate_payload)

                # 读取协商响应
                response += sock.recv(1024)

                # Telnet协议特征：
                # 1. IAC字节 (255)
                # 2. 常见的Telnet命令 (DO/WILL/WONT/DONT - 251-254)
                # 3. 常见的Telnet选项 (ECHO/SGA/TTYPE - 1,3,24等)
                if b'\xff' in response and any(x in response for x in [b'\xfb', b'\xfc', b'\xfd', b'\xfe']):
                    return "TELNET"

                # 如果没有协商响应，检查是否有登录提示
                response_str = response.decode('ascii', errors='ignore').lower()
                if any(prompt in response_str for prompt in ['login:', 'username:', 'password:', 'user:']):
                    return "TELNET"

        except socket.error as e:
            logger.debug(f"Error identifying Telnet on {target_ip}:{port}: {e}")

        return None

if __name__ == "__main__":
    print(TelnetScanner.detect(23, "61.216.79.90"))
