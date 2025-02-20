import socket
import struct
from loguru import logger

class RdpScanner:
    DEFAULT_PORTS = {3389, 3388}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是RDP服务
        """
        return port in RdpScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        # RDP 协议连接请求包
        tpkt_header = bytes([
            0x03,  # Version
            0x00,  # Reserved
            0x00, 0x13,  # Length (19 bytes)
        ])
        # X.224 Connection Request
        x224_crq = bytes([
            0x0e,  # Length
            0xe0,  # Connection Request
            0x00, 0x00,  # Destination reference
            0x00, 0x00,  # Source reference
            0x00,  # Class option
        ])

        # RDP Negotiation Request
        rdp_neg_req = bytes([
            0x01,  # Type: RDP Negotiation Request
            0x00,  # Flags
            0x08, 0x00,  # Length (8 bytes)
            0x03, 0x00, 0x00, 0x00,  # Protocols: SSL/TLS + Hybrid + RDP
        ])

        connection_request = tpkt_header + x224_crq + rdp_neg_req

        try:
            with socket.create_connection((target_ip, port), timeout=3) as sock:
                # 发送连接请求
                sock.send(connection_request)
                
                # 读取响应
                response = sock.recv(1024)
                
                if len(response) < 6:
                    return None

                # 检查TPKT头部
                if response[0] == 0x03:  # TPKT version 3
                    # 检查X.224响应类型
                    x224_type = response[5]
                    if x224_type in {0xd0, 0x0e, 0x02}:  # Connection Confirm or Data
                        return "RDP"
                    
                    # 如果上面的检查失败，尝试其他特征
                    if len(response) > 11:
                        # 检查是否包含RDP协议协商响应
                        if response[7] in {0x02, 0x03, 0x04}:  # Negotiation Response/Failure
                            return "RDP"
                        
                        # 检查SSL/TLS握手
                        if response[5] == 0x02 and response[2] == 0x01:
                            return "RDP"

        except socket.error as e:
            error_msg = str(e).lower()
            # 某些RDP服务器可能直接返回连接重置
            if "connection reset" in error_msg:
                return "RDP"
            logger.debug(f"Error identifying RDP on {target_ip}:{port}: {e}")

        return None

if __name__ == "__main__":
    print(RdpScanner.detect(3389, "139.224.222.19"))
