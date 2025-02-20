import socket
import struct
from loguru import logger

class PostgresqlScanner:
    DEFAULT_PORTS = {5432, 5433}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是PostgreSQL服务
        """
        return port in PostgresqlScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        # PostgreSQL StartupMessage 包
        
        # 构造StartupMessage
        version = 196608  # PostgreSQL 协议版本 3.0 (0x00030000)
        user = b"postgres"  # 默认用户名
        database = b"postgres"  # 默认数据库名
        
        # 构建消息体
        message = struct.pack("!I", version)  # 协议版本
        message += b"user\x00" + user + b"\x00"  # 用户参数
        message += b"database\x00" + database + b"\x00"  # 数据库参数
        message += b"\x00"  # 消息结束符
        
        # 添加消息长度（包括长度本身的4字节）
        length = len(message) + 4
        packet = struct.pack("!I", length) + message

        try:
            with socket.create_connection((target_ip, port), timeout=3) as sock:
                # 发送StartupMessage
                sock.send(packet)
                
                # 读取响应
                response = sock.recv(1024)
                
                if len(response) < 1:
                    return None

                # 检查PostgreSQL响应类型
                msg_type = response[0:1]
                
                # 常见的PostgreSQL响应类型：
                # E: ErrorResponse
                # R: AuthenticationRequest
                # N: NoticeResponse
                # S: ParameterStatus
                if msg_type in {b'E', b'R', b'N', b'S'}:
                    # 如果是错误响应，进一步验证错误消息格式
                    if msg_type == b'E':
                        # 检查错误响应的格式是否符合PostgreSQL协议
                        if len(response) > 5:
                            # 检查消息长度字段
                            try:
                                msg_len = struct.unpack("!I", response[1:5])[0]
                                if msg_len > 0 and len(response) >= 5:
                                    return "POSTGRESQL"
                            except struct.error:
                                pass
                    else:
                        # 其他响应类型直接认为是PostgreSQL
                        return "POSTGRESQL"

        except socket.error as e:
            error_msg = str(e).lower()
            # 某些情况下连接被重置也可能是PostgreSQL服务
            if "connection reset" in error_msg:
                return "POSTGRESQL"
            logger.debug(f"Error identifying PostgreSQL on {target_ip}:{port}: {e}")

        return None

if __name__ == "__main__":
    print(PostgresqlScanner.detect(5432, "216.225.155.73"))
