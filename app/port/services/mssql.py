import pymssql
from loguru import logger

class MssqlScanner:
    DEFAULT_PORTS = {1433, 1434}
    
    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是MSSQL服务
        """
        return port in MssqlScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            # 尝试建立连接，使用较短的超时时间
            conn = pymssql.connect(
                server=target_ip,
                port=port,
                user='',  # 空用户名
                password='',  # 空密码
                login_timeout=2,  # 连接超时2秒
                timeout=2  # 查询超时2秒
            )
            conn.close()
            return "MSSQL"
        except pymssql.OperationalError as e:
            error_msg = str(e)
            # 扩展错误匹配条件
            if any(msg in error_msg.lower() for msg in [
                "login failed",  # 英文
                "inicio de sesión",  # 西班牙语
                "error de inicio",  # 西班牙语
                "connection failed",  # 连接失败但服务存在
                "adaptive server",  # Sybase/MSSQL服务标识
                "sql server error",  # SQL Server错误
                "database does not exist",  # 数据库不存在但服务存在
            ]):
                return "MSSQL"
            logger.debug(f"Error identifying MSSQL on {target_ip}:{port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Error identifying MSSQL on {target_ip}:{port}: {e}")
            return None

if __name__ == "__main__":
    print(MssqlScanner.detect(1433, "2.50.11.60"))
