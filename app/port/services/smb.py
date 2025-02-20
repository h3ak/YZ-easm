from impacket.smbconnection import SMBConnection, SessionError
from loguru import logger

class SmbScanner:
    DEFAULT_PORTS = {445}

    @staticmethod
    def is_match(port: int) -> bool:
        """
        检查端口是否可能是SMB服务
        """
        return port in SmbScanner.DEFAULT_PORTS

    @staticmethod
    def detect(port, target_ip):
        try:
            # 创建SMB连接对象
            smb = SMBConnection(target_ip, target_ip, timeout=2)
            # 尝试连接，不使用任何凭据
            smb.login('', '')
            smb.close()
            return "SMB"

        except SessionError as e:
            # 会话错误通常意味着服务存在但认证失败
            return "SMB"

        except Exception as e:
            error_msg = str(e).lower()
            # 某些错误也表明服务存在
            if any(msg in error_msg for msg in [
                "authentication failed",
                "access denied",
                "logon failure",
                "bad password",
                "unknown username",
                "session setup failed",
                "status_logon_failure",
                "status_access_denied"
            ]):
                return "SMB"

            logger.debug(f"Error identifying SMB on {target_ip}:{port}: {e}")
            return None

if __name__ == "__main__":
    print(SmbScanner.detect(445, "192.168.0.117"))


