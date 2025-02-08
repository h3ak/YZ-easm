import socket
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
import nmap

def is_smb_port_open(host: str) -> bool:
    """
    扫描目标主机的 445 端口是否开放。
    :param host: 目标主机的 IP 地址或域名。
    :return: True 如果 445 端口开放，否则 False。
    """
    try:
        nm = nmap.PortScanner()
        result = nm.scan(host, arguments="-p 445 --open")
        return host in result["scan"] and 445 in result["scan"][host]["tcp"]
    except Exception as e:
        print(f"Error while scanning SMB port on {host}: {e}")
        return False

def get_smb_info(host: str) -> dict:
    """
    获取目标主机的 SMB 信息。
    :param host: 目标主机的 IP 地址或域名。
    :return: 包含 SMB 信息的字典。
    """
    smb_info = {}
    try:
        # 创建 SMB 连接
        smb = SMBConnection(host, host, timeout=5)
        smb.login("", "")  # 匿名登录

        # 获取 SMB 服务器信息
        smb_info["domain"] = smb.getServerDomain()
        smb_info["hostname"] = smb.getServerName()
        smb_info["os_version"] = smb.getServerOSVersion()
        smb_info["dialect"] = smb.getDialect()

        # 获取共享文件夹列表
        shares = smb.listShares()
        smb_info["shares"] = [share["shi1_netname"] for share in shares]

        # 获取用户列表（如果支持匿名登录）
        try:
            users = smb.listUsers()
            smb_info["users"] = users
        except Exception as e:
            print(f"Error while getting users from {host}: {e}")
            smb_info["users"] = []

        return smb_info
    except Exception as e:
        print(f"Error while getting SMB info from {host}: {e}")
        return {}

def probe_smb_and_get_info(host: str) -> dict:
    """
    探测 445 端口是否为 SMB 协议，并获取 SMB 信息。
    :param host: 目标主机的 IP 地址或域名。
    :return: 包含 SMB 信息的字典。
    """
    smb_info = {}
    if is_smb_port_open(host):
        print(f"Port 445 is open on {host}. Probing for SMB protocol...")
        smb_info = get_smb_info(host)
        if smb_info:
            print(f"SMB protocol detected on {host}.")
        else:
            print(f"Port 445 is open, but SMB protocol is not detected on {host}.")
    else:
        print(f"Port 445 is closed on {host}.")
    return smb_info

# 示例使用
if __name__ == "__main__":
    target_host = "192.168.174.1"
    smb_info = probe_smb_and_get_info(target_host)
    if smb_info:
        print("SMB Information:")
        for key, value in smb_info.items():
            print(f"{key}: {value}")