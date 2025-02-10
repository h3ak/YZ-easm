import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from loguru import logger

class PortScanner:
    def __init__(self, target, ports=None, max_workers=50, timeout=2):
        """
        初始化端口扫描器
        :param target: 目标IP或域名
        :param ports: 端口列表，默认为常见端口
        :param max_workers: 最大线程数
        :param timeout: 超时时间
        """
        self.target = target
        self.ports = ports or range(1, 1025)  # 默认扫描1-1024端口
        self.max_workers = max_workers
        self.timeout = timeout
        
    def scan_port(self, port):
        """
        TCP端口扫描
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                return True
            return False
        except Exception as e:
            logger.debug(f"扫描端口 {port} 失败: {str(e)}")
            return False
        finally:
            sock.close()
            
    def identify_service(self, port):
        """
        服务识别
        """
        service_info = {
            'port': port,
            'service': None,
            'banner': None,
            'version': None
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # 常见服务的探测数据
            probes = {
                'http': f'GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n'.encode(),
                'ssh': b'SSH-2.0-OpenSSH_8.2p1\r\n',
                'ftp': b'USER anonymous\r\n',
                'smtp': b'EHLO test\r\n',
                'pop3': b'USER test\r\n',
                'mysql': struct.pack('<i', 1) + b'\x85\xae\x03\x00' + b'\x00' * 32,
                'redis': b'PING\r\n',
                'mongodb': b'\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00'
            }
            
            # 尝试不同的探测数据
            for service_name, probe in probes.items():
                print(probe)
                try:
                    sock.send(probe)
                    try:
                        data = sock.recv(1024)
                        if not data:  # 增加空数据检查
                            continue
                    except socket.timeout:
                        continue
                    service_info['banner'] = data[:100]  # 保存前100字节的banner信息
                    print(service_info['banner'])
                    # 基于响应内容识别服务
                    if b'HTTP' in data:
                        service_info['service'] = 'http'
                        if b'Server:' in data:
                            version = data.split(b'Server:')[1].split(b'\r\n')[0].strip()
                            service_info['version'] = version.decode(errors='ignore')
                    elif b'SSH' in data:
                        service_info['service'] = 'ssh'
                    elif b'FTP' in data:
                        service_info['service'] = 'ftp'
                    elif b'SMTP' in data:
                        service_info['service'] = 'smtp'
                    elif any(
                        keyword in data
                        for keyword in [
                            b'+PONG',
                            b'-NOAUTH Authentication required',
                            b'-DENIED Redis'
                        ]
                    ):
                        service_info['service'] = 'redis'
                    elif b'mysql' in data.lower():
                        service_info['service'] = 'mysql'
                    elif b'mongodb' in data.lower():
                        service_info['service'] = 'mongodb'
                        
                    if service_info['service']:
                        break
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"服务识别失败 {port}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.debug(f"服务识别失败 {port}: {str(e)}")
        finally:
            if service_info['service'] == None:
                service_info['service'] = "Unknown"
            sock.close()
            
        return service_info
        
    def scan(self):
        """
        执行端口扫描
        """
        results = []
        logger.info(f"开始扫描目标: {self.target}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 先扫描开放端口
            port_futures = {executor.submit(self.scan_port, port): port 
                          for port in self.ports}
            
            # 对开放端口进行服务识别
            for future in port_futures:
                port = port_futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        logger.info(f"发现开放端口: {port}")
                        service_info = self.identify_service(port)
                        if service_info['service']:
                            logger.info(f"端口 {port} 运行服务: {service_info['service']}")
                            results.append(service_info)
                except Exception as e:
                    logger.error(f"扫描出错: {str(e)}")
                    
        logger.success(f"扫描完成，发现 {len(results)} 个开放端口")
        return results

def scan_ports(target, ports=None, max_workers=50):
    """
    端口扫描入口函数
    """
    scanner = PortScanner(target, ports, max_workers)
    return scanner.scan()

if __name__ == "__main__":
    # 测试代码
    results = scan_ports("124.220.94.123", ports=range(6379, 6380))
    for result in results:
        print(f"Port: {result['port']}")
        print(f"Service: {result['service']}")
        print(f"Version: {result['version']}")
        print(f"Banner: {result['banner']}")
        print("---")