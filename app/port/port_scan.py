import socket
import concurrent.futures
from loguru import logger
from app.services.protocol_scanner import recognize_protocol
from app.port.services.http import HttpScanner
# ... 导入其他服务扫描器 ...

class PortScanner:
    def __init__(self, target, ports, max_workers=50):
        self.target = target
        self.ports = ports
        self.max_workers = max_workers
        self.open_ports = []
        # 注册服务扫描器
        self.service_scanners = [
            HttpScanner,
            # ... 其他服务扫描器 ...
        ]

    def is_port_open(self, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    logger.info(f"端口 {port} 开放")
                    return True
        except Exception as e:
            logger.error(f"端口 {port} 扫描出错: {e}")
        return False

    def scan_ports(self):
        # 根据注册的服务扫描器构建优先端口列表
        priority_ports = set()
        for scanner in self.service_scanners:
            priority_ports.update(scanner.DEFAULT_PORTS)
        
        # 优先扫描可能的服务端口
        sorted_ports = sorted(self.ports, key=lambda p: (0 if p in priority_ports else 1, p))
        
        logger.info("开始多线程端口扫描...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.is_port_open, port): port for port in sorted_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        self.open_ports.append(port)
                except Exception as e:
                    logger.error(f"处理端口 {port} 时出错: {e}")
        return self.open_ports

    def recognize_protocols(self):
        results = {}
        for port in self.open_ports:
            # 查找匹配的服务扫描器
            for scanner in self.service_scanners:
                if scanner.is_match(port):
                    results[port] = scanner.scan(self.target, port)
                    break
            else:
                # 如果没有匹配的扫描器，使用通用协议识别
                results[port] = recognize_protocol(self.target, port)
        return results


def main():
    target = "127.0.0.1"
    ports = list(range(20, 1025))
    scanner = PortScanner(target, ports)
    open_ports = scanner.scan_ports()
    logger.info(f"开放端口: {open_ports}")
    protocols = scanner.recognize_protocols()
    logger.info("协议识别结果:")
    for port, proto in protocols.items():
        logger.info(f"端口 {port}: {proto}")
        
if __name__ == "__main__":
    main()
