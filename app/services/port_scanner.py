import nmap

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
    
    async def scan_ports(self, ip, ports="1-1000"):
        try:
            result = self.scanner.scan(ip, ports)
            scanned_ports = []
            
            if ip in result['scan']:
                for port in result['scan'][ip]['tcp']:
                    if result['scan'][ip]['tcp'][port]['state'] == 'open':
                        scanned_ports.append({
                            'port': port,
                            'service': result['scan'][ip]['tcp'][port]['name'],
                            'version': result['scan'][ip]['tcp'][port]['version']
                        })
            return scanned_ports
            
        except Exception as e:
            print(f"端口扫描错误: {str(e)}")
            return [] 