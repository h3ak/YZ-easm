import dns.resolver
import concurrent.futures
from loguru import logger
from app.utils.dnsUtil import check_wildcard_dns, extract_baseDoamin
from itertools import cycle


def subdomain_bruteforce(domain, dict="../dict/top200.txt", max_workers=40):
    domain = extract_baseDoamin(domain)
    if check_wildcard_dns(domain):
        return {''}
    
    subdomains = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    # DNS服务器列表
    nameservers = [
        '223.5.5.5',       # 阿里 AliDNS
        '119.29.29.29',    # 腾讯 DNSPod
        '180.76.76.76',    # 百度 BaiduDNS
        '114.114.114.114', # 114DNS
        '1.2.4.8',         # CNNIC DNS
        '117.50.11.11',    # ONE DNS
        '101.226.4.6',     # DNS派
        '208.67.222.222',  # OpenDNS
        '1.1.1.1',         # Cloudflare
        '8.8.8.8'          # Google DNS
    ]
    dns_iterator = cycle(nameservers)
    
    with open(dict, "r") as f:
        wordlist = f.readlines()

    def check_subdomain(subdomain):
        try:
            # 每次解析使用下一个DNS服务器
            resolver.nameservers = [next(dns_iterator)]
            answers = resolver.resolve(f"{subdomain}.{domain}")
            if answers:
                subdomains.add(f"{subdomain}.{domain}")
                logger.info(f"Found subdomain: {subdomain}.{domain}")
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_subdomain, word.strip()) for word in wordlist]
        concurrent.futures.wait(futures)

    return subdomains


if __name__ == "__main__":
    print(len(subdomain_bruteforce("www.hnust.edu.cn")))
