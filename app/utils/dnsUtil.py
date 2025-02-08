import dns.resolver
import random
import string
import tldextract
import socket
from app.utils.cdn import cdn_check



def easy_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return False
    return ip

def get_full_domain(url):
    # 移除协议部分
    domain = url.split('://')[1] if '://' in url else url
    fulldomain = domain.split('/')[0]

    return fulldomain

def extract_baseDoamin(domain):

    try:
        ext = tldextract.extract(domain)
        base_domain = f"{ext.domain}.{ext.suffix}"
        return base_domain
    except Exception as e:
        return [f"Resolve domain error:{e}"]


def dns_resolve(domain, record_type='A'):

    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return False


def check_wildcard_dns(domain, num_checks=4):

    base_domain = extract_baseDoamin(domain)

    successful_resolutions = 0

    for _ in range(num_checks):
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=10))
        random_domain = f"{random_subdomain}.{base_domain}"

        try:
            ip = easy_dns(random_domain)
            if ip :
                successful_resolutions += 1
        except Exception:
            pass

    return successful_resolutions == num_checks

def domain_resolve(domain):

    ips = dns_resolve(domain)
    if not ips:
        return False
    flag = True
    if len(ips) == 1:
        cnames = dns_resolve(domain, "CNAME")
        if cnames:
            for item in cnames:
                if cdn_check(item):
                    flag = False
    else:
        flag = False
    return {"domain":domain,"ip":ips[0],"port_scan":flag}



# 使用示例
if __name__ == "__main__":
    print(extract_baseDoamin("hnust.edu.cn"))

