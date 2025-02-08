from loguru import logger
from app.subdomain.brute import subdomain_bruteforce
from app.subdomain.passive import all_passive
from app.utils.dnsUtil import extract_baseDoamin

def get_all_subdomains(domain):
    domain = extract_baseDoamin(domain)
    all_subdomains = set()
    
    # 收集被动子域名
    try:
        passive_results = all_passive(domain)
        all_subdomains.update(passive_results)
        logger.info(f"被动收集到 {len(passive_results)} 个子域名")
    except Exception as e:
        logger.error(f"被动收集出错: {str(e)}")
    
    # 收集主动爆破子域名
    try:
        brute_results = subdomain_bruteforce(domain)
        all_subdomains.update(brute_results)
        logger.info(f"主动爆破收集到 {len(brute_results)} 个子域名")
    except Exception as e:
        logger.error(f"主动爆破出错: {str(e)}")
    
    logger.success(f"总共收集到 {len(all_subdomains)} 个不重复子域名")
    return list(all_subdomains)

if __name__ == "__main__":
    print(len(get_all_subdomains("hnust.edu.cn")))
