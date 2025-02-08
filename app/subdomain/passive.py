import requests
import json
from bs4 import BeautifulSoup


def otx_data(domain):
    subdomains = set()
    has_next = True
    page = 1
    while has_next:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}"
        data = requests.get(otx_url).text
        json_data = json.loads(data)
        url_list = json_data['url_list']
        for list in url_list:
            domain = list['hostname']
            subdomains.add(domain)
        #判断是否结束
        if json_data['has_next']:
            page += 1
        else:
            has_next = False

    return subdomains

def rapiddns_data(domain):
    subdomains = set()
    page = 1
    while 1:
        rapiddns_url = f"https://rapiddns.io/subdomain/{domain}?page={page}"
        res = requests.get(rapiddns_url)
        soup = BeautifulSoup(res.text, 'html.parser')
        table = soup.find('table', id='table')
        tbody = table.find('tbody')

        if tbody.find_all('tr'):
            page += 1
            for row in tbody.find_all('tr'):
                td = row.find('td')
                subdomains.add(td.text.strip())
        else:
            break
    return subdomains

def crt_data(domain):
    subdomains = set()
    ctr_url = f"https://crt.sh/?q={domain}&output=json"
    data = requests.get(ctr_url).text
    json_data = json.loads(data)
    for item in json_data:
        if item['name_value'].startswith('*'):
            continue
        if '\n' in item['name_value']:
            for subdomain in item['name_value'].split('\n'):
                subdomains.add(subdomain)
        else:
            subdomains.add(item['name_value'])
    return subdomains



def all_passive(domain):
    """
    整合所有被动收集的子域名数据
    :param domain: 目标域名
    :return: 去重后的子域名集合
    """
    all_subdomains = set()
    
    # 收集 rapiddns 数据
    rapiddns_results = rapiddns_data(domain)
    all_subdomains.update(rapiddns_results)
    
    # 收集 crt.sh 数据
    crt_results = crt_data(domain)
    all_subdomains.update(crt_results)
    
    # 收集 otx 数据
    otx_results = otx_data(domain)
    all_subdomains.update(otx_results)
    
    return all_subdomains

if __name__ == "__main__":
    print(len(all_passive("hnust.edu.cn")))