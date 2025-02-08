from bs4 import BeautifulSoup
import requests
from app.config import Request
from app.utils.dnsUtil import get_full_domain


def get_page_title(response):
    try:
        response.encoding = response.apparent_encoding
        soup = BeautifulSoup(response.text, 'html.parser')

        title = soup.title.string if soup.title else ""

        return title.strip()

    except requests.RequestException as e:
        return f"get title err: {e}"

def check_url(url):
    try:

        res = requests.get(url,verify=False,timeout=8,allow_redirects=False)
        title = get_page_title(res)
        statuscode = res.status_code
        domain = get_full_domain(url)

        return {"url":url,"statuscode":statuscode,"title":title,"domain":domain}
    except Exception:
        return False


if __name__ == "__main__":
    # 使用示例
    url = "https://www.kuaishou.com"

    print(check_url(url))