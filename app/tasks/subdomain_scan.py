from celery import shared_task
import subprocess

@shared_task
def scan_subdomains(domain):
    try:
        # 使用subfinder进行子域名扫描
        cmd = f"subfinder -d {domain} -silent"
        process = subprocess.Popen(
            cmd.split(), 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        output, error = process.communicate()
        
        if error:
            raise Exception(f"子域名扫描错误: {error}")
            
        subdomains = output.decode().split('\n')
        return [s for s in subdomains if s]
        
    except Exception as e:
        print(f"扫描出错: {str(e)}")
        return [] 