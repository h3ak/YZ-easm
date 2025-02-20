from app.tasks.celery import app
from app.models import ScanResult
from app.scanners.port_scanner import PortScanner

@app.task(bind=True, name='full_scan')
def full_scan(self, target):
    """全量扫描任务"""
    try:
        self.update_state(state='PROGRESS', meta={'status': '扫描端口'})
        port_scanner = PortScanner(target)
        open_ports = port_scanner.scan()
        
        self.update_state(state='PROGRESS', meta={'status': '识别服务'})
        service_results = ServiceScanner(target).scan(open_ports)
        
        # 保存结果
        result = ScanResult(
            task_id=self.request.id,
            target=target,
            results=service_results
        ).save()
        
        return {'status': '完成', 'result_id': str(result.id)}
    except Exception as e:
        self.retry(exc=e, countdown=60, max_retries=3)