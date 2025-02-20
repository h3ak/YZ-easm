from celery import Celery
from app.config import settings

app = Celery('tasks',
             broker=settings.CELERY_BROKER_URL,
             backend=settings.CELERY_RESULT_BACKEND,
             include=['app.tasks.scan_tasks'])

# 配置
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Shanghai',
    enable_utc=True,
)

if __name__ == '__main__':
    app.start() 