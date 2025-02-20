import os

class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = os.getenv('MONGO_DB', 'attack_surface')
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_BACKEND', 'redis://localhost:6379/1')
    API_SECRET_KEY = os.getenv('API_SECRET', 'your-secret-key') 