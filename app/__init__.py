from flask import Flask
from celery import Celery
from pymongo import MongoClient

# app = Flask(__name__)
# app.config.from_object('app.config')

# # MongoDB配置
# client = MongoClient('mongodb://localhost:27017/')
# db = client['your_database_name']
#
# # Celery配置
# celery = Celery(
#     'tasks',
#     broker=app.config['CELERY_BROKER_URL'],
#     backend=app.config['CELERY_RESULT_BACKEND']
# )
