from mongoengine import connect
from app.config import settings

connect(
    db=settings.MONGO_DB,
    host=settings.MONGO_URI,
    alias='default'
) 