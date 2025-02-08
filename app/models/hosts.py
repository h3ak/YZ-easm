from datetime import datetime, timezone
from app import db  # 确保db已正确初始化

class Hosts:
    def __init__(self):
        self.collection = db.hosts  # 假设集合名为'hosts'
    
    def create_host(self, ip, alive, os, win_name, open_port, service):
        host_data = {
            "ip": ip,
            "alive": alive,
            "os": os,
            "win_name": win_name,
            "open_port": [],
            "service": service,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        return self.collection.insert_one(host_data)
    
