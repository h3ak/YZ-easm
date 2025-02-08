from datetime import datetime, timezone
from app import db  # 确保db已正确初始化

class Domain:
    def __init__(self):
        self.collection = db.domains  # 假设集合名为'domains'
    
    def create_domain(self, domain, ip, port_scan):
        domain_data = {
            "domain": domain,
            "ip": ip,
            "port_scan": port_scan,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        return self.collection.insert_one(domain_data)
    
