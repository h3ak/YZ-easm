from mongoengine import Document, StringField, DictField, DateTimeField
from datetime import datetime

class ScanResult(Document):
    meta = {
        'collection': 'scan_results',
        'indexes': [
            'task_id',
            'target',
            {'fields': ['-timestamp'], 'sparse': True}
        ]
    }
    
    task_id = StringField(required=True)
    target = StringField(required=True)
    results = DictField()
    timestamp = DateTimeField(default=datetime.utcnow)
    
    def to_json(self):
        return {
            "task_id": self.task_id,
            "target": self.target,
            "results": self.results,
            "timestamp": self.timestamp.isoformat()
        } 