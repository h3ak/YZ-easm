from flask_restful import Resource, reqparse
from flask import jsonify
from app.tasks.scan_tasks import full_scan
from app.models.scan_result import ScanResult

class ScanResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('target', type=str, required=True)
        args = parser.parse_args()
        
        task = full_scan.delay(args['target'])
        return {'task_id': task.id}, 202

class ResultResource(Resource):
    def get(self, task_id):
        result = ScanResult.objects(task_id=task_id).first()
        if not result:
            return {'error': '结果不存在'}, 404
        return jsonify(result.to_json())

class ResultListResource(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('page', type=int, default=1)
        args = parser.parse_args()
        
        results = ScanResult.objects.paginate(
            page=args['page'], 
            per_page=20
        )
        return jsonify([r.to_json() for r in results.items]) 