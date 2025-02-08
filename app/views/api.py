from flask import Blueprint, request, jsonify
from app.tasks.subdomain_scan import scan_subdomains
from app.models.asset import Asset

api = Blueprint('api', __name__)

@api.route('/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': '域名不能为空'}), 400
            
        # 创建资产记录
        asset = Asset().create_asset(domain, 'domain')
        
        # 启动子域名扫描任务
        scan_task = scan_subdomains.delay(domain)
        
        return jsonify({
            'message': '扫描任务已启动',
            'task_id': scan_task.id,
            'asset_id': str(asset.inserted_id)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500 