from flask import Flask
from flask_restful import Api
from app.api.resources import ScanResource, ResultResource

app = Flask(__name__)
api = Api(app)

api.add_resource(ScanResource, '/api/scan')
api.add_resource(ResultResource, '/api/result/<string:task_id>') 