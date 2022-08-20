from flask import request
from flask_restx import Resource, Namespace

from dao.model.director import DirectorSchema
from implemented import director_service
from views.decorators import auth_required, admin_required

director_ns = Namespace('directors')
director_schema = DirectorSchema()
directors_schema = DirectorSchema(many=True)


@director_ns.route('/')
class DirectorsView(Resource):

    @auth_required
    def get(self):
        rs = director_service.get_all()
        res = DirectorSchema(many=True).dump(rs)
        return res, 200

    @admin_required
    def post(self):
        dir_json = request.json
        director_service.add_one(dir_json)
        return "", 201


@director_ns.route('/<int:rid>')
class DirectorView(Resource):

    @auth_required
    def get(self, rid):
        r = director_service.get_one(rid)
        sm_d = DirectorSchema().dump(r)
        return sm_d, 200

    @admin_required
    def put(self, uid):
        data = request.json
        director_service.update(uid, data)
        return "", 204

    @admin_required
    def delete(self, uid):
        director_service.delete(uid)
        return "", 204
