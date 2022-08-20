from flask import request
from flask_restx import Resource, Namespace

from dao.model.genre import GenreSchema
from implemented import genre_service
from views.decorators import auth_required, admin_required

genre_ns = Namespace('genres')


@genre_ns.route('/')
class GenresView(Resource):

    @auth_required
    def get(self):
        rs = genre_service.get_all()
        res = GenreSchema(many=True).dump(rs)
        return res, 200
    
    @admin_required
    def post(self):
        dir_json = request.json
        genre_service.add_one(dir_json)
        return "", 201


@genre_ns.route('/<int:rid>')
class GenreView(Resource):

    @auth_required
    def get(self, rid):
        r = genre_service.get_one(rid)
        sm_d = GenreSchema().dump(r)
        return sm_d, 200
    
    @admin_required
    def put(self, uid):
        data = request.json
        genre_service.update(uid, data)
        return "", 204

    @admin_required
    def delete(self, uid):
        genre_service.delete(uid)
        return "", 204
