from flask import request, abort
from flask_restx import Resource, Namespace

from dao.model.user import UserSchema
from implemented import user_service
from views.decorators import admin_required

auth_ns = Namespace('auth')
users_ns = Namespace('users')


@auth_ns.route('/')
class AuthView(Resource):

    def post(self):
        req_json = request.json
        username = req_json.get('username', None)
        password = req_json.get('password', None)

        if None in [username, password]:
            abort(400)

        if result := user_service.create_tokens(username, password):
            return result

        return {"error": f"Неверные учётные данные. User: {username}, pass: {password}"}, 401

    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token', None)
        if refresh_token is None:
            abort(400)

        if result := user_service.refresh_tokens(refresh_token):
            return result

        abort(400)


@users_ns.route('/')
class UsersView(Resource):
    def get(self):
        rs = user_service.get_all()
        res = UserSchema(many=True).dump(rs)
        return res, 200


@users_ns.route('/<int:uid>')
class UserView(Resource):
    @admin_required
    def delete(self, uid):
        user_service.delete(uid)
        return "", 204

