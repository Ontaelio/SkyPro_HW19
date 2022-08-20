import base64
import hashlib
import datetime
import calendar
import hmac

import jwt

from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS, JWT_SECRET, JWT_ALGORITHM, PASS_ALGO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def create_tokens(self, username, password):
        user = self.dao.get_by_name(username)

        if user is None:
            return None

        if self.check_password(user.password, password, PWD_HASH_SALT, PASS_ALGO):
            return self.generate_jwt(user)

        return 11

    def refresh_tokens(self, refresh_token):

        try:
            data = jwt.decode(jwt=refresh_token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM, ])
        except Exception as e:
            return None

        username = data.get('username')

        user = self.dao.get_by_name(username)

        return self.generate_jwt(user)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_d):
        user_d['password'] = self.make_password_hash(user_d.get('password'))
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, rid):
        self.dao.delete(rid)

    def make_password_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            PASS_ALGO,
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def get_hash(self, password):
        return hashlib.pbkdf2_hmac(
            PASS_ALGO,
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ).decode("utf-8", "ignore")

    def generate_jwt(self, user_obj):
        data = {
            'username': user_obj.username,
            'role': user_obj.role,
        }
        mins30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(mins30.timetuple())
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return {'access_token': access_token, 'refresh_token': refresh_token}

    def check_password(self, password_hash, incoming_password, salt, algo):
        return hmac.compare_digest(
            base64.b64decode(password_hash),
            hashlib.pbkdf2_hmac(algo, incoming_password.encode('utf-8'), salt, PWD_HASH_ITERATIONS)
        )

