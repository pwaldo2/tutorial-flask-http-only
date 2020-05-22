from datetime import datetime
from functools import wraps

from flask import abort
from flask import request
from flask import jsonify
from flask.views import MethodView
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    decode_token,
    fresh_jwt_required,
    jwt_refresh_token_required,
    get_jwt_claims,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt,
)
from api.auth.models import UserModel
from api.auth.models import RoleModel
from api.auth.models import CompanyModel
from api.auth.models import TokenModel
from api.resources import OBJECT_DELETED, OBJECT_NOT_FOUND
from api.auth.schemas import RoleSchema
from api.auth.schemas import UserSchema
from api.auth.schemas import UserPostSchema
from api.auth.schemas import CompanySchema
from api.auth.schemas import TokenSchema
from api.auth.schemas import NewPasswordSchema

USER_ALREADY_EXISTS = "A user with that username already exists."
EMAIL_ALREADY_EXISTS = "A user with that email already exists."
CREATED_SUCCESSFULLY = "User created successfully."
USER_NOT_FOUND = "User not found."
USER_DELETED = "User deleted."
INVALID_CREDENTIALS = "Invalid credentials!"
USER_LOGGED_OUT = "User <id={user_id}> successfully logged out."

user_schema = UserSchema()
user_list_schema = UserSchema(many=True)
user_post_schema = UserPostSchema()
role_schema = RoleSchema()
role_list_schema = RoleSchema(many=True)
company_schema = CompanySchema()
company_list_schema = CompanySchema(many=True)
token_schema = TokenSchema()
new_password_schema = NewPasswordSchema()

def site_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        claims = get_jwt_claims()
        if 'SITE_ADMIN' not in claims["roles"] or 'ADMIN' not in claims["roles"]:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        claims = get_jwt_claims()
        if 'ADMIN' not in claims["roles"]:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def check_obj_permissions(company_id):
    claims = get_jwt_claims()
    return claims["company_id"] == company_id

def get_company_from_request():
    jti = get_raw_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT.
    user_id = get_jwt_identity()
    return UserModel.find_by_id(_id=user_id).company_id


def get_current_user():
    jti = get_raw_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT.
    return get_jwt_identity()


class CompanyView(MethodView):

    decorators = [jwt_required, ]

    def __init__(self):
        pass

    @classmethod
    def get(cls, _id):
        data = CompanyModel.find_by_id(_id)
        if data:
            return jsonify({"data": company_schema.dump(data), "errors": {}, "status": 200})

        return {"message": OBJECT_NOT_FOUND.format('Company', _id)}, 404

    @classmethod
    def put(cls, _id):
        pass

    @classmethod
    def delete(cls, _id):
        data = CompanyModel.find_by_id(_id)
        if data:
            data.delete_from_db()
            return {"message": OBJECT_DELETED.format('Company', _id)}

        return {"message": OBJECT_NOT_FOUND.format('Company', _id)}, 404


class CompanyListView(MethodView):

    decorators = [jwt_required, ]

    def __init__(self):
        pass

    @classmethod
    def get(cls):
        data = CompanyModel.find_all()
        return jsonify({"data": company_list_schema.dump(data),
                        "errors": [],
                        "count": len(data),
                        "status": 200,
                        }
                       )
    @classmethod
    def post(cls):
        req_json = request.get_json()
        errors = company_schema.validate(req_json)
        if errors:
            response = jsonify({"errors": errors, "status": 400})
            response.status_code = 400
            return response

        data = company_schema.load(req_json)
        data.save_to_db()

        response = jsonify({"data": company_schema.dump(data), "errors": {}, "status": 201})
        response.status_code = 201
        return response


class RoleListView(MethodView):

    @classmethod
    def get(cls):
        data = RoleModel.find_all()
        return jsonify({"data": role_list_schema.dump(data),
                        "errors": [],
                        "count": len(data),
                        "status": 200,
                        }
                       )


class RoleDetailView(MethodView):

    @classmethod
    def get(cls, role_id):
        data = RoleModel.find_by_id(role_id)
        if not data:
            return {"message": OBJECT_NOT_FOUND.format("Role", role_id)}, 404

        return role_schema.dump(data), 200


class UserRegisterView(MethodView):

    @classmethod
    def post(cls):
        req_json = request.get_json()

        errors = user_post_schema.validate(req_json)

        if errors:
            response = jsonify({'errors': errors, "status": 400})
            response.status_code = 400
            return response

        if UserModel.find_by_username(req_json['username']):
            return {"message": USER_ALREADY_EXISTS}, 400

        if UserModel.query.filter_by(email=req_json['email']).first():
            return {"message": EMAIL_ALREADY_EXISTS}, 400

        data = user_post_schema.load(req_json)
        data.set_password(req_json['password'])
        data.save_to_db()

        return {"message": CREATED_SUCCESSFULLY}, 201


class ChangePasswordView(MethodView):

    @classmethod
    @fresh_jwt_required # Ask the user to login again
    def post(cls):
        req_json = request.get_json()
        user_id = get_jwt_identity()
        user = UserModel.find_by_id(user_id)
        errors = new_password_schema.validate(req_json)

        if errors:
            response = jsonify({'errors': errors, "status": 400})
            response.status_code = 400
            return response

        if user and user.check_password(req_json['password']):
            user.set_password(req_json['new_password'])
            user.save_to_db()
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            access_decoded_token = decode_token(access_token)

            entry = {
                "jti": access_decoded_token["jti"],
                "token_type": 'access',
                "fresh": True,
                "blacklisted": False,
                "never_expire": False,
            }
            data = token_schema.load(entry)
            data.user_id = user.id
            data.expiration_date = datetime.fromtimestamp(access_decoded_token['exp'])
            data.save_to_db()

            resp = jsonify({"message":"Successfully set a new password", "login": True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200

        return {"message": INVALID_CREDENTIALS, 'login': False}, 401


class UserView(MethodView):

    decorators = [jwt_required, ]

    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": USER_NOT_FOUND}, 404

        return user_schema.dump(user), 200

    @classmethod
    def delete(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": USER_NOT_FOUND}, 404

        user.delete_from_db()
        return {"message": USER_DELETED}, 200


class UserLoginView(MethodView):

    @classmethod
    def post(cls):
        user_json = request.get_json()
        user_data = user_schema.load(user_json)
        user = UserModel.find_by_username(user_json['username'])

        if user and user.check_password(user_json['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            access_decoded_token = decode_token(access_token)

            entry = {
                "jti": access_decoded_token["jti"],
                "token_type": 'access',
                "fresh": True,
                "blacklisted": False,
                "never_expire": False,
            }
            data = token_schema.load(entry)
            data.user_id = user.id
            data.expiration_date = datetime.fromtimestamp(access_decoded_token['exp'])
            data.save_to_db()

            resp = jsonify({"message":"Successfully logged in!", "login": True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200


        return {"message": INVALID_CREDENTIALS, 'login': False}, 401


class UserLogoutView(MethodView):

    decorators = [jwt_required, ]

    @classmethod
    def post(cls):
        jti = get_raw_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT.
        user_id = get_jwt_identity()
        data = TokenModel.find_by_jti(jti)
        data.blacklisted = True
        data.save_to_db()
        resp = jsonify({"message": USER_LOGGED_OUT.format(user_id=user_id), 'logout': True})
        unset_jwt_cookies(resp)
        return resp, 200


class TokenRefresh(MethodView):

    #decorators = [jwt_refresh_token_required, ]

    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        # Issues a new token, but doesn't expire the old one...hmmmm
        print("TESTING!!!")
        print(get_raw_jwt())
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=user_id, fresh=False)
        access_decoded_token = decode_token(new_token)
        resp = jsonify({'refresh': True})
        set_access_cookies(resp, new_token)

        entry = {
            "jti": new_token,
            "token_type": 'access',
            "fresh": True,
            "blacklisted": False,
            "never_expire": False,
        }
        data = token_schema.load(entry)
        data.user_id = user_id
        data.expiration_date = datetime.fromtimestamp(access_decoded_token['exp'])
        data.save_to_db()

        return resp, 200


class TokenRefreshLogin(MethodView):

    #decorators = [jwt_refresh_token_required, ]

    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        user_json = request.get_json()
        user_data = user_schema.load(user_json)
        user = UserModel.find_by_username(user_data.username)

        if user and user.check_password(user_json['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            access_decoded_token = decode_token(access_token)

            entry = {
                "jti": access_decoded_token["jti"],
                "token_type": 'access',
                "fresh": True,
                "blacklisted": False,
                "never_expire": False,
            }
            data = token_schema.load(entry)
            data.user_id = user.id
            data.expiration_date = datetime.fromtimestamp(access_decoded_token['exp'])
            data.save_to_db()

            resp = jsonify({'refresh': True, 'login': True})
            set_access_cookies(resp, access_token)
            return resp, 200

        return {"message": INVALID_CREDENTIALS}, 401


class TestView(MethodView):

    decorators = [jwt_required, ]

    @classmethod
    def get(cls):
        jti = get_raw_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT.
        user_id = get_jwt_identity()
        user = UserModel.find_by_id(_id=user_id)
        co = user.company
        roles = [role.name for role in user.roles]
        return {"user": user_schema.dump(user), "jti": jti, "roles": roles}


class TokenView(MethodView):

    decorators = [jwt_required, ]

    @classmethod
    def post(cls):
        data = TokenModel.find_by_jti(get_raw_jwt()["jti"])
        if data:
            return jsonify({"data": token_schema.dump(data), "errors": {}, "status": 200})

        return {"message": OBJECT_NOT_FOUND.format('Token', 'None')}, 404


class NeverTokenView(MethodView):

    decorators = [jwt_required, ]

    @classmethod
    def post(cls):
        data = TokenModel.find_by_jti(get_raw_jwt()["jti"])
        user_id = get_jwt_identity()

        data.blacklisted = True
        data.save_to_db()

        access_token = create_access_token(identity=user_id, expires_delta=False)
        refresh_token = create_refresh_token(user_id)
        access_decoded_token = decode_token(access_token)

        entry = {
            "jti": access_decoded_token["jti"],
            "token_type": 'access',
            "fresh": False,
            "blacklisted": False,
            "never_expire": True,
        }
        data = token_schema.load(entry)
        data.user_id = user_id
        # data.expiration_date = None
        data.save_to_db()

        return {"access_token": access_token, "refresh_token": refresh_token}, 200