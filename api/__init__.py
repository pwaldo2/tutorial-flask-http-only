import os

import click
from flask.cli import AppGroup
from dotenv import load_dotenv

from flask import Flask
from flask import jsonify

from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required, get_raw_jwt

from api.db import db
from api.ma import ma

bcrypt = Bcrypt()
jwt = JWTManager()
cors = CORS()

def create_app():

    app = Flask(__name__)

    app.config.from_object(os.getenv('APP_SETTINGS'))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') # secrets.token_urlsafe(24)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['CSRF_ENABLED'] = True
    app.config['BCRYPT_LOG_ROUNDS'] = 15
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/auth/refresh/'
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True
    app.config['JWT_CSRF_CHECK_FORM'] = True
    app.config["JWT_BLACKLIST_ENABLED"] = True  # enable blacklist feature
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = [
        "access",
        "refresh",
    ]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True

    db.init_app(app)
    ma.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)

    with app.app_context():

        # Register Models

        from api.models import CategoryModel
        from api.models import ArticleModel
        from api.auth.models import UserModel
        from api.auth.models import CompanyModel
        from api.auth.models import RoleModel
        from api.auth.models import TokenModel

        # Register Views

        from api.resources import ArticleListView
        from api.resources import CategoryListView
        from api.auth.resources import RoleDetailView
        from api.auth.resources import RoleListView
        from api.auth.resources import UserView
        from api.auth.resources import UserRegisterView
        from api.auth.resources import UserLoginView
        from api.auth.resources import TestView
        from api.auth.resources import UserLogoutView
        from api.auth.resources import TokenRefresh
        from api.auth.resources import CompanyView
        from api.auth.resources import CompanyListView
        from api.auth.resources import TokenRefreshLogin
        from api.auth.resources import NeverTokenView
        from api.auth.resources import TokenView
        from api.auth.resources import ChangePasswordView

        api_article_list = ArticleListView.as_view('api_article_list')
        app.add_url_rule('/article/', view_func=api_article_list, methods=['GET', 'POST', ])

        api_category_list = CategoryListView.as_view('api_category_list')
        app.add_url_rule('/category/', view_func=api_category_list, methods=['GET', 'POST', ])


        user_auth = UserView.as_view('user_auth')
        app.add_url_rule('/auth/user/<int:user_id>', view_func=user_auth, methods=['GET', 'DELETE', ])

        role_list_auth = RoleListView.as_view('role_list_auth')
        app.add_url_rule('/auth/role/', view_func=role_list_auth, methods=['GET', 'POST', ])

        role_auth = RoleDetailView.as_view('role_auth')
        app.add_url_rule('/auth/role/<int:role_id>', view_func=role_auth, methods=['GET', 'POST', ])

        register_auth = UserRegisterView.as_view('register_auth')
        app.add_url_rule('/auth/register', view_func=register_auth, methods=['POST', ])

        login_auth = UserLoginView.as_view('login_auth')
        app.add_url_rule('/auth/login', view_func=login_auth, methods=['POST', ])

        test_auth = TestView.as_view('test_auth')
        app.add_url_rule('/auth/test', view_func=test_auth, methods=['GET', ])

        logout_auth = UserLogoutView.as_view('logout_auth')
        app.add_url_rule('/auth/logout', view_func=logout_auth, methods=['POST', ])

        refresh_auth = TokenRefresh.as_view('refresh_auth')
        app.add_url_rule('/auth/refresh', view_func=refresh_auth, methods=['POST', ])

        refresh_login_auth = TokenRefreshLogin.as_view('refresh_login_auth')
        app.add_url_rule('/auth/refresh/login', view_func=refresh_login_auth, methods=['POST', ])

        company_list_api = CompanyListView.as_view('company_list_api')
        app.add_url_rule('/auth/company/', view_func=company_list_api, methods=['GET', 'POST', ])

        company_api = CompanyView.as_view('company_api')
        app.add_url_rule('/auth/company/<int:_id>', view_func=company_api, methods=['GET', 'PUT', 'DELETE', ])

        test_token = TokenView.as_view('test_token')
        app.add_url_rule('/auth/token', view_func=test_token, methods=['POST', ])

        never_token = NeverTokenView.as_view('never_token')
        app.add_url_rule('/auth/token/never', view_func=never_token, methods=['POST', ])

        change_password = ChangePasswordView.as_view('change_password')
        app.add_url_rule('/auth/change-password', view_func=change_password, methods=['POST', ])

        # Blueprints

        from api.auth import auth_bp

        app.register_blueprint(auth_bp)

        # Authentication

        @jwt.token_in_blacklist_loader
        def check_if_token_in_blacklist(decrypted_token):
            data = TokenModel.find_by_jti(decrypted_token["jti"])
            if data:
                return data.blacklisted
            else:
                return None

        @jwt.user_claims_loader
        def add_claims_to_access_token(identity):
            return {
                'user': identity,
                'company_id': UserModel.find_by_id(_id=identity).company_id,
                'roles': [role.name for role in UserModel.find_by_id(_id=identity).roles]
            }

        @app.errorhandler(403)
        def permission_denied(e):
            return {"errors": "You don't have permission to view this resource"}, 403

        app.register_error_handler(403, permission_denied)

        # Custom Views

        @app.route('/hello/')
        @app.route('/hello/<string:name>')
        def hello(name=None):
            if name:
                return jsonify({'message':'Hi {}!'.format(name)})
            return jsonify({'message':'Hello World!'})



        from api.initialize import initialize_cli

        app.cli.add_command(initialize_cli)

        return app