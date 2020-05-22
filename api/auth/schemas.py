from api.db import db
from api.ma import ma
from api.auth.models import UserModel
from api.auth.models import CompanyModel
from api.auth.models import RoleModel
from api.auth.models import TokenModel

class NewPasswordSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("username", "password", "new_password")

class CompanySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = CompanyModel
        include_fk = True
        # load_only = ("password",)
        dump_only = ("id",)
        load_instance = True


class RoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = RoleModel
        dump_only = ("id", )
        load_only = ("users", )
        load_instance = True


class RoleUserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = RoleModel
        dump_only = ("name", "description",)
        load_only = ("users",)
        load_instance = True


class UserPostSchema(ma.SQLAlchemyAutoSchema):
    company = ma.Nested(CompanySchema)
    roles = ma.Nested(RoleUserSchema, many=True)

    class Meta:
        model = UserModel
        load_only = ("password",)
        dump_only = ("id",)
        include_fk = True
        load_instance = True
        include_relationships = True
        sqla_session = db.session


class UserSchema(ma.SQLAlchemyAutoSchema):
    company = ma.Nested(CompanySchema)
    roles = ma.Nested(RoleSchema, many=True)

    class Meta:
        model = UserModel
        load_only = ("password",)
        dump_only = ("id",)
        include_fk = True
        load_instance = True


class TokenSchema(ma.SQLAlchemyAutoSchema):
    user = ma.Nested(UserSchema)
    class Meta:
        model = TokenModel
        include_fk = True
        dump_only = ("id")
        load_instance = True