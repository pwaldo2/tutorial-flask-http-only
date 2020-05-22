from datetime import datetime

from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_claims

from sqlalchemy import event
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm.query import Query

from api.models import db, CRUDMixin
from api import bcrypt


api_auth_roles_users = db.Table(
    'api_auth_roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('api_auth_user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('api_auth_role.id'), primary_key=True),
    db.PrimaryKeyConstraint('user_id', 'role_id')
)


class CompanyQuery(Query):
    current_company_constrained = True

    def company_unconstrained_unsafe(self):
        rv = self._clone()
        rv.current_company_constrained = False
        return rv


class CompanyBoundMixin(object):
    query_class = CompanyQuery

    @declared_attr
    def company_id(cls):
        return db.Column(db.Integer, db.ForeignKey('api_auth_company.id'))

    @declared_attr
    def company(cls):
        return db.relationship(CompanyModel)


@event.listens_for(Query, "before_compile", retval=True)
def company_filter(query):
    if request.headers.get('Authorization'):
        claims = get_jwt_claims()
        for desc in query.column_descriptions:
            if hasattr(desc['type'], 'company_id'):
                try:
                    query = query.filter_by(company_id = claims['company_id'])
                except Exception as err:
                    # print(err)
                    # Query.filter() being called on a Query which already has LIMIT or OFFSET applied. To modify the row-limited results of a  Query, call from_self() first.  Otherwise, call filter() before limit() or offset() are applied.
                    # Not sure how to deal with this
                    return None

        return query


class TokenModel(db.Model, CRUDMixin):
    __tablename__ = "api_auth_token"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String, nullable=False, unique=True)
    token_type = db.Column(db.String, nullable=False)
    fresh = db.Column(db.Boolean, nullable=False, default=False)
    blacklisted = db.Column(db.Boolean, nullable=False, default=False)
    never_expire = db.Column(db.Boolean, nullable=False, default=False)

    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiration_date = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey(
        'api_auth_user.id'))  # Each token has one user
    user = db.relationship("UserModel")

    @classmethod
    def find_by_jti(cls, _jti):
        return cls.query.filter_by(jti=_jti).first()


class CompanyModel(db.Model, CRUDMixin):
    __tablename__ = "api_auth_company"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    active = db.Column(db.Boolean())
    address = db.Column(db.String(255))
    city = db.Column(db.String(255))
    zip = db.Column(db.Integer)

    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    modification_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    def __str__(self):
        return self.name

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).first()


class RoleModel(db.Model, CRUDMixin):
    __tablename__ = "api_auth_role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return '<id {}>'.format(self.id)


class UserModel(db.Model):
    __tablename__ = "api_auth_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, default='SOME_SECRET')
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())

    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    modification_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    roles = db.relationship('RoleModel', secondary=api_auth_roles_users, lazy='subquery',
                             backref=db.backref('users', lazy=True))
    company_id = db.Column(db.Integer, db.ForeignKey('api_auth_company.id'))  # Each user has one company
    company = db.relationship("CompanyModel")


    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_company(cls, _id):
        return cls.query.filter_by(company_id=_id).all()

    def set_password(self, pw):
        pwhash = bcrypt.generate_password_hash(pw.encode('utf8'))
        self.password = pwhash.decode('utf8')

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password, pw)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        return db.session.commit()