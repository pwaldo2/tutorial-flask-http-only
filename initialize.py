import click
import csv
import os

from flask import Blueprint
from flask.cli import with_appcontext

from api import create_app
from api.db import db
from api.auth.models import RoleModel
from api.auth.models import UserModel
from api.auth.schemas import RoleSchema
from api.auth.schemas import RoleUserSchema
from api.auth.schemas import CompanySchema
from api.auth.schemas import UserPostSchema

from marshmallow import ValidationError

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = create_app()

@click.group()
def cli():
    pass

@cli.command()
def hello():
    print("Hiya!")

@cli.command()
def roles():
    with app.app_context():
        role_schema = RoleSchema()

        entries = [{'name': 'ADMIN', 'description': 'Admin role has total access, restricted to Devs'},
                   {'name': 'SITE_ADMIN',
                    'description': 'Site Admin role has total access for a Company, restricted to users'},
                   {'name': 'USER', 'description': 'User role has content creation access'},
                   ]

        entries = [{'name': 'TEST', 'description': 'Test role has content creation access'},]
        print('Seeding DB with standard roles...')
        for entry in entries:
            errors = role_schema.validate(entry)

            if errors:
                print("ERROR")
                print(errors)

            data = role_schema.load(entry)
            data.save_to_db()
            print('Add...', entry)

        print("Success!")

@cli.command()
def company():
    with app.app_context():
        company_schema = CompanySchema()
        entry = {"active": 1,
                "address": "123 Main Street",
                "city": "Houston",
                "name": "Test Company",
                "zip": "77008"
                }

        data = company_schema.load(entry)
        data.save_to_db()
        print('Added...', entry)

        print("Success!")


@cli.command()
def user():
    with app.app_context():
        user_post_schema = UserPostSchema()
        role_user_schema = RoleUserSchema()

        entry = {"username":"testuser123",
                "password": "test123",
                "first_name": "Patrick",
                "last_name": "Waldo",
                "email": "test123@example.com",
                "active": 1,
                "company_id": 1,
                "roles":[{"id": 3}]
                }

        # errors = user_post_schema.validate(entry, session=db.session)
        # https://github.com/marshmallow-code/marshmallow-sqlalchemy/issues/20#issuecomment-136400602

        # if errors:
        #     print("ERROR")
        #     print(errors)

        # role = RoleModel.find_by_id(3)

        try:
            data = user_post_schema.load(entry)
        except ValidationError as err:
            errors = err.messages
            valid_data = err.valid_data

        data.set_password(entry['password'])
        # data.roles.append(role_user_schema.load({"id": 3}, session=db.session))
        # data.roles.append(role)
        data.save_to_db()

        print("Success!")


if __name__ == '__main__':
    cli()