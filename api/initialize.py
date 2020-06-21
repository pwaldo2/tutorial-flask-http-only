import click
import csv
import os

from flask import current_app
from flask.cli import with_appcontext
from flask.cli import AppGroup

from api import create_app
from api.db import db
from api.auth.schemas import RoleSchema
from api.auth.schemas import RoleUserSchema
from api.auth.schemas import CompanySchema
from api.auth.schemas import UserPostSchema

from marshmallow import ValidationError

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

initialize_cli = AppGroup('initialize')

@initialize_cli.command()
def sayhi():
    print("Hiya!")

@initialize_cli.command()
@with_appcontext
def roles():
    role_schema = RoleSchema()

    entries = [{'name': 'ADMIN', 'description': 'Admin role has total access, restricted to Devs'},
               {'name': 'SITE_ADMIN',
                'description': 'Site Admin role has total access for a Company, restricted to users'},
               {'name': 'USER', 'description': 'User role has content creation access'},
               ]

    print('Seeding DB with standard roles...')

    with current_app.test_request_context('/auth/role/'):
        for entry in entries:
            try:
                data = role_schema.load(entry)
                data.save_to_db()
                print('Add...', entry)
            except ValidationError as err:
                errors = err.messages
                valid_data = err.valid_data
                print (errors, valid_data)

@initialize_cli.command()
@with_appcontext
def company():
    company_schema = CompanySchema()
    entry = {"active": 1,
            "address": "123 Main Street",
            "city": "Houston",
            "name": "Test Company",
            "zip": "77008"
            }
    print('Seeding DB with Test Company...')
    with current_app.test_request_context('/auth/company/'):
        try:
            data = company_schema.load(entry)
            data.save_to_db()
            print('Added...', entry)
        except ValidationError as err:
            errors = err.messages
            valid_data = err.valid_data
            print(errors, valid_data)

@initialize_cli.command()
@with_appcontext
def user():

    user_post_schema = UserPostSchema()
    role_user_schema = RoleUserSchema()

    entry = {"username":"testuser",
            "password": "test123",
            "first_name": "Patrick",
            "last_name": "Waldo",
            "email": "testuser@example.com",
            "active": 1,
            "company_id": 1,
            "roles":[{"id": 3}]
            }
    print('Seeding DB with test user...')
    with current_app.test_request_context('/auth/register/'):
        try:
            data = user_post_schema.load(entry)
            data.set_password(entry['password'])
            data.save_to_db()
            print("Loading...", entry['username'])
        except ValidationError as err:
            errors = err.messages
            valid_data = err.valid_data
            print (errors, valid_data)

