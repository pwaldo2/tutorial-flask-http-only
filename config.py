"""
export APP_SETTINGS="config.DevelopmentConfig"
export DATABASE_URL='postgresql://localhost/legaldocs'
"""

import os
# import toastedmarshmallow

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    DEBUG = False
    TESTING = False
    PROPAGATE_EXCEPTIONS = True
    # MARSHMALLOW_SCHEMA_DEFAULT_JIT = toastedmarshmallow.Jit


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True