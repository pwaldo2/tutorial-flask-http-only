from api.db import db
from api.ma import ma
from api.models import CategoryModel
from api.models import ArticleModel


class CategoryPostSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = CategoryModel
        dump_only = ("name", )
        load_only = ("articles", )
        load_instance = True


class ArticlePostSchema(ma.SQLAlchemyAutoSchema):
    categories = ma.Nested(CategoryPostSchema, many=True)

    class Meta:
        model = ArticleModel
        dump_only = ("id",)
        include_fk = True
        load_instance = True
        include_relationships = True


class CategorySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = CategoryModel
        dump_only = ("id", )
        load_only = ("articles", )
        load_instance = True


class ArticleSchema(ma.SQLAlchemyAutoSchema):
    categories = ma.Nested(CategorySchema, many=True)

    class Meta:
        model = ArticleModel
        dump_only = ("id", )
        include_fk = True
        load_instance = True