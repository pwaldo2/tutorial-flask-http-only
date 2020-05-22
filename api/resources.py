from flask import jsonify
from flask import request
from flask.views import MethodView

from flask_jwt_extended import jwt_required

from api.models import CategoryModel
from api.models import ArticleModel
from api.schemas import CategorySchema
from api.schemas import ArticleSchema
from api.schemas import ArticlePostSchema

OBJECT_DELETED = "{} object with <id {}> deleted"
OBJECT_NOT_FOUND = "{} object with <id {}> not found"

category_schema = CategorySchema()
category_list_schema = CategorySchema(many=True)
article_schema = ArticleSchema()
article_post_schema = ArticlePostSchema()
article_list_schema = ArticleSchema(many=True)


class CategoryListView(MethodView):

    decorators = [jwt_required, ]

    def __init__(self):
        pass

    @classmethod
    def get(cls):
        data = CategoryModel.find_all()
        return jsonify({"data": category_list_schema.dump(data),
                        "count": len(data),
                        "status": 200
                        })

    @classmethod
    def post(cls):

        req_json = request.get_json()
        errors = category_schema.validate(req_json)

        if errors:
            response = jsonify({'errors': errors, "status": 400})
            response.status_code = 400
            return response

        data = category_schema.load(req_json)
        data.save_to_db()

        response = jsonify({"data": category_schema.dump(data), "errors": {}, "status": 201})
        response.status_code = 201
        return response


class ArticleListView(MethodView):

    decorators = [jwt_required, ]

    def __init__(self):
        pass

    @classmethod
    def get(cls):
        data = ArticleModel.find_all()
        return jsonify({"data": article_list_schema.dump(data),
                        "count": len(data),
                        "status": 200
                        })

    @classmethod
    def post(cls):

        req_json = request.get_json()
        errors = article_post_schema.validate(req_json)

        if errors:
            response = jsonify({'errors': errors, "status": 400})
            response.status_code = 400
            return response

        data = article_post_schema.load(req_json)
        data.save_to_db()

        response = jsonify({"data": article_post_schema.dump(data), "errors": {}, "status": 201})
        response.status_code = 201
        return response