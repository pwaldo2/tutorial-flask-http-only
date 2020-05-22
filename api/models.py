from api.db import db, CRUDMixin
from api import bcrypt


api_category_article = db.Table('api_category_article',
                          db.Column('category_id', db.Integer, db.ForeignKey('api_category.id'), primary_key=True),
                          db.Column('article_id', db.Integer, db.ForeignKey('api_article.id'), primary_key=True),
                          db.PrimaryKeyConstraint('category_id', 'article_id')
                    )


class CategoryModel(db.Model, CRUDMixin):
    __tablename__ = "api_category"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<id {}>'.format(self.id)


class ArticleModel(db.Model, CRUDMixin):
    __tablename__ = 'api_article'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)

    categories = db.relationship('CategoryModel', secondary=api_category_article, lazy='subquery',
                             backref=db.backref('articles', lazy=True))

    def __repr__(self):
        return '<id {}>'.format(self.id)