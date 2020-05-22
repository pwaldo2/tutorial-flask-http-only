from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class CRUDMixin():

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    def save_to_db(self):
        db.session.add(self)
        return db.session.commit()

    def update(self):
        return db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        return db.session.commit()