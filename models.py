from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4

db = SQLAlchemy()

def get_uuid():
    return uuid4().hex

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String, primary_key=True, unique=True, default=get_uuid)
    name = db.Column(db.String(150), default='')
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"
