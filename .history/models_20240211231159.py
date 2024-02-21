from . import db

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True) 
    google_id = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(80), nullable=False)

# Other model classes