from app import db 
from sqlalchemy import DateTime
from sqlalchemy.sql import func


#Models
class Users(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    fName = db.Column(db.String(200), nullable=False)
    lName = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True, nullable=False)
    userName = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Jobs(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(500))
    jobTitle = db.Column(db.String(500))
    jobDesc = db.Column(db.String(500))
    jobRate = db.Column(db.String(500))
    latitiude = db.Column(db.String(500))
    longitude = db.Column(db.String(500))
    isActive = db.Column(db.Boolean, default=True, nullable=False)
    jobCreated = db.Column(DateTime(timezone=True), server_default=func.now())
    jobUpdated = db.Column(DateTime(timezone=True), onupdate=func.now())

    def update_to_db(self, data):
        for key, value in data.items():
            setattr(self, key, value)
        db.session.commit()
