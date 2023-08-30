from hack import db,login_manager
from flask_login import UserMixin
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String(64), index=True)
    password = db.Column(db.String)
    sent_messages = db.relationship('Message', back_populates='sender', foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', back_populates='receiver', foreign_keys='Message.receiver_id')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_content = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_messages')