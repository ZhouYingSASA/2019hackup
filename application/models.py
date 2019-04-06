import datetime
from . import db
from flask import current_app
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from werkzeug.security import check_password_hash, generate_password_hash


class Users(UserMixin, db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    username = db.Column(db.String(20), unique=True, index=True)
    email = db.Column(db.String(20), unique=True, index=True)
    password_hash = db.Column(db.String(64))
    confirmed = db.Column(db.Boolean, default=False)
    passed = db.Column(db.Integer, default=0)
    icon = db.Column(db.SmallInteger, nullable=False)
    code = db.Column(db.SmallInteger)
    verify_time = db.Column(db.DateTime, default=datetime.datetime.now())

    def generate_confirmation_token(self, expiration=3000):  # 生成token
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.email}).decode('utf-8')

    def confirm(self, code):  # 验证
        if self.code == code:
            if datetime.datetime.now() - self.verify_time <= datetime.timedelta(hours=2):  # 如果验证码未发送2小时
                self.confirmed = True
                db.session.add(self)
                db.session.commit()
                return True
            else:
                return 0
        else:
            return False

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.email
