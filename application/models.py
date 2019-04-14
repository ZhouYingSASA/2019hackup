import datetime
import random
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
    code = db.Column(db.String(4))
    verify_time = db.Column(db.DateTime, default=datetime.datetime.now())

    def generate_confirmation_token(self, expiration=3000):  # 生成token
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'email': self.email}).decode('utf-8')

    def verify_confirmation_token(self, token):  # 解析token
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('email') != self.email:
            return False
        return True

    def confirm(self, code, password=''):  # 验证
        if self.code == code:
            if datetime.datetime.now() - self.verify_time < datetime.timedelta(hours=2):  # 如果验证码未发送2小时
                if password:
                    self.password_hash = self.password(kwargs['password'])  # 修改密码
                elif not self.confirmed:
                    self.confirmed = True
                    self.verify_time -= datetime.timedelta(hours=2)  # 验证码用后过期
                    db.session.add(self)
                    db.session.commit()
                    return True
                else:
                    # Already confirmed
                    return 1
            else:
                # Timed out
                return 0
        else:
            return False

    def ver_code(self):  # 生成验证码
        li = []
        for i in range(4):  # 循环4次,生成4个字符
            num = random.randrange(0, 9)
            li.append(str(num))
        r_code = ''.join(li)  # 拼接为字符串并转化为int
        self.code = r_code
        self.verify_time = datetime.datetime.now()
        db.session.add(self)
        db.session.commit()
        return r_code  # 返回字符串

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username
