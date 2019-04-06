import random, datetime
from flask import request
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..email import send_email
from ..models import Users


@auth.route('/login', methods=['POST'])  # 登陆路由
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()
        if email is None:
            error = "no email"
            # print(error)
            return {'error': error}
        elif user is None:
            error = "unknown user"
            # print(error)
            return {'error': error}
        elif user.verify_password(password):
                login_user(user)
                # print('login')
                return user.generate_confirmation_token()
        else:
            error = "wrong password"
            # print(error)
            return {'error': error}
    # print("error")
    return error


def ver_code():
    li = []
    for i in range(4):  # 循环4次,生成4个字符
        num = random.randrange(0, 9)
        li.append(str(num))
    r_code = ''.join(li)  # 6个字符拼接为字符串
    return r_code  # 返回字符串


@auth.route('/register', methods=['POST', 'GET'])  # 注册路由
def register():
    if Users.query.filter_by(email=request.form['email']).all():
        return {'error': 'email'}
    elif Users.query.filter_by(username=request.form['username']).all():
        return {'error': 'username'}
    else:
        user = Users()
        code = ver_code()

        def reg_user():
            nonlocal user
            if Users.query.filter_by(email=request.form.['email']):
                return {'error': 'email failed'}
            elif Users.query.filter_by(username=request.form['username']):
                return {'error': 'username failed'}
            user.email = request.form['email']
            user.username = request.form['username']
            user.password = request.form['password']
            user.code = code
            user.verify_time = datetime.datetime.now()
        try:
            reg_user()
            db.session.add(user)
        except:
            print('register user failed')
            return {'error': 'unknown'}

        db.session.commit()
        try:
            send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user, code=code)
        except:
            print('send email failed')
            return {'error': 'fail to send email'}

        return {'status': 1}


@auth.route('/confirm/<code>', method='GET')  # 邮箱确认路由
def confirm(code):
    if current_user.confirmed:
        return {'error': 'Already confirmed.'}
    elif current_user.code != code:
        return {'error': 'wrong code'}
    else:
        try:
            current_user.confirm()
            return {'status': 1}
        except:
            return {'error': 'unknown'}
