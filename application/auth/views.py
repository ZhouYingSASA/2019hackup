import random
import datetime
from flask import request, jsonify
from . import auth
from .. import db
from ..email import send_email
from ..models import Users


@auth.route('/login', methods=['POST'])  # 登陆路由
def login():
    if Users.query.filter_by(email=request.form['email']).first().confirmed:
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()
        if email is None:
            error = 'no email'
            # print(error)
            return jsonify({'error': error})
        elif user is None:
            error = 'unknown user'
            # print(error)
            return jsonify({'error': error})
        elif user.verify_password(password):
                # print('login')
                return user.generate_confirmation_token()
        else:
            error = 'wrong password'
            # print(error)
            return jsonify({'error': error})
    else:
        return jsonify({'error': 'not confirmed'})


def ver_code():  # 生成验证码
    li = []
    for i in range(4):  # 循环4次,生成4个字符
        num = random.randrange(0, 9)
        li.append(str(num))
    r_code = ''.join(li)  # 6个字符拼接为字符串
    return r_code  # 返回字符串


@auth.route('/register', methods=['POST', 'GET'])  # 注册路由
def register():
    if Users.query.filter_by(email=request.form['email']).first():
        return jsonify({'error': 'email failed'})
    elif Users.query.filter_by(username=request.form['username']).first():
        return jsonify({'error': 'username failed'})
    else:
        code = ver_code()

        try:
            user = Users(email=request.form['email'], username=request.form['username'],
                         password=request.form['password'], icon=request.form['icon'], code=code,
                         verify_time=datetime.datetime.now())
            db.session.add(user)
            db.session.commit()
        except:
            print('register user failed')
            return jsonify({'error': 'unknown'}), 500

        try:
            send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user, code=user.code)
        except:
            print('send email failed')
            return jsonify({'error': 'fail to send email'})

        return jsonify({'status': 1})


@auth.route('/confirm/<code>', methods=['POST'])  # 邮箱确认路由
def confirm(code):
    code = int(code)
    user = Users.query.filter_by(email=request.form['email']).first()
    if user.confirmed:
        return jsonify({'error': 'Already confirmed.'})
    else:
        con = user.confirm(code)
        if con == 0:
            return jsonify({'error': 'Timed out'})
        elif con:
            return jsonify({'status': 1})
        else:
            return jsonify({'error': 'unknown'})


@auth.route('/confirm', methods=['POST'])  # 重发验证码路由
def resend():
    user = Users.query.filter_by(email=request.form['email']).first()
    if not user.confirmed:
        code = ver_code()
        user.code = code
        db.session.add(user)
        db.session.commit()
        try:
            send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user.username, code=user.code)
        except:
            print('send email failed')
            return jsonify({'error': 'fail to send email'})
        return jsonify({'status': 1})
    else:
        return jsonify({'error': 'already confirmed'})
