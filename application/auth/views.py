import datetime
from flask import request, jsonify
from . import auth
from .. import db
from ..email import send_email
from ..models import Users


@auth.route('/login', methods=['POST'])  # 登陆路由
def login():
    data = {}
    status = 0
    if request.form['password']:
        if Users.query.filter_by(username=request.form['username']).first().confirmed:
            username = request.form['username']
            password = request.form['password']
            user = Users.query.filter_by(username=username).first()
            if username is None:
                message = 'no email'
                # print(message)
            elif user is None:
                message = 'unknown user'
                # print(message)
            elif user.verify_password(password):
                data['token'] = user.generate_confirmation_token()
                message = 'success'
                status = 1
                # print(message)
            else:
                message = 'wrong password'
                # print(message)
        else:
            message = 'not confirmed'
    else:
        if Users.query.filter_by(username=request.form['username']).first():
            message = 'success'
        else:
            message = 'unknown user'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/password', methods=['POST'])  # 修改密码
def get_email():
    data = {}
    status = 0
    user = Users.query.filter_by(username=request.form['username']).first()
    if user.email == request.form['email']:
        user.password = request.form['password']
        db.session.commit()
        message = 'success'
    else:
        message = 'wrong email'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/forget', methods=['POST'])  # 忘记密码
def forget():
    data = {}
    status = 0
    username = request.form['username']
    user = Users.query.filter_by(username=username)
    if user.email == request.form['email']:
        user.confirm(request.form['code'], password=request.form['password'])
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/register', methods=['POST', 'GET'])  # 注册路由
def register():
    data = {}
    status = 0
    if Users.query.filter_by(email=request.form['email']).first():
        message = 'email failed'
    elif Users.query.filter_by(username=request.form['username']).first():
        message = 'username failed'
    else:
        try:
            code = ver_code()
            user = Users(email=request.form['email'], username=request.form['username'],
                         password=request.form['password'], icon=request.form['icon'], code=code,
                         verify_time=datetime.datetime.now())
            db.session.add(user)
            db.session.commit()
            send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user, code=user.code)
            message = 'success'
            status = 1
        except:
            print('send email failed')
            message = 'fail to send email'

    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/confirm/<code>', methods=['POST'])  # 邮箱确认路由
def confirm(code):
    data = {}
    status = 0
    code = int(code)
    user = Users.query.filter_by(email=request.form['email']).first()
    if user.confirmed:
        message = 'Already confirmed.'
    else:
        con = user.confirm(code)
        if con == 0:
            message = 'Timed out'
        elif con:
            message = 'success'
            status = 1
        else:
            message = 'unknown'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/confirm', methods=['POST'])  # 重发验证码路由
def resend():
    data = {}
    status = 0
    user = Users.query.filter_by(email=request.form['email']).first()
    if not user.confirmed:
        code = user.ver_code()
        try:
            send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user.username, code=code)
            status = 1
            message = 'success'
        except:
            print('send email failed')
            message = 'fail to send email'
    else:
        message = 'already confirmed'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


def ver_code():  # 生成验证码
    li = []
    for i in range(4):  # 循环4次,生成4个字符
        num = random.randrange(0, 9)
        li.append(str(num))
    r_code = int(''.join(li))  # 拼接为字符串并转化为int
    return r_code  # 返回code
