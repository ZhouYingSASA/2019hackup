import datetime
import random
from flask import request, jsonify
from . import auth
from .. import db
from ..email import send_email
from ..models import Users


@auth.route('/login', methods=['POST'])  # 登陆路由
def login():
    data = {}
    status = 0
    user = Users.query.filter_by(username=request.form['username']).first()
    if request.form['password']:
        if user.confirmed:
            username = request.form['username']
            password = request.form['password']
            if username is None:
                message = 'no email'
                # print(message)
            elif user is None:
                message = 'unknown user'
                # print(message)
            elif user.verify_password(password):
                data['token'] = user.generate_confirmation_token()
                data['icon'] = user.icon
                message = 'success'
                status = 1
                # print(message)
            else:
                message = 'wrong password'
                # print(message)
        else:
            message = 'not confirmed'
    else:
        if user:
            message = 'success'
            data['icon'] = user.icon
        else:
            message = 'unknown user'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/is_exist', methods=['POST'])  # 邮箱检测
def is_exist():
    status = 0
    email = request.form['email']
    user = Users.query.filter_by(email=email).first()
    if not user:
        message = 'ok'
        status = 1
    else:
        message = 'exist'
    return jsonify({
        'message': message,
        'status': status
    })


@auth.route('/email', methods=['POST'])  # 用户名=>邮箱匹配
def get_email():
    status = 0
    message = 'fail'
    user = Users.query.filter_by(username=request.form['username']).first()
    if user.email == request.form['email']:
        message = 'success'
        status = 1
    return jsonify({
        'message': message,
        'status': status
    })


@auth.route('/chic', methods=['POST'])  # 更改头像
def chic():
    user = Users.query.filter_by(username=request.form['username']).first()
    user.icon = request.form['icon']
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'message': 'success',
        'status': 1
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
                         code=code, icon=request.form['icon'], password=request.form['password'],
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


@auth.route('/con', methods=['POST'])  # 邮箱确认路由
def confirm():
    data = {}
    status = 0
    code = request.form['code']
    user = Users.query.filter_by(email=request.form['email']).first()
    if user.confirmed:
        message = 'Already confirmed.'
    else:
        con = user.confirm(code)
        print(con)
        if con == 2:
            message = 'Timed out'
        elif con:
            message = 'success'
            status = 1
        elif not con:
            message = 'wrong code'
        else:
            message = 'unknown'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/forget', methods=['POST'])  # 忘记密码(发送验证码)
def forget():
    data = {}
    status = 0
    message = 'unknown user'
    username = request.form['username']
    user = Users.query.filter_by(username=username).first()
    if user.email == request.form['email']:
        user.ver_code()
        send_email(user.email, '确认验证码', 'auth/email/confirm', user=user, code=user.code)
        message = 'success'
        status = 1
    else:
        message = "not match"
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/code', methods=['POST'])  # 忘记密码(确认验证码)
def verify_code():
    data = {}
    message = ''
    status = 0
    user = Users.query.filter_by(username=request.form['username']).first()
    if user.email == request.form['email']:
        is_code = user.confirm(request.form['code'])
        if is_code:
            data['token'] = user.generate_confirmation_token()
            message = 'success'
        elif is_code == 2:
            message = 'Timed out'
    else:
        message = 'not match'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/password', methods=['POST'])  # 修改密码
def change_password():
    status = 0
    user = Users.query.filter_by(email=request.form['email']).first()
    if user:
        if user.verify_confirmation_token(request.form['token']):
            user.password = request.form['password']
            db.session.commit()
            message = 'success'
            status = 1
        else:
            message = 'token failed'
    else:
        message = 'unknown user'
    return jsonify({
        'message': message,
        'status': status
    })


@auth.route('/confirm', methods=['POST'])  # 重发验证码路由
def resend():
    data = {}
    status = 0
    user = Users.query.filter_by(email=request.form['email']).first()
    code = user.ver_code()
    try:
        send_email(user.email, '注册确认邮件', 'auth/email/confirm', user=user.username, code=code)
        status = 1
        message = 'success'
    except:
        print('send email failed')
        message = 'fail to send email'
    return jsonify({
        'data': data,
        'message': message,
        'status': status
    })


@auth.route('/pass', methods=['POST'])
def level_pass():
    status = 0
    username = request.form['username']
    token = request.form['token']


def ver_code():  # 生成验证码
    li = []
    for i in range(4):  # 循环4次,生成4个字符
        num = random.randrange(0, 9)
        li.append(str(num))
    r_code = ''.join(li)  # 拼接为字符串
    return r_code  # 返回code
