&nbsp;

**登陆路由**：

```/auth/login```

方法：POST

传入：<code>username, password</code>

登陆成功：返回<code>{'data': token, 'status':1}</code>

不存在用户：返回 <code>{'message' : 'unknown user'}</code>

密码错误：返回 <code>{'message': 'wrong password'}</code>

用户未确认：返回<code>{'message': 'not confirmed'}</code>

&nbsp;

&nbsp;

**更改头像**:

```/auth/chic```

方法：POST

传入：
<code>username, icon</code>

更改成功：返回
<code>{‘message’: 'success', 'status': 1}</code>

&nbsp;

&nbsp;

**忘记密码**：

```/auth/forget```

方法：POST

传入：<code>username, email</code>

用户存在：返回 <code>{'data': email}</code>

用户不存在：返回 <code>{'message': 'unknown user'}</code>

&nbsp;

&nbsp;

**注册路由**:

```/auth/register```

方法：POST

传入：
<code>email, username, password, icon</code>

注册成功：返回
<code>{‘message’: 'success', 'status': 1}</code>

发送邮件失败：返回
<code>{'message': 'failed to send email'}</code>

用户名已存在：返回
<code>{'message': 'username failed'}</code>

邮箱已存在：返回
<code>{'message': 'email failed'}</code>

未知错误：返回
<code>{'message': 'unknown'}</code>

&nbsp;

&nbsp;

**确认邮箱**：

```/auth/confirm/<code>```

方法:POST

确认成功：返回
<code>{'message': 'success', 'status': 1}</code>

用户已存在：返回
<code>{'message': 'Already confirmed'}</code>

验证码错误：返回
<code>{'message': 'wrong code'}</code>

验证码超时：返回
<code>{'message': 'Timed out'}</code>

&nbsp;

&nbsp;

**重发验证码**：

```/auth/confirm</code>```

方法：POST

重发成功：返回
<code>{'message': 'success', 'status': 1} </code>

发送邮件失败：返回
<code>{'message': 'failed to send email'} </code>

用户已确认过：返回
<code>{'message': 'Already confirmed'}</code>

&nbsp;

(错误下status均为0)
