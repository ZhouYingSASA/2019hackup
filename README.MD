&nbsp;

**登陆路由**：

```/auth/login```

方法：POST

传入：<code>username, password</code>

登陆成功：返回<code>{'data': token, 'icon': icon 'status':1}</code>

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

**邮箱检测**：

```/auth/is_exist```

方法：POST

传入：
<code>email</code>

email未注册过：返回<code>{'message': 'ok', 'status': 1}</code>

email存在：返回<code>{'message': 'exist'}</code>

&nbsp;

&nbsp;

**用户名、邮箱匹配**：

```/auth/email```

传入：
<code>username, email</code>

匹配：返回<code>{'message': 'success', 'status': 1}</code>

不匹配：返回<code>{'message': 'fail'}</code>'

不存在用户：返回<code>{'message': 'unknown user'}</code>

&nbsp;

&nbsp;

**确认邮箱**：

```/auth/con```

方法:POST

传入：<code>email, code</code>

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

**忘记密码(发送验证码)**：

```/auth/forget```

方法：POST

传入：<code>username, email</code>

已发送验证码：返回 <code>{'data': 'success', 'status': 1}</code>

用户邮箱不存在：返回 <code>{'message': 'not match'}</code>

&nbsp;

&nbsp;

**忘记密码(确认验证码)**：

```/auth/code```

方法：POST

传入：<code>username, email, code</code>

验证码正确：返回 <code>{'data': token, 'message': 'success', 'status': 1}</code>

用户邮箱不匹配：返回 <code>{'message': 'not match'}</code>

验证码过期：返回<code>{'message': 'Timed out', 'status': 0}</code>

&nbsp;

&nbsp;

**修改密码**:

```/auth/password```

方法：POST

传入：<code>email, token, password</code>

修改成功：返回<code>{'message': 'success', 'status': 1}</code>

email不存在：返回<code>{'message': 'unknown user'}</code>

token错误：返回<code>{'message': 'token failed'}</code>

&nbsp;

&nbsp;

**重发验证码**：

```/auth/confirm```

方法：POST

传入：<code>email, code</code>

重发成功：返回
<code>{'message': 'success', 'status': 1} </code>

发送邮件失败：返回
<code>{'message': 'failed to send email'} </code>

&nbsp;

(错误下status均为0)
