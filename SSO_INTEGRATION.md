# TAOS SSO 单点登录接入文档

本文档说明如何将外部论坛/系统与 TAOS（Triangle Agency Operation System）进行单点登录集成。

## 概述

TAOS 支持通过 JWT Token 方式实现单点登录。用户在论坛登录后，点击跳转链接即可自动登录 TAOS，无需再次输入账号密码。

## 接入流程

```
论坛用户 → 点击"进入TAOS" → 论坛生成JWT Token → 跳转到TAOS /auth/sso → TAOS验证并登录 → 进入Dashboard
```

## 配置

### TAOS 端配置

在 `server.js` 中配置 SSO 参数（或通过环境变量）：

```javascript
const SSO_CONFIG = {
    enabled: process.env.SSO_ENABLED === 'true' || true,
    secret: process.env.SSO_SECRET || 'your-sso-shared-secret-change-this',
    tokenExpiry: 5 * 60 * 1000,  // Token有效期（毫秒），默认5分钟
    autoCreateUser: true,         // 是否自动创建不存在的用户
    defaultRole: 0,               // 新用户默认角色（0=玩家, 1=经理, 2=管理员）
};
```

**重要**：`secret` 必须与论坛端保持一致，建议使用 32 位以上的随机字符串。

### 环境变量

可通过环境变量覆盖默认配置：

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SSO_ENABLED` | 是否启用SSO | `true` |
| `SSO_SECRET` | JWT签名密钥（必须与论坛一致） | `your-sso-shared-secret-change-this` |

## 论坛端实现

### 1. 生成 JWT Token

当用户点击"进入TAOS"按钮时，论坛需要生成一个 JWT Token：

```javascript
const jwt = require('jsonwebtoken');

const SSO_SECRET = 'your-sso-shared-secret-change-this'; // 必须与TAOS一致

function generateSSOToken(user) {
    const payload = {
        forum_user_id: user.id,           // 必填：论坛用户ID
        username: user.username,           // 可选：用户名（用于自动创建账号）
        display_name: user.displayName,    // 可选：显示名称
        email: user.email,                 // 可选：邮箱
        timestamp: Date.now(),             // 必填：时间戳（防重放）
        redirect: '/dashboard.html'        // 可选：登录后跳转页面
    };

    return jwt.sign(payload, SSO_SECRET, { expiresIn: '5m' });
}
```

### 2. 跳转到 TAOS

生成 Token 后，将用户重定向到 TAOS：

```javascript
const token = generateSSOToken(currentUser);
const taosUrl = 'https://your-taos-domain.com'; //目前为tr.kaigua.vip
window.location.href = `${taosUrl}/auth/sso?token=${token}`;
```

### Token Payload 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `forum_user_id` | string/number | 是 | 论坛用户唯一ID，用于关联TAOS账号 |
| `username` | string | 否 | 用户名，自动创建账号时使用 |
| `display_name` | string | 否 | 显示名称，自动创建账号时使用 |
| `email` | string | 否 | 邮箱地址 |
| `timestamp` | number | 是 | 生成时间戳（毫秒），用于防止重放攻击 |
| `redirect` | string | 否 | 登录成功后跳转的页面，默认 `/dashboard.html` |

## 用户账号关联机制

TAOS 会按以下顺序尝试关联用户：

1. **通过 forum_id 查找**：如果之前已经登录过，会记录 `forum_id` 与 TAOS 用户的关联
2. **通过用户名/邮箱匹配**：如果找到相同用户名或邮箱的 TAOS 账号，自动关联
3. **自动创建新账号**：如果 `autoCreateUser` 为 true，自动创建新 TAOS 账号

## 示例代码

### PHP 实现

```php
<?php
require 'vendor/autoload.php';
use Firebase\JWT\JWT;

$SSO_SECRET = 'your-sso-shared-secret-change-this';

function generateSSOToken($user) {
    global $SSO_SECRET;

    $payload = [
        'forum_user_id' => $user['id'],
        'username' => $user['username'],
        'display_name' => $user['display_name'],
        'email' => $user['email'],
        'timestamp' => time() * 1000,
        'redirect' => '/dashboard.html'
    ];

    return JWT::encode($payload, $SSO_SECRET, 'HS256');
}

// 使用示例
$currentUser = getCurrentUser(); // 获取当前登录用户
$token = generateSSOToken($currentUser);
$taosUrl = 'https://your-taos-domain.com';

header("Location: {$taosUrl}/auth/sso?token={$token}");
exit;
```

### Python 实现

```python
import jwt
import time

SSO_SECRET = 'your-sso-shared-secret-change-this'

def generate_sso_token(user):
    payload = {
        'forum_user_id': user['id'],
        'username': user['username'],
        'display_name': user.get('display_name', user['username']),
        'email': user.get('email', ''),
        'timestamp': int(time.time() * 1000),
        'redirect': '/dashboard.html'
    }

    return jwt.encode(payload, SSO_SECRET, algorithm='HS256')

# Flask 示例
from flask import redirect

@app.route('/goto-taos')
def goto_taos():
    user = get_current_user()
    token = generate_sso_token(user)
    taos_url = 'https://your-taos-domain.com'
    return redirect(f'{taos_url}/auth/sso?token={token}')
```

### Node.js 实现

```javascript
const jwt = require('jsonwebtoken');

const SSO_SECRET = 'your-sso-shared-secret-change-this';

function generateSSOToken(user) {
    const payload = {
        forum_user_id: user.id,
        username: user.username,
        display_name: user.displayName || user.username,
        email: user.email || '',
        timestamp: Date.now(),
        redirect: '/dashboard.html'
    };

    return jwt.sign(payload, SSO_SECRET, { expiresIn: '5m' });
}

// Express 示例
app.get('/goto-taos', (req, res) => {
    const user = req.user; // 假设已经有登录用户
    const token = generateSSOToken(user);
    const taosUrl = 'https://your-taos-domain.com';
    res.redirect(`${taosUrl}/auth/sso?token=${token}`);
});
```

## API 端点

### GET /auth/sso

SSO 登录入口

**参数**：
- `token` (string, 必填): 论坛生成的 JWT Token

**响应**：
- 成功：302 重定向到 `{redirect}?sso_token={taos_token}&sso_uid={user_id}&sso_role={role}`
- 失败：返回错误信息

**错误码**：
- `403`: SSO未启用
- `400`: 缺少token参数 / Token已过期 / Token缺少forum_user_id
- `401`: Token验证失败
- `404`: 用户不存在且未启用自动创建

### GET /api/sso/status

检查 SSO 状态

**响应**：
```json
{
    "enabled": true,
    "autoCreateUser": true
}
```

## 安全注意事项

1. **密钥安全**：`SSO_SECRET` 必须保密，不要提交到代码仓库
2. **HTTPS**：生产环境必须使用 HTTPS
3. **Token 有效期**：默认 5 分钟，防止 Token 被截获后重放
4. **时间戳验证**：TAOS 会验证时间戳，确保 Token 在有效期内
5. **一次性使用**：建议论坛每次点击都生成新 Token

## 故障排查

### Token 验证失败

1. 检查两端 `SSO_SECRET` 是否一致
2. 检查服务器时间是否同步
3. 检查 Token 是否过期

### 用户无法自动创建

1. 检查 `autoCreateUser` 是否为 `true`
2. 检查 Token 中是否包含 `username` 字段
3. 检查用户名是否已被占用

### 关联到错误的账号

1. 检查 `forum_user_id` 是否正确
2. 检查是否有重复的用户名或邮箱
