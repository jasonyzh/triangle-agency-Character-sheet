# 三角机构角色卡管理系统

基于 Node.js + Express + SQLite 构建的 TRPG 角色卡管理系统，支持多用户、权限管理、角色卡分享等功能。

- 作者：ska，残光

## 功能特性

### 安全与认证
- JWT Token 认证（24小时有效期）
- bcrypt 密码加密存储
- 三级角色权限系统：玩家 / 经理 / 超级管理员

### 用户管理
- 用户注册/登录
- 可选邮箱验证注册（需配置SMTP）
- 超管可管理所有用户

### 角色卡功能
- 创建/编辑/删除角色卡
- 异常能力与关系网槽位限制（初始各3个，经理可解锁更多）
- JSON导出/导入角色卡数据
- 角色卡分享（支持密码保护和过期时间）

### 授权系统
- 玩家可生成授权码给经理
- 经理认领授权后可查看和编辑玩家角色卡
- 经理可管理已授权角色的槽位数量

## 快速开始

### 环境要求
- [Node.js](https://nodejs.org/) v18 或更高版本
- npm 包管理器

### 安装步骤

1. **克隆或下载项目**
   ```bash
   git clone https://github.com/your-repo/triangle-agency-Character-sheet.git
   cd triangle-agency-Character-sheet
   ```

2. **安装依赖**
   ```bash
   npm install
   ```

   > 如果 sqlite3 安装失败，可尝试使用国内镜像：
   > ```bash
   > npm install sqlite3 --registry=https://registry.npmmirror.com --sqlite3_binary_host_mirror=https://npmmirror.com/mirrors/sqlite3/
   > ```

3. **启动服务器**
   ```bash
   npm start
   ```
   或
   ```bash
   node server.js
   ```

4. **访问系统**

   打开浏览器访问：`http://localhost:3333`

## 默认账号

| 账号 | 密码 | 角色 |
|------|------|------|
| admin | admin | 超级管理员 |
| 111 | 111 | 测试玩家 |

> **重要**：生产环境请务必修改默认密码！

## 角色权限说明

| 角色 | 权限 |
|------|------|
| 玩家 (0) | 管理自己的角色卡，生成授权码 |
| 经理 (1) | 玩家权限 + 管理已授权角色卡、调整槽位 |
| 超级管理员 (2) | 所有权限 + 用户管理、系统配置 |

## 配置说明

### SMTP邮箱配置（可选）

如需启用邮箱验证注册，请在管理后台配置SMTP：

1. 以超级管理员登录
2. 进入管理台 → 系统设置
3. 配置SMTP服务器信息：
   - SMTP主机
   - SMTP端口（通常 587 或 465）
   - SMTP用户名
   - SMTP密码
   - 发件人地址

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| JWT_SECRET | JWT签名密钥 | triangle-agency-secret-key-change-in-production |

> **生产环境**请设置自定义的 JWT_SECRET：
> ```bash
> JWT_SECRET=your-secret-key node server.js
> ```

## 数据存储

所有数据存储在 `data/` 目录下：
- `database.db` - SQLite数据库文件
- `anoms.json` - 异常能力选项配置
- `realities.json` - 现实锚点选项配置
- `functions.json` - 功能部门选项配置
- `bonuses.json` - 加成选项配置
- `email-template.html` - 自定义邮件模板（可选）

### 重置数据库

如需重置数据库（清除所有数据）：
```bash
rm data/database.db
node server.js
```

## 项目结构

```
├── server.js           # 后端服务主文件
├── package.json        # 项目配置和依赖
├── data/               # 数据目录
│   ├── database.db     # SQLite数据库
│   └── *.json          # 配置文件
└── public/             # 前端静态文件
    ├── login.html      # 登录页
    ├── dashboard.html  # 档案页（角色卡列表）
    ├── sheet.html      # 角色卡编辑页
    ├── manager.html    # 经理控制台
    ├── monitor.html    # 管理员监控台
    └── share.html      # 分享查看页
```

## 依赖说明

| 包名 | 用途 |
|------|------|
| express | Web框架 |
| body-parser | 请求体解析 |
| sqlite3 | SQLite数据库 |
| bcrypt | 密码加密 |
| jsonwebtoken | JWT认证 |
| nodemailer | 邮件发送 |
| uuid | 生成唯一ID |

## 更新日志

### v1.0.0
- 基础角色卡管理功能
- JWT认证和bcrypt密码加密
- 三级角色权限系统
- 角色卡授权与分享功能
- 异常能力/关系网槽位限制系统
- JSON导出/导入功能
- SMTP邮箱验证注册（可选）

## 许可证

MIT License
