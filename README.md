# Triangle Agency

三角机构跑团管理平台。

## 功能

- **角色档案** — 创建、编辑、导出角色卡，支持异常/关系/物品卡片化管理
- **分部系统** — 多部门隔离，新用户申请加入分部，管理员审批
- **任务管理** — 外勤任务创建、分配、归档，自动计算逸散端
- **申领物** — 物资申领商店，支持一次性/限制型物品
- **siphon商店** — 申诫消耗与管理
- **高墙文件** — Markdown 格式的机密文档阅读器
- **管理后台** — 用户管理、分部管理、入职审批
- **经理台** — 角色审核、任务管理、申领物审批

## 技术栈

- **后端**: Express + SQLite3
- **前端**: 原生 HTML/CSS/JS，无构建工具
- **认证**: JWT + bcrypt

## 快速开始

```bash
npm install
npm start
```

服务启动在 `http://localhost:3333`。

首次启动自动创建数据库和默认管理员账户（`jiuzhoulu` / `jiuzhoulu888`）。

## 修改管理员账户

编辑 `db/init.js` 中的以下两行，然后删除 `data/database.db` 重新启动：

```js
const NEW_ADMIN_USERNAME = '你的用户名';
const NEW_ADMIN_PASSWORD = '你的密码';
```

如果想保留现有数据，也可以在管理后台（admin.html）直接修改用户信息。

## 项目结构

```
├── server.js            # 入口
├── constants.js         # 常量配置
├── utils.js             # 工具函数
├── db/init.js           # 数据库初始化与迁移
├── middleware/auth.js   # JWT 认证中间件
├── routes/              # API 路由
│   ├── auth.js          # 登录注册
│   ├── admin.js         # 管理后台
│   ├── branches.js      # 分部管理
│   ├── characters.js    # 角色档案
│   ├── records.js       # 角色记录
│   ├── missions.js      # 外勤任务
│   ├── items.js         # 申领物
│   ├── siphon.js        # 虹吸商店
│   ├── documents.js     # 高墙文件
│   ├── messages.js      # 消息
│   ├── mail.js          # 邮件
│   ├── monitor.js       # 监控
│   ├── manager-inbox.js # 经理收件箱
│   ├── options.js       # 下拉选项数据
│   └── shares.js        # 分享
├── public/              # 静态前端
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html   # 用户主页
│   ├── manager.html     # 经理台
│   ├── admin.html       # 管理后台
│   ├── sheet.html       # 角色卡编辑
│   ├── items.html       # 申领物商店
│   ├── documents.html   # 高墙文件阅读器
│   ├── monitor.html     # 监控页
│   ├── css/
│   └── js/
└── data/                # 运行时数据
    ├── database.db      # SQLite 数据库
    ├── functions.json   # 职能选项
    ├── anoms.json       # 异常选项
    ├── realities.json   # 现实选项
    ├── bonuses.json     # 加值选项
    └── high-security/   # 高墙文档 (.md)
```

## 用户角色

| 角色 | 说明 |
|------|------|
| 玩家 | 创建角色、加入分部、查看档案 |
| 经理 | 管理本分部角色、任务、申领物审批 |
| 超级管理员 | 管理全部分部、用户、系统配置 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `JWT_SECRET` | 内置密钥 | 生产环境务必修改 |
