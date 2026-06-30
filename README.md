# Triangle Agency

三角机构跑团管理平台。

## 功能

* **角色档案** — 创建、编辑、导出角色卡，支持异常/关系/物品卡片化管理
* **角色卡打印** — A4 排版打印视图，一键导出完整角色档案
* **分部系统** — 多部门隔离，新用户申请加入分部，管理员审批
* **任务管理** — 外勤任务创建、分配、归档，自动计算逸散端
* **任务面板** — 任务总览横排职员卡片，GM 实时查看角色异常/关系/物品/资质保证
* **天气 / 事件卡** — 44 张天气/事件骰子卡，GM 多选设置 + 递进展开，Socket 实时广播玩家端，画板悬浮按钮 + Win98 风格详情弹窗 + 故障闪烁特效
* **NPC 关系预设** — 经理预预设关系模板，角色卡片/任务详情一键赋予，直接写入角色关系网
* **画板系统** — GM 和玩家共享画布，拖拽摆放 NPC 和地图图片，实时同步，手机端触控适配
* **连线系统** — 地图节点虚线连接，玩家 NPC 关系连线（友善/敌对/中立/未知）
* **骰子系统** — 骰子剪影按钮（d4-d20 + d%），检定 6d4 统计3，结果广播全员
* **邮件系统** — GM 群发邮件给任务参与者，Socket.IO 实时通知收件人
* **申领物** — 物资申领商店，支持一次性/限制型物品
* **虹吸商店** — 特殊道具购买与管理，需解锁高墙文件 X2
* **高墙文件** — Markdown 格式的机密文档阅读器
* **COS 对象存储** — 腾讯云 COS 图库上传，系统设置开关切换，支持自定义域名/CDN
* **管理后台** — 用户管理、分部管理、入职审批、系统设置（注册/SMTP/COS）
* **经理台** — 角色审核、任务管理、申领物审批、异常能力模板、NPC 关系预设

## 技术栈

* **后端**: Express + better-sqlite3 + Socket.IO
* **前端**: 原生 HTML/CSS/JS（ES Modules 模块化）
* **开发工具**: Vite（开发服务器）+ ESLint + Prettier + nodemon
* **认证**: JWT + bcrypt
* **实时通信**: Socket.IO（画板同步、骰子广播、邮件通知、天气广播）
* **文件上传**: multer（图片素材库，支持本地/腾讯云 COS 双模式）
* **对象存储**: cos-nodejs-sdk-v5（腾讯云 COS，可选）

## 快速开始

    npm install
    npm start

服务启动在 `http://localhost:3333`。

首次启动自动创建数据库和默认管理员账户（`admin` / `admin123`）。

## 开发模式

    # 后端热重载
    npm run dev
    
    # 前端 + 后端同时启动（Vite 端口 30303，代理 API 到 3333）
    npm run dev:all
    
    # 代码检查
    npm run lint
    
    # 代码格式化
    npm run format

## 修改管理员账户

编辑 `db/init.js` 中的以下两行，然后删除 `data/database.db` 重新启动：

    const NEW_ADMIN_USERNAME = '你的用户名';
    const NEW_ADMIN_PASSWORD = '你的密码';

如果想保留现有数据，也可以在管理后台（admin.html）直接修改用户信息。

## 项目结构

    ├── server.js                # 入口（含 Socket.IO）
    ├── vite.config.js           # Vite 开发服务器配置
    ├── eslint.config.js         # ESLint v10 flat config
    ├── .prettierrc              # Prettier 配置
    ├── constants.js             # 常量配置
    ├── utils.js                 # 工具函数
    ├── cos.js                   # 腾讯云 COS 工具模块（上传/删除/URL构造）
    ├── db/init.js               # 数据库初始化与迁移（better-sqlite3 同步 API）
    ├── middleware/auth.js        # JWT 认证中间件
    ├── routes/                  # API 路由
    │   ├── auth.js              # 登录注册
    │   ├── admin.js             # 管理后台
    │   ├── branches.js          # 分部管理
    │   ├── characters.js        # 角色档案
    │   ├── records.js           # 角色记录
    │   ├── missions.js          # 外勤任务
    │   ├── items.js             # 申领物
    │   ├── siphon.js            # 虹吸商店
    │   ├── documents.js         # 高墙文件
    │   ├── messages.js          # 消息
    │   ├── mail.js              # 邮件（含 GM 群发）
    │   ├── boards.js            # 画板 + 地图连线 CRUD
    │   ├── image-library.js     # 图片素材库 + 文件夹管理
    │   ├── anomaly-templates.js # 异常能力模板
    │   ├── npc-templates.js     # NPC 关系预设模板
    │   ├── monitor.js           # 监控
    │   ├── manager-inbox.js     # 经理收件箱
    │   ├── options.js           # 下拉选项数据
    │   └── shares.js            # 分享
    ├── public/                  # 静态前端
    │   ├── login.html
    │   ├── register.html
    │   ├── dashboard.html       # 用户主页
    │   ├── manager.html         # 经理台
    │   ├── admin.html           # 管理后台
    │   ├── sheet.html           # 角色卡编辑（含画板 tab + 骰子栏）
    │   ├── print-sheet.html     # 角色卡打印页（A4 排版）
    │   ├── mission-panel.html   # 任务面板（三 tab：总览/画板/发邮件）
    │   ├── items.html           # 申领物商店
    │   ├── documents.html       # 高墙文件阅读器
    │   ├── monitor.html         # 监控页
    │   ├── css/
    │   ├── js/
    │   │   ├── common.js        # 通用工具函数（非模块页面使用）
    │   │   ├── board-core.js    # 画布引擎（拖拽/缩放/连线SVG）
    │   │   ├── common-modules/  # ES module 共享模块
    │   │   │   ├── auth.js      # 认证工具
    │   │   │   ├── ui.js        # UI 工具（toast、escapeHtml）
    │   │   │   ├── nav.js       # 导航工具（侧边栏、转场）
    │   │   │   └── index.js     # 统一导出
    │   │   ├── sheet/           # 角色卡模块（19 个文件）
    │   │   │   ├── init.js      # 入口（window 挂载 + 初始化）
    │   │   │   ├── state.js     # 共享状态对象 S
    │   │   │   ├── api.js       # API 调用
    │   │   │   ├── tabs.js      # 标签页切换
    │   │   │   ├── anomaly.js   # 异常能力
    │   │   │   ├── reality.js   # 关系网
    │   │   │   ├── items.js     # 申领物
    │   │   │   ├── dice.js      # 骰子系统
    │   │   │   ├── board.js     # 画板
    │   │   │   ├── mail.js      # 邮件系统
    │   │   │   └── ...
    │   │   ├── manager/         # 经理台模块（12 个文件）
    │   │   │   ├── init.js      # 入口
    │   │   │   ├── state.js     # 共享状态对象 S
    │   │   │   ├── characters.js# 角色管理
    │   │   │   ├── missions.js  # 任务管理
    │   │   │   ├── items.js     # 申领物管理
    │   │   │   ├── npc-templates.js # NPC 关系预设
    │   │   │   └── ...
    │   │   ├── sheet.js         # 原始文件（备份）
    │   │   ├── manager.js       # 原始文件（备份）
    │   │   └── ...
    │   └── ...
    └── data/                    # 运行时数据
        ├── database.db          # SQLite 数据库
        ├── uploads/             # 图片素材库
        ├── functions.json       # 职能选项
        ├── anoms.json           # 异常选项
        ├── realities.json       # 现实选项
        ├── bonuses.json          # 加值选项
        ├── tianqi.json           # 天气/事件卡数据（44 张）
        └── high-security/       # 高墙文档 (.md)

## 用户角色

| 角色  | 说明  |
| --- | --- |
| 玩家  | 创建角色、加入分部、查看档案、拖拽画板图片、投骰子、查看天气 |
| 经理  | 管理本分部角色、任务、申领物审批、画板管理、群发邮件、NPC 关系预设、天气设置 |
| 超级管理员 | 管理全部分部、用户、系统配置（注册/SMTP/COS） |

## 数据库表

| 表   | 说明  |
| --- | --- |
| `users` | 用户账户 |
| `characters` | 角色卡片（data 字段存 JSON） |
| `branches` | 分部信息 |
| `user_branches` | 用户-分部分配 |
| `field_missions` | 外勤任务（含天气 weather 字段） |
| `field_mission_members` | 任务成员 |
| `requisitions` | 申领物 |
| `siphon_products` | 虹吸商店商品 |
| `anomaly_templates` | 异常能力模板 |
| `npc_templates` | NPC 关系预设模板 |
| `image_library` | 图片素材库 |
| `mission_boards` | 任务画板 |
| `board_images` | 画板图片（经理/玩家坐标分离） |
| `board_connections` | 地图节点连线 |
| `player_npc_connections` | 玩家 NPC 关系连线 |
| `character_messages` | 角色消息/邮件 |
| `document_permissions` | 高墙文件权限 |

## 环境变量

| 变量  | 默认值 | 说明  |
| --- | --- | --- |
| `JWT_SECRET` | 内置密钥 | 生产环境务必修改 |
