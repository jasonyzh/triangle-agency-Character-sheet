# 三角机构角色卡管理系统 - API 开发文档

## 基础信息

- **基础URL**: `http://localhost:3333`
- **认证方式**: JWT Token（Bearer Token）
- **请求格式**: JSON
- **响应格式**: JSON

## 认证说明

大部分 API 需要在请求头中携带 JWT Token：

```
Authorization: Bearer <token>
```

### 权限等级

| 等级 | 角色 | 说明 |
|------|------|------|
| 0 | 玩家 | 基础权限 |
| 1 | 经理 | 管理权限 |
| 2 | 超级管理员 | 全部权限 |

---

## 公开接口

### 获取配置选项

```
GET /api/options
```

**响应示例**:
```json
{
  "anoms": ["异常A", "异常B"],
  "realities": ["现实锚点A"],
  "functions": ["功能部门A"],
  "bonuses": ["加成A"]
}
```

### 用户登录

```
POST /api/login
```

**请求体**:
```json
{
  "username": "用户名",
  "password": "密码"
}
```

**响应示例**:
```json
{
  "success": true,
  "token": "jwt_token_here",
  "user": {
    "id": 1,
    "username": "admin",
    "name": "管理员",
    "role": 2
  }
}
```

### 获取注册状态

```
GET /api/register/status
```

**响应示例**:
```json
{
  "enabled": true,
  "requireEmail": false
}
```

### 发送验证码（邮箱注册）

```
POST /api/register/send-code
```

**请求体**:
```json
{
  "email": "user@example.com"
}
```

### 验证并注册

```
POST /api/register/verify
```

**请求体**:
```json
{
  "email": "user@example.com",
  "code": "123456",
  "username": "用户名",
  "password": "密码",
  "name": "显示名称"
}
```

---

## 角色卡接口

### 获取角色卡列表

```
GET /api/characters
```

**查询参数**:
- `userId`: 用户ID（可选）

**响应示例**:
```json
[
  {
    "id": "uuid",
    "name": "角色名",
    "pAnom": "异常类型",
    "pFunc": "功能部门"
  }
]
```

### 获取角色卡详情

```
GET /api/character/:id
```

**需要认证**: 可选（认证后可访问授权角色）

**响应**: 完整角色卡数据 JSON

### 创建角色卡

```
POST /api/character
```

**需要认证**: 是

**请求体**:
```json
{
  "data": { /* 角色卡数据 */ }
}
```

### 更新角色卡

```
PUT /api/character/:id
```

**需要认证**: 是

**请求体**:
```json
{
  "data": { /* 角色卡数据 */ }
}
```

### 删除角色卡

```
DELETE /api/character/:id
```

**需要认证**: 是

---

## 角色卡分享接口

### 创建分享链接

```
POST /api/character/:id/share
```

**需要认证**: 是

**请求体**:
```json
{
  "password": "访问密码（可选）",
  "expireDays": 7
}
```

**响应示例**:
```json
{
  "success": true,
  "shareCode": "abc123",
  "expiresAt": 1702483200000
}
```

### 获取分享状态

```
GET /api/character/:id/share
```

**需要认证**: 是

**响应示例**:
```json
{
  "exists": true,
  "shareCode": "abc123",
  "hasPassword": true,
  "expiresAt": 1702483200000
}
```

### 删除分享

```
DELETE /api/character/:id/share
```

**需要认证**: 是

### 检查分享链接状态

```
GET /api/share/:code/status
```

**响应示例**:
```json
{
  "exists": true,
  "needPassword": true
}
```

### 访问分享内容

```
POST /api/share/:code
```

**请求体**:
```json
{
  "password": "访问密码"
}
```

**响应示例**:
```json
{
  "success": true,
  "data": { /* 角色卡数据 */ }
}
```

---

## 授权系统接口

### 生成授权码

```
POST /api/character/:id/auth-code
```

**需要认证**: 是

**响应示例**:
```json
{
  "code": "AUTH-XXXX-XXXX"
}
```

### 认领授权码

```
POST /api/auth/claim
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "code": "AUTH-XXXX-XXXX"
}
```

### 获取角色授权列表

```
GET /api/character/:id/authorizations
```

**需要认证**: 是

### 删除授权

```
DELETE /api/auth/:authId
```

**需要认证**: 是

---

## 槽位管理接口

### 获取槽位限制

```
GET /api/character/:id/slots
```

**需要认证**: 是

**响应示例**:
```json
{
  "anomSlots": 3,
  "realSlots": 3
}
```

### 更新槽位限制

```
PUT /api/character/:id/slots
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "anomSlots": 5,
  "realSlots": 5
}
```

---

## 嘉奖/申诫接口

### 获取记录历史

```
GET /api/character/:id/records
```

**需要认证**: 是

### 添加嘉奖

```
POST /api/character/:id/reward
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "count": 1,
  "reason": "表现优秀"
}
```

**参数说明**:
- `count`: 数量，支持负数（范围 -99 到 99，不能为 0）
- `reason`: 原因描述

### 添加申诫

```
POST /api/character/:id/reprimand
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "count": 1,
  "reason": "违规行为"
}
```

**参数说明**:
- `count`: 数量，支持负数（范围 -99 到 99，不能为 0）
- `reason`: 原因描述

### 删除记录

```
DELETE /api/character/:id/record/:recordId
```

**需要认证**: 是（经理权限）

---

## 经理接口

### 获取已授权角色卡列表

```
GET /api/manager/characters
```

**需要认证**: 是（经理权限）

### 创建外勤任务

```
POST /api/manager/mission
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "name": "任务名称",
  "description": "任务描述",
  "missionType": "containment"
}
```

**任务类型**:
- `containment`: 收容任务
- `sweep`: 清扫任务
- `disruption`: 市场扰乱任务
- `other`: 其他任务

### 获取任务列表

```
GET /api/manager/missions
```

**需要认证**: 是（经理权限）

**查询参数**:
- `status`: `active` 或 `archived`

### 更新任务

```
PUT /api/manager/mission/:id
```

**需要认证**: 是（经理权限）

### 删除任务

```
DELETE /api/manager/mission/:id
```

**需要认证**: 是（经理权限）

### 添加任务成员

```
POST /api/manager/mission/:id/member
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "characterId": "角色卡ID"
}
```

### 移除任务成员

```
DELETE /api/manager/mission/:id/member/:charId
```

**需要认证**: 是（经理权限）

### 更新成员状态

```
PUT /api/manager/mission/:id/member/:charId/status
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "status": "active"
}
```

### 归档任务

```
POST /api/manager/mission/:id/archive
```

**需要认证**: 是（经理权限）

---

## 任务报告接口

### 获取任务报告列表

```
GET /api/manager/mission/:id/reports
```

**需要认证**: 是（经理权限）

### 更新报告

```
PUT /api/manager/mission/:id/report/:reportId
```

**需要认证**: 是（经理权限）

### 发送报告

```
POST /api/manager/mission/:id/report/:reportId/send
```

**需要认证**: 是（经理权限）

### 发送报告（带奖惩）

```
POST /api/manager/mission/:id/report/:reportId/send-with-rewards
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "rewards": [
    {
      "characterId": "角色ID",
      "rewardChange": 1,
      "watchChange": 0,
      "isMvp": true
    }
  ]
}
```

### 定稿报告

```
POST /api/manager/mission/:id/report/:reportId/finalize
```

**需要认证**: 是（经理权限）

---

## 角色卡邮箱接口

### 获取收件箱

```
GET /api/character/:id/messages
```

**需要认证**: 是

### 获取已发邮件

```
GET /api/character/:id/sent-messages
```

**需要认证**: 是

### 获取可发送对象

```
GET /api/character/:charId/send-targets
```

**需要认证**: 是

### 发送邮件

```
POST /api/character/:charId/send-mail
```

**需要认证**: 是

**请求体**:
```json
{
  "targetType": "manager",
  "targetId": 1,
  "subject": "主题",
  "content": "内容"
}
```

### 发送收容物

```
POST /api/character/:charId/send-containment
```

**需要认证**: 是

**请求体**:
```json
{
  "targetId": 1,
  "itemName": "收容物名称",
  "itemDescription": "描述"
}
```

### 提交任务报告

```
POST /api/character/:charId/send-report
```

**需要认证**: 是

**请求体**:
```json
{
  "content": "报告内容"
}
```

### 标记消息已读

```
PUT /api/character/:charId/message/:msgId/read
```

**需要认证**: 是

---

## 经理收件箱接口

### 获取收件箱

```
GET /api/manager/inbox
```

**需要认证**: 是（经理权限）

### 获取未读数量

```
GET /api/manager/inbox/unread-count
```

**需要认证**: 是（经理权限）

### 获取消息详情

```
GET /api/manager/inbox/:msgId
```

**需要认证**: 是（经理权限）

### 标记已读

```
PUT /api/manager/inbox/:msgId/read
```

**需要认证**: 是（经理权限）

### 删除消息

```
DELETE /api/manager/inbox/:msgId
```

**需要认证**: 是（经理权限）

---

## 高墙文件接口

### 获取文件列表

```
GET /api/documents/list
```

**需要认证**: 是

### 读取文件

```
GET /api/documents/read/:filename
```

**需要认证**: 是

### 获取角色可访问的高墙文件

```
GET /api/character/:id/highwall-files
```

**需要认证**: 是

### 检查A1权限

```
GET /api/character/:id/check-a1
```

**需要认证**: 是

---

## 文件授权接口（经理）

### 获取角色文件权限

```
GET /api/manager/character/:charId/permissions
```

**需要认证**: 是（经理权限）

### 更新角色文件权限

```
PUT /api/manager/character/:charId/permissions
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "permissions": ["file1.md", "file2.md"]
}
```

---

## 分部管理接口（超管）

### 创建分部

```
POST /api/admin/branch
```

**需要认证**: 是（超管权限）

**请求体**:
```json
{
  "name": "分部名称",
  "description": "描述"
}
```

### 获取分部列表

```
GET /api/admin/branches
```

**需要认证**: 是（经理权限）

### 获取分部详情

```
GET /api/admin/branch/:id
```

**需要认证**: 是（经理权限）

### 更新分部

```
PUT /api/admin/branch/:id
```

**需要认证**: 是（超管权限）

### 删除分部

```
DELETE /api/admin/branch/:id
```

**需要认证**: 是（超管权限）

### 添加分部经理

```
POST /api/admin/branch/:id/manager
```

**需要认证**: 是（超管权限）

**请求体**:
```json
{
  "managerId": 1
}
```

### 移除分部经理

```
DELETE /api/admin/branch/:id/manager/:managerId
```

**需要认证**: 是（超管权限）

---

## 用户管理接口（超管）

### 获取用户列表

```
GET /api/users
```

**需要认证**: 是（超管权限）

### 创建用户

```
POST /api/users
```

**需要认证**: 是（超管权限）

**请求体**:
```json
{
  "username": "用户名",
  "password": "密码",
  "name": "显示名称",
  "role": 0
}
```

### 更新用户

```
PUT /api/users/:id
```

**需要认证**: 是（超管权限）

### 删除用户

```
DELETE /api/users/:id
```

**需要认证**: 是（超管权限）

### 修改用户角色

```
PUT /api/admin/users/:id/role
```

**需要认证**: 是（超管权限）

**请求体**:
```json
{
  "role": 1
}
```

---

## 系统配置接口（超管）

### 获取系统配置

```
GET /api/admin/config
```

**需要认证**: 是（超管权限）

### 更新系统配置

```
PUT /api/admin/config
```

**需要认证**: 是（超管权限）

### 测试SMTP

```
POST /api/admin/test-smtp
```

**需要认证**: 是（超管权限）

### 切换消息系统

```
POST /api/admin/toggle-messaging
```

**需要认证**: 是（超管权限）

### 获取消息系统状态

```
GET /api/admin/messaging-status
```

**需要认证**: 是（超管权限）

### 获取监控数据

```
GET /api/admin/monitor
```

**需要认证**: 是（超管权限）

---

## 验证接口

### 验证Token

```
GET /api/verify-token
```

**需要认证**: 是

**响应示例**:
```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "admin",
    "role": 2
  }
}
```

---

## 角色任务信息接口

### 获取角色任务信息

```
GET /api/character/:charId/mission
```

**需要认证**: 是

**响应示例**:
```json
{
  "inMission": true,
  "missions": [
    {
      "missionId": "uuid",
      "missionName": "任务名称",
      "missionDescription": "任务描述",
      "missionType": "containment",
      "missionStatus": "active",
      "myStatus": "active",
      "creatorName": "经理名",
      "teammates": [
        {
          "characterId": "uuid",
          "characterName": "角色名",
          "status": "active",
          "isMe": false
        }
      ]
    }
  ],
  "managers": [
    {
      "id": 1,
      "name": "经理名"
    }
  ]
}
```

---

## 申领物商店接口（经理）

### 获取申领物列表

```
GET /api/manager/shop/items
```

**需要认证**: 是（经理权限）

**响应示例**:
```json
{
  "success": true,
  "items": [
    {
      "id": 1,
      "title": "物品名称",
      "description": "物品描述",
      "is_global": 0,
      "created_by": 1,
      "creator_name": "经理名",
      "canEdit": true,
      "prices": [
        {
          "id": 1,
          "price_name": "标准版",
          "price_cost": 2,
          "currency_type": "commendation",
          "usage_type": "permanent",
          "usage_count": 0
        }
      ]
    }
  ]
}
```

### 创建申领物

```
POST /api/manager/shop/items
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "title": "物品名称",
  "description": "物品描述",
  "isGlobal": false,
  "prices": [
    {
      "name": "标准版",
      "cost": 2,
      "currencyType": "commendation",
      "usageType": "permanent",
      "usageCount": 0
    }
  ]
}
```

**标价参数说明**:
- `currencyType`: 货币类型，`commendation`（嘉奖）或 `reprimand`（申诫）
- `usageType`: 使用类型
  - `permanent`: 永久物品
  - `consumable`: 一次性物品
  - `per_mission`: 每任务限次物品
- `usageCount`: 使用次数（仅 `per_mission` 类型有效）

### 更新申领物

```
PUT /api/manager/shop/items/:id
```

**需要认证**: 是（经理权限）

### 删除申领物

```
DELETE /api/manager/shop/items/:id
```

**需要认证**: 是（经理权限）

---

## 申领物商店接口（玩家）

### 获取可购买的申领物列表

```
GET /api/character/:charId/shop
```

**需要认证**: 是

**响应示例**:
```json
{
  "success": true,
  "items": [...],
  "availableCommendations": 5,
  "availableReprimands": 2
}
```

> 注：`availableReprimands` 仅在角色有申诫商店权限时返回

### 购买申领物

```
POST /api/character/:charId/shop/purchase
```

**需要认证**: 是

**请求体**:
```json
{
  "itemId": 1,
  "priceId": 1
}
```

**响应示例**:
```json
{
  "success": true,
  "message": "购买成功",
  "newItem": {
    "item": "物品名称",
    "pd": "物品描述",
    "eff": "",
    "usageType": "permanent",
    "usageRemaining": null
  }
}
```

**说明**:
- 购买时会自动在嘉奖/申诫历史记录中添加一条负数记录
- 记录格式：`商店购买「物品名」- 标价名`，数量为负数

---

## 申诫商店权限接口（经理）

### 切换申诫商店权限

```
PUT /api/manager/character/:charId/reprimand-shop-access
```

**需要认证**: 是（经理权限）

**请求体**:
```json
{
  "reprimandShopAccess": true
}
```

**响应示例**:
```json
{
  "success": true,
  "reprimandShopAccess": true
}
```

---

## 错误响应

所有接口在发生错误时返回以下格式：

```json
{
  "success": false,
  "message": "错误描述",
  "error": "详细错误信息（可选）"
}
```

### 常见HTTP状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 401 | 未认证或Token过期 |
| 403 | 权限不足 |
| 404 | 资源不存在 |
| 410 | 资源已过期（如分享链接） |
| 500 | 服务器内部错误 |
