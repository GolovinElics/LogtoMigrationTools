# Logto 用户迁移脚本（Auth0 到 Logto）

## 功能介绍
这是一个用于将 Auth0 用户数据迁移到 Logto 的 TypeScript 脚本。主要功能包括：
- 从 JSON 文件读取 待迁移的 Auth0 用户数据
- 自动处理 Logto API 认证
- 支持分批获取现有 Logto 用户数据，自动过滤已迁移用户
- 迁移过程中的错误处理和重试机制，迁移日志记录

## 项目结构
```plaintext
auth0tologto/
├── migration.ts              # 主迁移脚本
├── auth0-users.json          # Auth0 用户数据文件
├── .env.template             # 环境配置文件模板
├── package.json              # 项目依赖
├── package-lock.json         # 依赖版本锁定文件
├── tsconfig.json             # TypeScript 配置
└── logs/                     # 日志目录（自动创建）
   ├── migration.log          # 迁移过程日志
   ├── migration-errors.log   # 错误日志
   └── success-users.log      # 成功迁移用户记录
```
## 安装和配置

1. 克隆项目并安装依赖：
   ```bash
   git clone <repository-url>
   cd auth0tologto
   npm install node-fetch @types/node typescript ts-node dotenv zod
   ```

2. 或者使用 package.json 安装（推荐）：
   ```bash
   git clone <repository-url>
   cd auth0tologto
   npm install
   ```

   package.json 依赖配置参考：
   ```json
   {
     "dependencies": {
       "node-fetch": "^2.6.7",
       "dotenv": "^16.0.3",
       "zod": "^3.22.4"
     },
     "devDependencies": {
       "@types/node": "^18.11.18",
       "@types/node-fetch": "^2.6.2",
       "typescript": "^5.0.0",
       "ts-node": "^10.9.1"
     }
   }
   ```

2. 配置环境变量，参照 `.env.template` 创建 `.env` 文件：
   ```env
   # Logto 租户配置
   LOGTO_TENANT_ID=your_tenant_id
   # M2M 应用凭证
   LOGTO_CLIENT_ID=your_client_id
   LOGTO_CLIENT_SECRET=your_client_secret
   # 迁移配置
   AUTH0_USERS_FILE=./auth0-users.json
   MIGRATION_DELAY=1000
   # 初始 Access Token (可选，如果不设置会自动获取)
   INITIAL_ACCESS_TOKEN=
   ```

3. 准备 Auth0 用户数据，创建 `auth0-users.json` 文件：
    ```json
    [
        {
            "created_at": "2025-02-18T13:33:57.835Z",
            "email": "q12345@vip.qq.com",
            "email_verified": true,
            "identities": [
                {
                    "connection": "Username-Password-Authentication",
                    "provider": "auth0",
                    "user_id": "67b4dsgss54fgds6v1b",
                    "isSocial": false
                }
            ],
            "name": "Qyt",
            "nickname": "Qyt",
            "picture": "https://xxxxxxxxxxxxx.com",
            "updated_at": "2025-02-19T07:16:01.790Z",
            "user_id": "auth0|67b4dsgss54fgds6v1b",
            "username": "qj",
            "last_password_reset": "2025-02-19T07:14:49.336Z",
            "last_ip": "115.222.333.339",
            "last_login": "2025-02-19T07:16:01.790Z",
            "logins_count": 3,
            "blocked_for": [],
            "guardian_authenticators": [],
            "passkeys": []
        }
    ]
    ```

## 配置项说明

| 配置项 | 必填 | 说明 | 示例 |
|--------|------|------|------|
| LOGTO_TENANT_ID | 是 | Logto 租户 ID | AAAccc |
| LOGTO_CLIENT_ID | 是 | M2M 应用的 Client ID | 67b43243534gfg4665656v1b |
| LOGTO_CLIENT_SECRET | 是 | M2M 应用的 Client Secret | XkCsdfdg46435fdhdfh4dfgZ... |
| AUTH0_USERS_FILE | 是 | Auth0 用户数据文件路径 | ./auth0-users.json |
| MIGRATION_DELAY | 是 | 迁移用户间的延迟(毫秒) | 1000 |

## 使用方法

1. 运行迁移脚本：
   ```bash
   npx ts-node migration.ts
   ```

2. 查看迁移日志：
   - `logs/migration.log`: 完整迁移过程记录
   - `logs/migration-errors.log`: 迁移失败的用户记录
   - `logs/success-users.log`: 成功迁移的用户记录

## 注意事项

1. Logto M2M 应用配置：
   - 需要在 Logto 控制台创建 M2M 应用
   - 确保应用有足够的权限进行用户管理，已配置关联 Role 授予了 all 权限
   - 获取并配置正确的 Client ID 和 Secret
   - 转码成为Base64格式，参考命令：echo -n "dfgfdh44dfs435345:GJDJG565894645HBFB945635446" | base64

2. 数据迁移：
   - 建议先使用小批量数据测试
   - 迁移过程会自动跳过已存在的用户，基于以下规则判断：
     * 邮箱地址匹配（primaryEmail）
     * 手机号匹配（primaryPhone，如果存在，一般auth0用户数据没有）
   - 支持断点续传（通过日志记录）
   - 分页查询配置：
     * 默认每页大小为 20
     * 如遇分页问题，请检查日志中的 "总用户数" 和 "需要查询页数" 是否匹配
     * 确保 API 返回的分页数据结构正确

3. 错误处理：
   - Token 过期自动刷新
   - 请求失败自动重试（最多 3 次）
   - 详细的错误日志记录，并输出到日志文件
   - 常见错误排查：
     * 检查 migration.log 中的 API 响应状态
     * 验证 access token 是否正确
     * 确认网络连接是否正常

## 开发相关

- TypeScript 版本: 5.0.0+
- 主要依赖:
  - node-fetch: API 请求
  - dotenv: 环境变量管理
  - zod: 配置验证

## 参考文档 - Logto

- [Interact with Management API](https://docs.logto.io/integrate-logto/interact-with-management-api#create-an-m2m-app)
- [Logto API 文档](https://openapi.logto.io/operation/operation-updateuserprofile)

## 运行效果
```log
golovin@Golovins-MacBook-Pro auth0tologto % npx ts-node migration.ts
总用户数: 5
正在获取现有 Logto 用户列表...
Token 不存在或已过期，正在刷新...
成功获取新 token, 过期时间: 3600 秒
新 token: eyJhbGciOiJFUzM4NCIsInR5cCI6ImF0K2p3dCIsImtpZCI6IloxLTJrNWgyTVp54653456gddgdfgYRmZDanNiZHBNY3Z2b0EifQ.eyJqdGkiOiJQSnhJcnJ6eFZ4535fgdsf454FGSGGasddfsg3453gs456453CJpYXQiOjE3NDAwMzkxNDcsImV4cCI6MTc0MDA0Mjc0Nywic2NvcGUiOiJhbGwiLCJjbGllbnRfaWQiOiI2bHQxNTlqd2w3MWQ3b3c4NGQ2bzUiLCJpc3MiOiJodHRwczovLzQ2MGNjYy5sb2d0by5hcHAvb2lkYyIsImF1ZCI6Imh0dHBdfgsd345345mxvZ3RvLmFwcC9hcGkifQ.6qK0LqWGHprPjdeEpC8kQNChuFjHJzH1fKOTMjB1NqXC9w1z75446fgfhdW1vWy002kt4plxtJ5473fghgfD6N05-TsTHmGF_c4qQ0BwO
Logto 总用户数: 5
每页大小: 2
需要查询 3 页数据
正在获取第 2/3 页数据...
正在获取第 3/3 页数据...
成功获取所有 5 个用户数据
已在 Logto 中存在的用户数: 5
其中邮箱用户: 5, 手机号用户: 3

待迁移用户数: 0 (已过滤 5 个已迁移用户)
使用现有有效 token

=== 迁移统计 ===
开始时间: 2025-02-20T08:12:24.557Z
结束时间: 2025-02-20T08:12:30.362Z
总用户数: 5
已迁移用户数: 5
本次待迁移数: 0
本次成功数: 0
本次失败数: 0
本次成功率: 100.00%
总体完成率: 100.00%
================

golovin@Golovins-MacBook-Pro auth0tologto % 
```

## 许可证

MIT License

