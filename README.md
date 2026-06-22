# FreeHub

FreeHub 是一个自托管的社区平台，集成了用户系统、内容管理、在线 IDE、子域名共享和网站代理服务。

---

## 🚀 项目结构

```
FreeHub/
├── app.py                    # 主应用入口
├── bps/                      # 蓝图模块
│   ├── users.py             # 用户功能（注册/登录/帖子/文章/私信/悬赏等）
│   ├── admins.py            # 管理员功能
│   ├── superadmins.py       # 超级管理员功能
│   ├── owners.py            # 所有者功能
│   └── api.py               # 公共 API
├── utils/                    # 工具模块
│   ├── database_creator.py  # 数据库模型定义
│   ├── password_checker.py  # Argon2 密码哈希
│   ├── pbkdf2_security.py   # PBKDF2 安全参数
│   ├── email_sender.py      # SMTP 邮件发送
│   ├── file_scanner.py      # 文件扫描（病毒/类型检测）
│   ├── content_filter.py    # XSS 过滤与内容净化
│   ├── captcha_maker.py     # 图形验证码生成
│   └── utils.py             # 通用工具（CSRF/速率限制/URL检测等）
├── share/                    # Share 服务（子域名代理/端口转发）
│   ├── app.py
│   └── restart.sh
├── ide/                      # IDE 服务（在线编程环境）
│   ├── app.py
│   └── restart.sh
├── static/                   # 静态资源
├── templates/                # Jinja2 模板
├── uploads/                  # 用户上传文件
└── restart.sh                # 主服务重启脚本
```

---

## 🛠️ 技术栈

| 组件 | 技术 |
|:---|:---|
| 后端框架 | Flask + Flask-SQLAlchemy + Flask-Login |
| 数据库 | SQLite（可迁移至 PostgreSQL） |
| 密码安全 | Argon2 + PBKDF2 |
| 容器化 | Docker SDK（IDE 隔离执行） |
| 实时通信 | Flask-SocketIO（WebSocket 终端） |
| 前端 | Jinja2 + 自定义 CSS/JS |
| 安全 | CSP + CSRF 保护 + XSS 过滤 |

---

## ✨ 主要功能

### 👤 用户系统

- 主账户注册 / 登录（邮箱验证）
- 子账户（UID）多开支持
- 邮箱恢复（假邮箱自救）
- 积分系统（每日签到、分配、转账）
- 个人资料与隐私设置

### 📝 内容社区

- **帖子**：发布、编辑、删除、浏览量统计
- **文章**：富文本内容、评论系统
- **点赞 / 收藏**：帖子与文章互动
- **关注系统**：用户关系网络
- **私信**：好友私聊、系统通知

### 💰 悬赏接单系统（赏金池模式）

- 发布悬赏（四六开赏金池）
- 上传作品（按顺序获得动态池奖励）
- 悬赏者查看作品（支付查看费）
- 选择成交者（获得静态池 + 剩余动态池）
- 无人成交处理（退款或分配）

### 📁 文件仓库

- 文件上传 / 下载（支持图片预览）
- 公开 / 私密文件切换
- 病毒扫描（ClamAV 集成）
- 文件类型检测（含中文字体 HZK 识别）

### 🖥️ IDE 服务（端口 8001）

- Docker 容器隔离执行环境
- 支持语言：Python、C/C++、Java、JavaScript、Go、Rust、Shell
- 文件管理（创建 / 编辑 / 删除 / 重命名）
- WebSocket 终端（PTY 伪终端）
- 与主站 SSO 单点登录

### 🌐 Share 服务（端口 8002）

- 子域名注册与代理（server / iframe / redirect 模式）
- SSRF 防护（内网 IP / 高危端口拦截）
- 端口转发（IDE 容器端口映射）
- 网站举报与自动封禁（累计 3 次举报）
- 访问统计与点赞

---

## 🔧 安装与部署

### 前置要求

- Python 3.10+
- Docker（IDE 服务需要）
- ClamAV（可选，病毒扫描）
- Nginx（反向代理 + SSL 证书）

### 克隆仓库

```bash
git clone https://github.com/Zhou-39/website.git
cd FreeHub
```

### 安装依赖

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 环境变量（`.env`）

```env
EMAIL_BOX=your-email@qq.com
EMAIL_PASSWORD=your-smtp-authorization-code
TO_EMAIL=admin@example.com
SSO_SHARED_SECRET=your-sso-secret
```

### 数据库初始化

```bash
flask shell
>>> from app import db, app
>>> with app.app_context():
...     db.create_all()
>>> exit()
```

### 启动服务

**主服务（端口 443）**

```bash
python app.py  # 开发模式
# 或使用 Gunicorn
gunicorn --worker-class gthread --workers 1 --threads 2 --bind 127.0.0.1:8000 app:app
```

**IDE 服务（端口 8001）**

```bash
cd ide
python app.py
```

**Share 服务（端口 8002）**

```bash
cd share
python app.py
```

### Nginx 配置示例

```nginx
# 主站
server {
    listen 443 ssl http2;
    server_name free-hub.cn;
    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}

# IDE
server {
    listen 443 ssl http2;
    server_name ide.free-hub.cn;
    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Share
server {
    listen 443 ssl http2;
    server_name share.free-hub.cn;
    location / {
        proxy_pass http://127.0.0.1:8002;
    }
}
```

---

## 🔒 安全特性

| 特性 | 说明 |
|:---|:---|
| CSP 安全头 | 防止 XSS 注入 |
| CSRF 令牌 | 所有表单提交验证 |
| PBKDF2 盐值 | 每个用户独立迭代参数 |
| XSS 过滤 | `bleach` 净化用户输入 |
| 文件扫描 | ClamAV 病毒检测 + 文件类型验证 |
| SSRF 防护 | 拦截内网 IP 和高危端口 |

---

## 📊 数据库模型

| 表名 | 用途 |
|:---|:---|
| `IDs` | 主账户（真实身份） |
| `UIDs` | 子账户（匿名身份） |
| `Posts` / `Articles` | 帖子与文章 |
| `Comments` | 评论 |
| `Likes` / `Favorites` | 点赞与收藏 |
| `Follows` | 关注关系 |
| `Messages` / `Conversations` | 私信与会话 |
| `Uploads` | 文件仓库 |
| `Reports` / `ReportReasons` | 举报系统 |
| `BountyTasks` / `BountyUploads` | 悬赏系统 |
| `PointsHistory` / `PointsTransfers` | 积分历史与转账 |
| `Friends` / `FriendRequests` | 好友系统 |
| `BlockList` | 黑名单 |
| `Thanks` | 致谢列表 |

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

本项目采用 **AGPL-3.0** 许可证。详见 [LICENSE](LICENSE) 文件。

> 本项目为个人学习与自用项目，部分功能可能不够完善，欢迎提出改进建议。
---
