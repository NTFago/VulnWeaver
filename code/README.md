# VulnWeaver 代码工作区

本目录用于存放本系统的全部程序代码、配置、数据库迁移、自动化测试、部署文件和开发脚本。

开始开发前请先阅读根目录中的：

1. `AGENTS.md`
2. `DEVELOPMENT_STATUS.md`
3. `系统架构设计与技术选型.md`
4. `系统实现模块拆分.md`

## 当前开发基线

- Python 3.12 + uv
- Node.js 24 + pnpm
- Docker Compose 基础设施
- Dev Container 统一工具环境
- 国内依赖源：TUNA PyPI、TUNA Debian、npmmirror

默认源地址：

- Python：`https://pypi.tuna.tsinghua.edu.cn/simple`
- Debian：`https://mirrors.tuna.tsinghua.edu.cn/debian` 与 `debian-security`
- Node.js：`https://registry.npmmirror.com`

Docker 基础镜像的拉取由宿主机 Docker daemon 负责。项目不硬编码第三方镜像代理；如需加速，应在宿主机统一配置可信的 registry mirror。

复制 `.env.example` 为本地 `.env`，确认数据库密码和 Cookie/TLS 策略后启动完整产品：

```shell
docker compose up -d --build
```

打开 Web UI，页面会引导创建唯一的本地管理员账号。注册完成后可进入“设置”填写可选的复核模型连接。

仅搭建开发依赖时使用：

```shell
docker compose -f compose.yaml -f compose.dev.yaml up -d postgres redis
uv sync --frozen
pnpm install --frozen-lockfile
```

Compose 会先运行一次 `vulnweaver-migrate`，迁移成功后再以非 root、只读根文件系统启动
Dispatcher。当前公共后端包包括 `contracts`、`domain`、`persistence`、`artifact-store`、
`queue` 和 `worker`；具体分析 Worker 应复用 `worker` 包提供的租约、心跳、重试、结算与
优雅停止协议。

## 个人账号与登录

空数据库首次启动后，从 Web 页面创建至少 12 个字符密码的管理员账号。注册由数据库唯一约束保证只成功一次；账号存在后接口关闭。密码仅以 Argon2id 哈希保存，不进入 `.env`。

浏览器登录使用 `HttpOnly` 会话 Cookie；登录响应同时返回 `csrf_token`，写请求须和可读的 `vulnweaver_csrf` 同站 Cookie 一样，通过 `X-CSRF-Token` 回传。认证请求必须携带 `schema_version: "1.0.0"`，改密还必须携带 `Idempotency-Key`。本地纯 HTTP 调试需设置 `SECURE_COOKIE=false`。

复核模型端点、模型名、API Key、超时、重试和节流参数改由 Web“设置”管理并保存到 PostgreSQL，分析 Worker 下次启动时生效。API Key 按产品约定明文落库，但 API 永不回显，只显示是否已配置；数据库管理员和备份读取者仍可看到它。跨主机访问必须配置 HTTPS/TLS，本机纯 HTTP 仅用于 `localhost`。数据库/Redis/Runner 地址、Cookie 策略、代理和资源安全上限继续由部署配置注入。

从旧版升级时保留数据库即可继续使用原账号；删除 `PERSONAL_USERNAME`、`PERSONAL_PASSWORD_FILE` 和 `PERSONAL_PASSWORD_FILE_HOST`。原 `REVIEW_MODEL_*` 连接变量不再读取，请在升级前记录并通过 HTTPS 在设置页重新填写；不要把 API Key 提交到仓库。

## 质量门禁

本地与 CI 使用同一组命令：

```shell
pnpm run check
```

门禁依次执行 Ruff、Pyright、pytest 与 TypeScript 检查；MVP 阶段总体分支覆盖率阈值为
80%。日常迭代可只运行受影响模块的测试与静态检查，`pnpm run check` 保留给里程碑、合并和
CI，并使用 PostgreSQL 16 与 Redis 7 执行关键真实集成测试。

开发容器不挂载 Docker Socket，也不得用于直接运行未知样本、Poc 或利用脚本。
