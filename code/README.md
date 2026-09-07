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

复制 `.env.example` 为本地 `.env` 后，可以运行：

```shell
docker compose -f compose.yaml -f compose.dev.yaml up -d postgres redis
uv sync --frozen
pnpm install --frozen-lockfile
```

启动 PostgreSQL 迁移任务和 Outbox Dispatcher：

```shell
docker compose -f compose.yaml -f compose.dev.yaml up -d dispatcher
```

Compose 会先运行一次 `vulnweaver-migrate`，迁移成功后再以非 root、只读根文件系统启动
Dispatcher。当前公共后端包包括 `contracts`、`domain`、`persistence`、`artifact-store`
和 `queue`。

开发容器不挂载 Docker Socket，也不得用于直接运行未知样本、Poc 或利用脚本。
