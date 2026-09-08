# VulnWeaver API

T07 控制面 API。该服务面向个人使用，仅存在一个个人账号，不包含团队、成员、系统管理员、角色或 RBAC 模型。所有项目均由该个人账号创建并独占管理。

## 初始化登录

首次启动前创建一个只包含初始密码的 UTF-8 文件，并以只读 Secret 挂载到容器内：

- `PERSONAL_USERNAME`：登录名，默认 `owner`。
- `PERSONAL_PASSWORD_FILE`：容器内密码文件路径。
- `PERSONAL_PASSWORD_FILE_HOST`：Compose 读取的宿主密码文件路径。
- `SECURE_COOKIE`：生产环境保持 `true`；仅本机纯 HTTP 测试时使用 `false`。

服务只在数据库尚无个人账号时读取该密码。首次登录必须通过 `POST /api/auth/password` 修改密码，修改后全部已有会话立即失效。

## 已实现接口

- 个人登录、身份查询、改密和退出。
- Project 创建、列表与详情。
- Artifact 流式上传、列表、版本详情和内容流。
- Task 创建、查询、取消、Job 查询与事件恢复。
- HTTP 事件恢复与 WebSocket 增量事件。
- 存活和就绪检查。

领域写请求需要 `Idempotency-Key`。除登录外，Cookie 会话下的写请求还需要登录响应返回的 `X-CSRF-Token`。上传仅接受源码归档、ELF 和 PE 字节流，不接受宿主路径、空文件、`derived` 或 `source_repository` 直接上传。
