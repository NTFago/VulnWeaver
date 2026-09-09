# VulnWeaver API

T07 控制面 API。该服务面向个人使用，仅存在一个个人账号，不包含团队、成员、系统管理员、角色或 RBAC 模型。所有项目均由该个人账号创建并独占管理。

## 初始化与设置

数据库尚无账号时，Web 通过一次性 `POST /api/auth/register` 创建唯一管理员并建立会话；唯一约束保证并发注册只有一个请求成功。账号存在后注册返回 409。`GET /api/auth/installation` 仅公开注册是否开放。

管理员通过认证及 CSRF 保护的 `/api/settings` 管理模型连接与 API Key。API Key 明文保存在 PostgreSQL，响应只给出是否已配置而不回显；传输安全依赖 HTTPS。数据库、内部地址和安全上限仍由部署配置注入。`SECURE_COOKIE` 在生产环境保持 `true`，仅本机纯 HTTP 测试时使用 `false`。

## 已实现接口

- 首次注册、个人登录、身份查询、改密和退出。
- 产品设置读取与更新。
- Project 创建、列表与详情。
- Artifact 流式上传、列表、版本详情和内容流。
- Task 创建、查询、取消、Job 查询与事件恢复。
- HTTP 事件恢复与 WebSocket 增量事件。
- 存活和就绪检查。

领域写请求需要 `Idempotency-Key`。除登录外，Cookie 会话下的写请求还需要登录响应返回的 `X-CSRF-Token`。上传仅接受源码归档、ELF 和 PE 字节流，不接受宿主路径、空文件、`derived` 或 `source_repository` 直接上传。
