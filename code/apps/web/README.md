# VulnWeaver Web

Svelte 5 个人安全分析工作台，通过同源 `/api` 访问 FastAPI 控制面。

## 本地开发

```powershell
pnpm --filter @vulnweaver/web dev
```

Vite 将 `/api` 与 WebSocket 代理到 `http://localhost:8000`。完整 Compose 环境使用 `http://localhost:8080`，开发覆盖会关闭 Secure Cookie；生产部署必须经 HTTPS 提供服务。

## 验证

```powershell
pnpm --filter @vulnweaver/web typecheck
pnpm --filter @vulnweaver/web build
```
