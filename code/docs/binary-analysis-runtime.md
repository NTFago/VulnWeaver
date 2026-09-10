# 二进制分析运行时

T26 的二进制工具链由 `analysis-worker` 通过 `SANDBOX_RUNNER_URL` 调用
`sandbox-runner`，不在 Worker 内直接访问 Docker。Runner 使用注册的
`BINARY_TOOLS_IMAGE_DIGEST`（未显式设置时仅解析本机镜像 digest）启动
`binary-tools`，并将结果写入共享 CAS。

## Compose 挂载

- `artifact-data` 同时挂载到 Worker 和 Runner 的
  `/var/lib/vulnweaver/artifacts`，用于输入、派生工件和 `binary-facts.json`。
- `sandbox-runtime` 挂载到 Runner 的 `/var/lib/vulnweaver/sandbox`，其宿主机
  路径通过 `DOCKER_HOST_SANDBOX_ROOT` 显式传入 Docker 运行时。
- Runner 访问 `/var/run/docker.sock` 仅用于 Sandbox Runner；Worker、API 和
  普通工具容器不挂载 Docker Socket。
- 工具规格目录 `/etc/vulnweaver/tool-specs` 为只读挂载。

## 资源与安全默认值

`binary-facts` 请求默认使用 4,000 CPU millis、3 GiB 内存、1 GiB 磁盘和
Worker 配置的超时上限；输出大小仍受分析限额约束。执行容器默认禁网、非 root、
只读根文件系统，并通过临时工作目录保存 Ghidra 中间文件。生产环境应显式设置
`BINARY_TOOLS_IMAGE_DIGEST`、`SANDBOX_RUNNER_TOKEN` 和
`DOCKER_HOST_SANDBOX_ROOT`，避免依赖本机默认值。
