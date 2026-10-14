# 全面 Code Review（2026-10-14）

审查方式：6 路并行模块深审（orchestrator / api+web / persistence+queue+worker / sandbox+proof+fuzz 信任链 / binary-analysis+source-analysis / model-gateway+contracts+reporting+pair+artifact-store+domain）+ 横切面自查（compose/deploy、CI、secrets、危险调用模式 grep）。全部约 4.8 万行 Python + Svelte 前端。高严重度结论（全部 P1、agent 终态化路径、归档物化顺序、fuzz 超时算术）已由第二遍独立读码核实。基线：`main @ 047c62a`。

## 总体结论

未发现 P0（无边界绕过、无样本原生执行逃逸、无注入点、无密钥泄漏）。主流程的并发正确性、安全边界与幂等设计经得起推敲。**真正的系统性缺陷集中在三类**：

1. **失败路径的收尾缺乏兜底**——重试语义在多处自相矛盾（标了 `retryable=True` 却被白名单否决；`FailureKind.TIMEOUT` 却 `retryable=False`），毒丸消息无隔离，瞬态故障被终态化；
2. **ADR-025 去配额后"由超时与清理兜底"的承诺缺少工程接线**——8 GiB 输出上限被实现为进程内存缓冲、孤儿容器回收函数从未被调用、fuzz 分诊时间必超容器预算；
3. **单事件循环上的阻塞点**——binary_strings 搜索、PDF 渲染、（已修一半的）source 搜索同类问题在三处各自存在。

---

## P1（必修，6 条，全部已二次核实）

### P1-1 单条畸形队列消息可让整个 worker 组崩溃循环，无隔离/dead-letter 路径
- `packages/worker/src/vulnweaver_worker/worker.py:120-124`、`packages/queue/src/vulnweaver_queue/redis_streams.py:477`
- `run()` 主循环只捕获 `QueueUnavailable`；`read_group`/`claim_stale` 解码失败抛 `MalformedQueueMessage`（同属 `QueueError`），异常冲出 `run()` → 进程退出 → 消息未 ack → 30s 后 `XAUTOCLAIM` 重投 → 再失败。周期性 crash loop，消费组所有 job 停摆，重启不能自愈。触发：滚动升级契约漂移、Redis 数据损坏。修法：解码失败转 dead-letter 并 ack（`_DEAD_LETTER_SCRIPT` 原语已存在）或跳过+告警。

### P1-2 Runner 将沙箱 stdout/stderr 全量缓冲在进程内存，上限 8 GiB，join 时峰值再翻倍
- `packages/sandbox-runner/src/vulnweaver_sandbox_runner/runtime.py:591-606`、`runner.py:46,151`
- `MAX_SANDBOX_OUTPUT_BYTES = 8 GiB` 本意是宿主磁盘保护值，却被当作单进程内存缓冲预算：`_read_bounded` 以 `chunks: list[bytes]` 累积，收尾 `b"".join` 再分配一份。agent-sandbox 的 `/bin/sh -c` 由模型规划（ADR-038 设计如此），一条 `yes` 即可 600s 内打满 → runner（单 uvicorn 进程、compose 无内存限制）OOM，整个动态执行面不可用。修法：溢出落盘（spill-to-CAS 流式）而非内存累积。

### P1-3 `recover_orphans` 全仓库无生产调用点：runner 崩溃后孤儿容器/keeper/tmpfs 卷永久泄漏
- `packages/sandbox-runner/src/vulnweaver_sandbox_runner/runner.py:227-243`（仅 `tests/sandbox_runner/test_runner.py:332` 引用）
- 容器非 `--rm` 启动；runner 进程死亡（OOM/宿主重启/部署）后，workload 容器、`sleep 2147483647` 的 keeper（每个 16MiB 限制 + 一个 tmpfs 卷）、输出卷全部存活且无人认领。清理函数已写好但 `build_app` 启动流程未接线。修法：启动时调用一次 + 低频周期调用。

### P1-4 fuzz 崩溃回流在时间预算下系统性失败，崩溃证据静默丢失
- `packages/fuzzing/src/vulnweaver_fuzzing/job_executor.py:201`、`packages/fuzzing/src/vulnweaver_fuzzing/triage.py:119-120`、`apps/fuzz-tool/vulnweaver-fuzz-entrypoint:110-203`
- 沙箱超时被硬约束为 `min(budget.timeout, max_duration)`，而 entrypoint 里 `afl-fuzz -V <max_duration>` 恰好耗尽全部时长，之后才做 afl-tmin（30s/个）+ gdb 取栈（2×20s），最后统一写出产物。时间到且有崩溃 → 容器先被杀 → 输出目录空 → `FuzzStatus.TIMED_OUT`（retryable=True 还会再烧一轮同样失败）。已发现崩溃全部丢失，无 PARTIAL 记录。只有 `-E` 执行数先耗尽才来得及回流。修法：为分诊预留时间（afl 用 `max_duration - triage_reserve`）或超时后仍收集已完成产物。

### P1-5 含换页符的源文件摘录静默错位：行号双口径不一致
- `packages/source-analysis/src/vulnweaver_source_analysis/excerpts.py:150`（关联 `indexer.py:409`、`static_tools.py:344,369`）
- `SourceExcerptReader.read` 用 `str.splitlines()` 切行（额外在 `\f`/`\v`/`\x1c-\x1e`/`\x85`/`\u2028` 等处断行），而 tree-sitter 索引与 semgrep/cppcheck 诊断行号均为 `\n` 口径。C/C++ 真实代码中 `\f` 常见，诊断行前每多一个 `\f`，摘录就前移一行且无任何标记——审计读到错误代码区段、读取证明却照常授权。非恶意即触发。修法：改 `text.split("\n")` 计数。

### P1-6 归档成员元数据在所有限制生效前全量物化，合法大小上传可打 OOM
- `packages/source-analysis/src/vulnweaver_source_analysis/archive.py:132-133,199,214,241-242,277`
- `_extract_tar` 先 `getmembers()` 全量列表、ZIP 在打开时解析整个 central directory 再 `infolist()` 复制一份，`max_files=20000` 与压缩比检查排在其后。上传上限 512MB：一个由海量空成员头组成的 tar/zip（完全合法的大小）即可让单 job 物化百万级 TarInfo（GB 级 transient 内存），且 gzip 炸弹的解压时间也发生在校验前。`max_upload_concurrency=2` 叠加即内存耗尽。修法：流式遍历（tar 逐成员 `next()`、zip 打开即计数中止）让限额先于物化生效。

---

## P2（应修，15 条）

**重试/失败语义系统性矛盾（一个主题四处实例）：**
1. executor 未预期异常标 `kind=INTERNAL, retryable=True`，但结算门要求 kind 在 `retryable_failure_kinds` 白名单内，而所有默认策略只含 `TIMEOUT/ENVIRONMENT/DEPENDENCY` → 任何瞬时错误第一次即终态 FAILED，`max_attempts=2` 形同虚设（`worker/worker.py:537-541` + 各 `review_jobs.py:48-56`）。
2. agent 路径 8h deadline 到期 → `_AuditError(TIMEOUT)` 但 `retryable=False` 默认 → 终态；且 checkpoint 写 `"completed": status is not RUNNING` 为 True，恢复加载器直接放弃 → 与回退路径（RP-01/RC-01 精心设计的 deadline 可续传）韧性语义完全不对称，大索引恰是 agent 路径主战场（`orchestrator/semantic_audit.py:493-498`、`code_audit.py:454`、`agent_loop.py:576-593`）。
3. 分页聚合阶段把三种失败（存储瞬态不可用/摘要不匹配/JSON 损坏）统一折叠成 `INTERNAL` 终态；此刻检查点仍指向"只差聚合"，一次近乎零成本的重试却不被允许（`semantic_audit.py:806-815,845-848`）。
4. 网关对非重试错误（401/402/400）不尝试 fallback——主 provider 余额耗尽/密钥失效时配置了另一家的 fallback 永远不会被用（R6-R10 的 DeepSeek 402 若配了备账户即可无缝切换）；402/401 与 400 语义未区分（`model-gateway/gateway.py:622`）。

**事件循环阻塞（同一模式三处）：**
5. `code-search` 的 binary_strings 分支在协程内同步逐条匹配（50,000 条上限），最长阻塞 worker 事件循环 30s——同机所有 job 停摆、心跳停跳、跨过租约到期点即被他者接管；source 分支已线程化而此分支漏改（`orchestrator/audit_tools.py:1018-1054`）。
6. `render_pdf` 同步 WeasyPrint 调用直接在 execute 协程里跑；同仓库 `binary_importer.py:89` 注释记录过完全相同的"饿死心跳→job 被杀"教训并为此改了 `to_thread`，PDF 路径漏改（`reporting/executor.py:133-141`）。
7. 热重载装配在结算事务内做 HTTP 探测（超时可达分钟级）：拉长 jobs/tasks 行锁事务；装配失败从 hook 冒出 → 整个结算事务回滚 → 已跑 10 分钟的 job 整体重执行（`apps/analysis-worker/hot_reload.py:73-93,109-110` + `worker.py:398-405`）。

**资源护栏与声明的保护目标不符：**
8. 8 GiB 输出上限对文件输出完全不生效：`docker cp` 无界复制 tmpfs → 白名单不查总量 → `_store_path` 的 `max_bytes` 传文件自身大小恒过 → 三份数据落盘后才可能报超限（`sandbox-runner/runtime.py:387-403`、`runner.py:409-451`）。
9. `iter_member_texts` 的 ZIP 分支无异常映射：单个 CRC 损坏成员以裸 `BadZipFile` 击穿只捕 `SourceImportError` 的调用方，且 `_warmed` 标记不执行 → 每次读取都重跑整归档解压，CPU 放大无界（`source-analysis/archive.py:196-210` + `excerpts.py:118-136`）。
10. `SourceExcerptReader` 暖缓存无全局淘汰：256MB 预算是每归档局部变量，`_text_cache/_warmed` 只增不删，长驻 reader 进程内存随任务数线性上涨（`excerpts.py:101-102,121-136`）。

**性能/规模欠账（随真实世界大样本线性恶化）：**
11. `_resolve_location` 对每个候选 finding 全量 SELECT 该版本函数表再内存过滤——投影阶段 O(findings × functions)，5 万函数二进制 + 数千页审计累计小时级，直接侵蚀 8h deadline（`semantic_audit.py:1407-1415` + `repositories.py:2144-2165`）。
12. checkpoint 恢复加载该任务全部历史行（每轮一行、每行可达 4MB），恰在 worker 崩溃/接管最脆弱时刻反序列化数百 MB；`latest_for_node` 已实现却零调用（死代码）（`code_audit.py:417-435`、`repositories.py:1334-1342`）。
13. `find_reusable_imports` 的 JSONB 谓词（`tool->>'name'` 等值 + `input_refs @>`）无索引，位于每个 import job 开头热路径，jobs 表全扫且随历史线性变慢（`repositories.py:686-705`）。
14. RUNNING 孤儿 job 无 DB 侧回收路径：过期租约唯一复活途径是 Redis PEL 重投，流条目丢失（未开 AOF 的 Redis 故障/flush/未来 maxlen 裁剪）即永久 RUNNING、Task 永不结算，API 也无 requeue 工具（`worker.py` 全文 + `repositories.py:761-814`）。
15. 2xx 响应上 usage 字段异常（第三方 OpenAI 兼容网关常见自相矛盾统计）会丢弃携带有效 content 的成功补全，且"breakdown exceeds total"判 `retryable=False` 不重试不回退；非 2xx 分支对 usage 却是尽力而为——同一函数两条路径信任级别不一致（`protocols.py:226-234,283-288` + `gateway.py:713-717`）。

---

## P3（择要，按模块）

**source/binary-analysis**：熵计算纯 Python 逐字节循环（512MB 样本单 job 2-3 份拷贝 + 数亿次迭代）；本地 angr 路径无内存上限（CFGFast 数十 GB 已知案例，靠容器兜底连带 worker）；critical-logic 按函数名聚合、同名 static 函数互相污染判定。

**orchestrator**：回退路径 `cwe_id` 仅受通用 Identifier 约束，非 `CWE-<数字>` 形态在 `_category` 抛 ValueError → 毒化该页重试两次终态（`semantic_audit.py:1450`）；`_persist_initial_job` 恢复后 `ToolNotFound` 落入兜底 except → 毒消息无限重投（`flow.py:485`）；恢复后 `_MAX_REPORTED_FINDINGS(32)` < checkpoint 携带(64) 不归一，报满后恢复的 attempt 无法再报新发现（`audit_tools.py:1304`）。

**persistence/queue**：`artifacts.project_id` 与 `evidence.input_ref` 缺索引；Redis 三流默认无 maxlen、dead-letter 流全库无消费者（只写不读）；pending 条目 30s 被反复偷走产生 BUSY 空转（心跳不刷新 PEL idle）；并发 `add_version` 下 `current_version_id` 后提交者胜、非单调；连接池 5+5 与 concurrency 128 不匹配、无 `statement_timeout`。

**model-gateway/contracts/pair/artifact-store**：fallback 端点缺 tier 时异常绕过错误收集、丢主端点 usage（registry 路径不可达，疑点）；`_resolved_file_offset` 用 `file_size` 而非 `virtual_size` 约束虚拟地址 delta；响应体全量下载后才检查 `max_response_bytes`；CAS 对象 0644 对 owner 可写、`.staging` 崩溃残留无清扫、全库无配额/GC；`validate_contract` 每次调用重建 Draft202012Validator（热路径纯 CPU 开销）；SARIF rules 按 cwe_id 折叠、同 CWE 多发现时规则名取最后一条。

**api/web**：model-probe 在未提供 key 时把存储密钥发往任意 base_url（无 allowlist，被诱导粘贴恶意 URL 即凭据外送，`app.py:1629-1667`）；WebSocket 握手后不再校验会话、前端对 401/4401 无全局处理（改密/过期后旧页面无限重连收事件）；上传文件名 percent-encoding 后从不解码、列表与下载名永久显示 `%E6%A0%B7%E6%9C%AC.zip`；pair neighborhood 为判断成员关系全量拉该版本全部函数行（含伪代码 blob）；改密幂等指纹对明文密码对做无盐 SHA-256 落库（`auth.py:208-211`）；前端搜索与全量刷新毫秒级结果覆盖竞态（疑点）。

**sandbox/proof**：`SANDBOX_RUNNER_TOKEN` 缺省为空即关闭鉴权（缓解：analysis-plane internal + 一次性容器 `--network none`，纵深防御缺口）；bundle 加载接受 `r:*` 压缩 tar 且全部成员同时驻留内存（理论 ~4.8GiB，需控制面先失守）；proof 目标可 double-fork 逃逸进程组清理、在报告写出后毫秒级窗口竞态覆盖 `/output/execution-report.json`（ADR-036 残余，不构成新确认路径，但击穿"父入口独立写报告"缓解假设，P0.5 设计时须以 cgroup 级清理应对）；jsonschema `$` 锚点允许尾随换行（当前有 `build_argv` + `_validate_argv` 双层兜底，不可利用）。

**Ghidra 脚本（本轮新增）**：`deploy/ghidra/ExportVulnWeaver.java:21-24` 的 `escape()` 未处理 `\n\r\t` 之外的控制字符（<0x20 在 JSON 字符串非法），畸形符号名可产出无法解析的 facts JSON；`new FileWriter(target)` 未显式指定 UTF-8（JDK17 上是平台默认字符集）。

**仓库与运维（自查）**：
- **没有任何 CI**（`.github/workflows` 不存在）：全部门禁依赖手工在 dev 容器跑 `pnpm run check`，与项目"多镜像重建纪律 + stale-wheel 教训（Q-003）"的现实放在一起是最薄弱的一环。
- `main` 领先 `origin/main` **16 个提交未推送**：本地单盘保存全部历史，耐久性风险。
- 工作区散落 `code/.tmp-sg-c.yml`、`code/.tmp-sg-c-out.json`（R1 semgrep 临时产物）未清理。
- 基础 `compose.yaml` 的 `SECURE_COOKIE` 默认 `false`、Postgres 默认密码 `vulnweaver_dev_only`——单机 HTTP 部署可接受，对外暴露前必须收敛。
- tool-specs 四个 JSON 共享同一个手工烘焙的镜像 digest，每次重建镜像需人工同步（client 侧 Q-025 重发现机制缓解了正确性，但属易漏流程）。

---

## 已核查且状态良好的部分（负面结论同样重要）

- **无 P0**：沙箱隔离参数（`--network none`/`--read-only`/cap-drop ALL/no-new-privileges/uid 10001/digest 三方一致）硬编码在 `DockerCliRuntime`，请求侧无法注入任何 docker 级参数；ToolSpec 隔离策略被 Runner 反向复核。
- 归档路径安全（zip-slip/绝对路径/盘符/符号链接/硬链接/NUL/大小写碰撞）实现完整，未发现绕过；ELF/PE 解析偏移全部前置校验，无死循环路径；外部进程（Ghidra/semgrep/cppcheck/objdump）全部固定 argv 无 shell + env 白名单 + 超时 + 输出预算。
- SQL 全参数化，三处原生 SQL 均常量/绑定参数；迁移链 0001→0024 严格线性、models 与迁移抽查无漂移；Outbox 同事务不变量处处成立；租约 fencing token 全链路传递、双执行窗口被 fencing 拒绝；幂等指纹 + `on_conflict_do_nothing` 正确。
- orchestrator 读证明按 (版本，路径，行号) 精确授权且与锚定版本对齐（CR-06 修复到位）；确认门事实驱动，红线 8 完好；模型输出经 JSON Schema + PolicyEngine 双重校验，未发现路径穿越。
- 报告渲染全量 `html.escape`/表格转义/动态代码栅栏，PDF 禁外部 fetcher——注入防御完整；报告聚合无丢 findings 路径（RA-04 同链已复查）。
- API 鉴权覆盖完整（逐路由核对）、argon2 + 摘要存储 + 常数工作量 + 原子锁定；上传双重限长 + magic 校验 + digest 复核；exploit 端点经 `evaluate_exploit_eligibility` 强制 CONFIRMED，红线 10 完好。
- 前端无 `{@html}`、token 在 HttpOnly cookie；CAS temp+fsync+link 原子发布、无删除/覆写路径；密钥在错误 details/AgentRun/日志中均无泄漏（有测试断言）。
- API key、`code/secrets/` 正确 gitignored（本轮验证）。

## 建议修复顺序

1. **接线类（低成本高收益）**：`recover_orphans` 接进 runner 启动（P1-3）；毒丸消息 dead-letter（P1-1）；worker 白名单纳入 INTERNAL 或把未预期异常映射为 DEPENDENCY（P2-1）；聚合阶段瞬态/持久失败分流（P2-3）。
2. **护栏类**：runner 输出溢出落盘替代内存累积（P1-2）+ 文件输出总量上限（P2-8）；fuzz 分诊时间预留（P1-4）；归档流式校验（P1-6）。
3. **正确性类**：`splitlines` → `\n` 口径（P1-5，一行修复）；agent 路径 deadline 可续传或显式记录决策（P2-2）；热重载挪出结算事务（P2-7）；PDF/binary_strings 线程化（P2-5/6）。
4. **上线前**：搭最小 CI（dev 容器门禁 + 契约 --check）；推送本地 16 个提交；清理临时文件；对外暴露前收敛 SECURE_COOKIE/默认密码/runner token。
