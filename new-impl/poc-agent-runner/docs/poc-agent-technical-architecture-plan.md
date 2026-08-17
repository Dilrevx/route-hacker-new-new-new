# PoC Agent 子系统技术架构计划

> 文档状态：技术架构讨论稿
>
> 更新时间：2026-08-17
>
> 当前范围：只设计 Harness 审计之后的动态确认子系统。召回与 Harness
> 审计由外部流水线负责，本计划仅定义接入边界。
>
> 当前目标：使用若干手工构造的 OpenMeetings 审计报告，验证独立
> Instrumentation Agent、PoC Agent 和 AI Verifier 能否形成真实动态闭环。

## Round 更新记录

### Round 0：替换旧的固定 Probe 规划

- Goal：将 PoC 模块从固定插桩计划和机械 Probe，调整为 AI 主导的动态确认系统。
- Scope：Instrumentation Agent、PoC Agent、Independent AI Verifier 和控制面。
- Action：确定三个 Agent 使用独立 session；PoC Agent 完全自由，仅限制 token；
  Verifier 不读取 PoC Agent transcript；插桩交付可重建 Docker bundle。
- Output：本技术架构计划。
- Verification：所有关键边界均来自当前设计讨论中的明确决策。
- Decision：PoC 是核心产物，Instrumentation 是观测基础设施，最终结论由独立
  AI Verifier 给出。
- Next Round：实现最小控制面和三个 Agent runner，再用手工 OpenMeetings
  报告验证 PoC 模块。

### Round 1：接入最小 PoC Agent 与 Verifier Runner

- Goal：先把 PoC Agent 和 Independent AI Verifier 的独立 session 能力接到 CLI。
- Scope：`route-hacker poc run` 与 `route-hacker poc verify`，不实现完整召回、
  Harness 审计或 Instrumentation Agent。
- Action：新增 PoC Agent runner 保存 prompt、event JSONL、stderr、final message、
  run metadata、session id、token usage 和 wall time；新增 Verifier runner，以原始
  audit report、PoC artifact、reproduction command 和 verifier workspace 作为输入。
- Output：可通过 CLI 启动 PoC 开发 session，也可启动全新的 verifier session。
- Verification：OpenMeetings 手工审计报告驱动 PoC Agent 生成可复现 JUnit PoC；
  final run 显示 `BUILD SUCCESS`、`marker_exposed=true` 和 Surefire 1/1 通过。
- Decision：runner 只负责启动独立 Agent 与留证，不在控制面里写死漏洞判断规则；
  Verifier prompt 明确不读取 PoC Agent transcript，仅允许环境适配，禁止修改 PoC 主体语义。
- Next Round：为 Verifier 接入预构建 runner 镜像或干净 `/mnt` 工作区模板，并在
  OpenMeetings PoC artifact 上执行一次独立复跑。

## 1. 设计目标

PoC 子系统接收 Harness 审计报告，通过自主运行时实验将静态风险判断转化为以下
终态之一：

- `CONFIRMED`：PoC 在干净环境中可重放，并产生审计报告所描述的安全影响。
- `REJECTED`：动态证据能够否定审计报告中的风险假设。
- `INVALID_POC`：PoC 无法在不改变其安全语义的情况下重放。
- `BLOCKED`：构建、依赖、平台或环境问题阻止有效验证。
- `INCONCLUSIVE`：现有动态证据不足以确认或排除风险。

该模块的研究目标不是发布 exploit，而是完成 confirmation-oriented
verification。PoC 可以是单元测试、集成测试、HTTP 请求序列、浏览器自动化、
脚本、二进制、Compose 场景或 Agent 选择的其他可执行形式。

## 2. 总体架构

```text
                      External Pipeline
          Recall/HCVR anchors -> Harness audit report
                                |
                                v
+------------------------------------------------------------------+
|                    PoC Subsystem Control Plane                    |
|                                                                  |
|  Job Manager                                                     |
|    - 创建独立 Agent session                                      |
|    - 管理状态迁移与 token budget                                 |
|    - 维护 artifact identity                                      |
|    - 收集时间、token、日志与最终 verdict                         |
|                                                                  |
|  Artifact Registry                                               |
|    - audit report                                                 |
|    - instrumentation Docker bundle revisions                     |
|    - instrumentation change requests                             |
|    - PoC artifact                                                 |
|    - verifier receipt                                             |
+-----------+----------------------+-------------------------------+
            |                      |
            v                      |
  Instrumentation Agent           |
  独立 session / 可独立平台         |
            |                      |
            v                      |
  Rebuildable Docker Bundle        |
            |                      |
            +---------------------> PoC Agent
                                     独立持续 session
                                     完全自由探索与修改
                                     仅限制 token
                                           |
                          observation 不足  |
            +------------------------------+
            | Instrumentation Change Request
            v
  Instrumentation Agent -> new bundle revision
                                           |
                                           v
                                  Portable PoC Artifact
                                           |
                                           v
                              Independent AI Verifier
                              独立 session / 预构建 runner
                                           |
                                           v
                    CONFIRMED / REJECTED / INVALID_POC
                         / BLOCKED / INCONCLUSIVE
```

## 3. 核心组件

### 3.1 Control Plane

控制面只负责调度和留档，不负责安全推理，不决定插桩点，不生成 PoC，也不解释
漏洞是否成立。

职责：

- 为三个 Agent 创建彼此独立的 session；
- 将 Harness 报告交给 Instrumentation Agent；
- 将当前 instrumentation bundle 和 Harness 报告交给 PoC Agent；
- 将 PoC Agent 的 change request 重新路由给 Instrumentation Agent；
- 保持 PoC Agent 原 session，使其在 bundle 更新后继续已有调试上下文；
- 仅对 PoC Agent 应用 token 上限；
- 将最终 artifact 交给全新的 Verifier session；
- 记录每个阶段的 token、wall time、artifact 和终态。

控制面不应将旧的 `instrument-plan-from-audit`、固定 HTTP Probe 或机械 marker
判断作为主流程。

### 3.2 Instrumentation Agent

Instrumentation Agent 是独立 AI，允许自由读取源码、修改构建文件、增加运行时
Agent、插入日志、配置 debugger 或使用其他观测机制。

输入：

- Harness 审计报告；
- 目标源码和构建环境；
- 可选的 Instrumentation Change Request；
- 上一版本 bundle，若本轮为修订。

输出：

- 可重建的 Docker bundle；
- bundle revision 和内容 hash；
- 构建、启动、停止和观测说明；
- 插桩加载成功的基线证据；
- 与上一 revision 的变化说明。

边界：

- 不负责生成或调试漏洞触发输入；
- 不要求主动触发关键漏洞分支；
- 每次修订都产生新 bundle，不覆盖历史 revision；
- 交付后 bundle 对 PoC Agent 和 Verifier 均为不可变输入。

Docker bundle 的实现形态不写死。它可以是 Dockerfile、Compose、多阶段构建、
Java Agent、源码 patch、动态 attach 工具或其他可重建方案。

### 3.3 PoC Agent

PoC Agent 是整个模块的主要开发 Agent，使用独立且持续的 session。

输入：

- Harness 审计报告；
- 当前 instrumentation Docker bundle；
- 完整源码和运行环境。

权限：

- 可读取整个仓库；
- 可修改任意 PoC 开发文件和测试文件；
- 可启动、停止和重建服务；
- 可创建认证、业务数据和外部依赖；
- 可选择任意 PoC 技术；
- 可根据运行时反馈持续修改；
- 可向 Instrumentation Agent 请求新的 bundle；
- 不记录或限制其读取了哪些源码文件。

预算：

- 只设置 PoC Agent token 上限；
- 不设置固定迭代轮数；
- 不设置固定命令数；
- 不将 wall time 作为研究终止条件；
- 允许基础设施 watchdog 终止挂死进程，但这不等于 PoC 预算耗尽。

退出条件：

- 成功产生可执行 PoC artifact；
- token 上限耗尽；
- 出现有证据的不可恢复环境阻塞。

PoC artifact 只要求语义上的可执行与可重放，不要求固定语言、目录结构或封装格式。
实现可以提供推荐 manifest 或 adapter，但不能把研究定义绑定到 `run.sh`、
`poc-config.json` 或某一种测试框架。

### 3.4 Independent AI Verifier

Verifier 是第三个独立 AI，不读取 PoC Agent 的 transcript、reasoning 或失败历史。

输入：

- 原始 Harness 审计报告；
- 最终 instrumentation bundle；
- PoC artifact；
- artifact identity 和完整性信息。

运行环境：

- 使用提前构建、版本固定的 verifier-runner 镜像；
- verifier-runner 包含 TraeX/Agent CLI、Docker/Compose、常用语言工具、HTTP
  客户端和浏览器自动化能力；
- 每个实验固定 runner image digest；
- Verifier 从 instrumentation bundle 重建干净目标环境；
- 不继承 PoC Agent 留下的容器、数据库或临时状态。

允许修改：

- host 和 port；
- 容器名和网络名；
- 文件路径和挂载位置；
- 凭据注入方式；
- 依赖路径等环境适配配置。

禁止修改：

- instrumentation bundle；
- PoC 请求语义；
- payload；
- 执行逻辑；
- 断言；
- 成功条件；
- 任何改变 PoC 主体安全语义的内容。

Verifier 以 PoC 为主要评估对象，以插桩输出和其他运行时证据作为支持。若必须修改
PoC 主体才能成功，输出 `INVALID_POC`，不能现场修复后判定 `CONFIRMED`。

## 4. Artifact Plane

Artifact Registry 维护不可变、内容寻址的对象。对象可存放在本地文件系统、
对象存储或数据库中，架构不依赖具体后端。

### 4.1 Audit Report

审计报告可以是结构化 JSON，也可以是自由文本。最低语义要求：

- 被审计的 guideline 或风险模式；
- anchors 和相关上下文；
- 风险假设；
- 静态推理与关键代码位置；
- 需要通过动态实验回答的问题；
- 预期安全影响；
- 已知环境和业务状态提示。

报告不应指定固定插桩技术，也不应被脚本直接翻译成固定 Probe。

### 4.2 Instrumentation Bundle

最低语义要求：

- 可重建；
- 可启动；
- 已加载观测能力；
- 有不可变 revision/hash；
- 有足够说明供 PoC Agent 和 Verifier 使用。

### 4.3 Instrumentation Change Request

change request 由 PoC Agent产生，允许自由文本，不强制结构化 schema。

它应描述当前观测为什么不足，以及 PoC Agent 希望新增或调整的观测能力。
Instrumentation Agent自行决定具体实现。

### 4.4 PoC Artifact

最低语义要求：

- 有明确执行方式；
- 可声明允许调整的环境参数；
- 能识别不可修改的 PoC 主体；
- 绑定成功开发时使用的 instrumentation bundle revision；
- 描述预期安全影响和成功表现；
- 可由独立 Verifier 重放。

格式保持开放。平台通过 adapter 或 Agent 说明理解不同 artifact。

### 4.5 Verifier Receipt

Verifier 输出：

- 最终 verdict；
- 原始 artifact 与 bundle identity；
- 干净环境重建记录；
- 实际执行方式；
- 环境适配项；
- 安全影响观测；
- 插桩或其他运行时证据；
- 结论理由；
- token 和时间统计。

## 5. 状态机

```text
RECEIVED
  -> INSTRUMENTING
  -> INSTRUMENTATION_READY
  -> POC_DEVELOPING

POC_DEVELOPING
  -> INSTRUMENTATION_CHANGE_REQUESTED
  -> INSTRUMENTING
  -> INSTRUMENTATION_READY
  -> POC_DEVELOPING

POC_DEVELOPING
  -> POC_READY
  -> VERIFYING
  -> CONFIRMED | REJECTED | INVALID_POC | BLOCKED | INCONCLUSIVE

POC_DEVELOPING
  -> POC_BUDGET_EXHAUSTED
  -> VERIFYING
  -> REJECTED | INVALID_POC | BLOCKED | INCONCLUSIVE
```

注意：

- PoC 单次执行失败不会触发终态；
- PoC Agent 应继续迭代直到成功、token 耗尽或不可恢复阻塞；
- `REJECTED` 必须有否定风险假设的动态证据，不能由“PoC 没成功”直接推出；
- Verifier 即使收到 budget-exhausted artifact，也要独立判断失败类型。

## 6. 部署架构

三个 Agent 可以运行在同一控制面下，也可以部署为三个独立平台。

推荐的初始部署：

- Control Plane：Python service/CLI，负责 session 和 artifact 管理；
- Agent Runtime：TraeX non-interactive session；
- Instrumentation Worker：具备源码、Docker 和目标工具链访问；
- PoC Worker：具备完整源码、Docker、网络和测试能力；
- Verifier Worker：运行预构建 verifier-runner 镜像；
- Artifact Registry：位于 `/mnt` 或对象存储，避免依赖临时 session 工作区。

推荐的扩展部署：

- 三个 Agent 平台通过 job queue 和 artifact URI 解耦；
- bundle 和 PoC 使用内容 hash 寻址；
- Control Plane 只传递 artifact references；
- 每个 Agent 平台独立扩缩容和维护工具镜像。

## 7. 安全与隔离

- 每个 PoC job 使用隔离的 Docker network、容器名前缀和临时目录；
- 禁止共享宿主机清理命令；
- PoC Agent 可以自由修改其 job workspace，但不能修改其他 job artifact；
- Verifier 使用干净 workspace；
- secret 通过环境或临时挂载注入，不写入 artifact；
- artifact 输出进行 token、session、authorization 和 credential 脱敏；
- Verifier 只接受内容 hash 与提交时一致的 PoC 主体。

## 8. 可观测性

必须记录：

- 三个 Agent 各自 token；
- PoC Agent token limit；
- 各 Agent wall time；
- 整个子系统 wall time；
- instrumentation revision 数；
- change request 数；
- PoC 执行次数，可从 transcript/receipt 后处理统计；
- 最终 PoC artifact；
- Verifier verdict；
- clean replay 是否成功；
- 最终安全影响和运行时证据。

PoC Agent transcript 可以保留用于失败分析和论文定性案例，但不提供给 Verifier。

## 9. NDSS 实验设计

### 9.1 主指标

- `CONFIRMED` 数量和比例；
- `REJECTED` 数量和比例；
- valid PoC rate；
- clean replay success rate；
- `BLOCKED` 和 `INCONCLUSIVE` 比例；
- PoC Agent token；
- 端到端 token；
- 端到端 wall time；
- instrumentation change request 数。

### 9.2 核心消融

1. Harness audit only。
2. PoC Agent without dedicated instrumentation feedback。
3. Full subsystem：Instrumentation Agent + PoC Agent + Independent AI
   Verifier。

核心研究问题：

> 在固定 PoC Agent token 预算下，运行时观测反馈是否能够将更多不确定的静态审计
> 报告转化为可独立复现的确认或排除结论？

### 9.3 公平性

- 所有方案使用相同 Harness 报告；
- 所有 PoC Agent 使用相同 token 上限；
- Verifier runner image digest 固定；
- Verifier 不读取任何 PoC Agent transcript；
- 报告三个 Agent 的总成本，但只对 PoC Agent执行预算限制；
- 失败、阻塞和预算耗尽分别统计。

## 10. 实施阶段

### Phase 0：契约与控制面骨架

- 定义 job、session、artifact reference 和状态机；
- 支持三个独立 TraeX session；
- 支持 PoC token budget；
- 支持 token、时间和 artifact 留档；
- 不实现固定 Probe 生成。

验收：

- 可用 fake Agent 完整重放状态机；
- Verifier 输入中不包含 PoC transcript；
- bundle revision 和 PoC identity 可追踪。

### Phase 1：Instrumentation Agent

- 从审计报告启动独立 Agent；
- 交付可重建 Docker bundle；
- 支持 revision 和 change request；
- 验证 baseline 启动和插桩加载。

验收：

- 从空 workspace 重建 bundle；
- clean start 成功；
- bundle revision 不可变；
- 不要求触发漏洞。

### Phase 2：PoC Agent

- 从 audit report + bundle 启动持续 session；
- 实现 token budget；
- 允许自由源码和环境访问；
- 支持 change request 后继续原 session；
- 保存最终 PoC artifact。

验收：

- Agent 能多轮执行和修改 PoC；
- bundle 更新后保留原 session；
- token 耗尽能够形成明确 receipt；
- 不限制 PoC 形态。

### Phase 3：Independent AI Verifier

- 预构建 verifier-runner image；
- 创建全新 Agent session；
- 从 bundle 重建干净环境；
- 环境适配与 PoC 主体变更分离；
- 输出五类终态。

验收：

- Verifier 不读取 PoC transcript；
- 不修改 instrumentation bundle；
- 不修改 PoC 安全语义；
- verdict 绑定实际 clean replay 证据。

### Phase 4：OpenMeetings 模块实验

- 手工构造多个 Harness 审计报告；
- 不运行完整 recall/Harness 流水线；
- 运行 Instrumentation Agent；
- 运行受 token 限制的 PoC Agent；
- 运行独立 AI Verifier；
- 记录完整实验 receipt。

首批建议覆盖：

- 可确认的逻辑漏洞；
- 静态上可疑但应被排除的候选；
- 需要 instrumentation change request 的候选；
- 环境阻塞候选。

### Phase 5：规模化与流水线接入

- 接收外部 HCVR/Harness pipeline 的真实报告；
- 批量调度 PoC jobs；
- 固化 NDSS 消融；
- 统计 confirmation、rejection、成本和可复现性。

该阶段不属于当前 OpenMeetings 模块可行性测试。

## 11. Legacy 处理

以下旧主线规划立即废弃：

- 脚本从审计报告确定插桩位置；
- 固定 instrumentation plan；
- 固定 HTTP/Arthas Probe 作为 PoC 模块；
- `mechanical-confirm` 作为最终确认器；
- direct JVM hook 代表 PoC 成功；
- 导入历史 harness summary 代表动态闭环。

相关代码暂不删除，可保留为：

- baseline；
- Agent 可选工具；
- 兼容旧 artifact；
- 调试工具。

新实现和论文方法均以本计划为准。

## 12. 当前无阻塞决策

以下决策已经确定，不需要在实现前继续讨论：

- 三个独立 AI Agent；
- PoC Agent 完全自由；
- 只限制 PoC Agent token；
- Verifier 不读取 PoC transcript；
- Instrumentation Agent 交付可重建 Docker bundle；
- Verifier 不修改 instrumentation bundle；
- Verifier 仅允许环境适配，不修改 PoC 主体安全语义；
- verifier-runner 镜像提前构建；
- 本轮只用手工 OpenMeetings 审计报告测试 PoC 模块。
