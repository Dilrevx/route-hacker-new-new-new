# GCA 研究与环境修复时间线

这份记录把早期 guideline 召回探索、P3 基线、环境修复和 9 月的 embedding 迭代串在一起，帮助以后回答：当时想解决什么、改变了什么、留下了什么，以及哪些结果不能直接比较。首次整理日期为 2026 年 10 月 1 日，清理记录更新至 10 月 3 日；临时目录规模来自 9 月 30 日盘点。

核心脉络是：先验证小模型能否学到 guideline 召回信号，再检查词面依赖、候选覆盖和排序预算；P3 固定为 0.6B 加 query-only MLP；后续才分别开展 4B 方法重建、LoRA、数据与可学习性诊断。编译和运行环境修复是支撑评估的并行工作，不是 embedding 训练的一部分。

## 阅读入口

- [70 个临时实验目录索引](REGISTRY.zh-CN.md)：每个目录的系列、来源和保存状态。
- [结构化实验登记](experiment-register.json)：390 份小型源记录的路径、哈希、时间来源及小权重登记。
- [早期方法依赖证据](early-lineage-evidence.json)和[9 月仓库级实验协议摘录](later-research-evidence.json)：用于核对方法、数据划分和前后依赖。
- [系统临时目录记录](SYSTEM_TMP.zh-CN.md)：issue/snippet 迁移、LoRA 修复、量化及 SVulD 支线。
- [P3 与 P4 已保存基线](../../baselines/previous-method/README.md)和[环境修复说明](../../baselines/environment-fixes/REPAIR_GUIDE.zh-CN.md)。
- [HCVR 早期修复记录](../../baselines/environment-fixes/hcvr/README.zh-CN.md)：补收 v8、v9、v10 的修法、真实执行记录和结果，按案例关联重复出处；不复制大体积构建现场。

主体结果来自历史记录，首次整理没有重新训练、启动环境或复现漏洞。后续 10 月 1 日对两个 HCVR 项目进行了独立编译及 CodeQL 建库验收，见[新增执行记录](../../baselines/environment-fixes/hcvr/rebuild-check-20261001/README.zh-CN.md)；它不是训练实验或漏洞动态确认。源说明中的 “current”“next”“goal” 是写作当时的状态，不是对当前工作的指令或结论。

## 日期怎么读

时间均按北京时间展示，并保留原始 UTC 字段供核对。时间证据分三类：

1. **记录时间**：源文件明确的 `created_at`、`finished_at`、`generated_at` 等字段；字段含义照录，协议创建不等于实验完成。
2. **文件时间**：文件 mtime，只能辅助定位历史快照，复制或修改可能改变它。
3. **目录日期**：目录中的日期标签，不证明真实开始或完成时间。

`split20260722`、`train20260723` 等数字经常是随机种子，不能直接当作日期。例如一个 `seed20260723` 的摘要在文件元数据中早于 7 月 23 日。[原始时间及 split 字段](early-lineage-evidence.json)保留了这种区别。

## 总时间线

| 时间及证据 | 当时的问题 | 工作与留下的成果 | 和其他阶段的关系 |
| --- | --- | --- | --- |
| 7 月 22 至 23 日，主要依据文件时间 | 小模型是否能学到超出原始 embedding 的召回信号 | 冻结 0.6B，训练共享线性投影；加入多视图、一致性、弱负例、词面扰动和候选合并。[阶段总览](sources/early-guideline/guideline-method-evidence-v1/method_evidence.md) | 常见口径是 169 cases，按项目分组划分为 86 train／38 dev／45 test cases；不是后来 P3 的 155 cases |
| 7 月 23 日 19:51，审计 `generated_at` | 指标分母和候选包选型是否有可追溯证据 | 保留训练／评估边界检查，同时记录 balanced Top900 选型时间的证据缺口。[原始审计](sources/early-guideline/guideline-fusion-aware-reranker-v1/training_leakage_audit_current/guideline_reranker_training_leakage_audit.json) | 审计对象是当时的 fusion-aware reranker，不是所有后续模型的无泄漏认证 |
| 7 月 27 日，冻结与选择记录 | 能否形成稳定的 query-only 小适配器基线 | 15:22 冻结开发数据；15:33 的选择摘要记录 P3C64。0.6B 加残差 MLP，code bank 冻结。[P3 选择记录](../../baselines/previous-method/p3c64/selection_run_v1/summary.json) | 155 cases：112 fitting、43 selection；43 是选型集，不是盲测 |
| 7 月 27 日 16:38，one-shot 摘要 | 选中的 P3C64 能否迁移到外部项目 | 不 refit、不重新选择 variant；22 个来源案例中 21 个有映射正例，进入召回指标。[P4 记录](../../baselines/previous-method/p3c64/p4_external_b0_vs_p3c64_one_shot_v1/summary.json) | 继承已选 P3C64，但重新生成外部 generic 候选池 |
| 8 月 15 日标签及 8 月后续记录，见各自来源 | 历史项目怎样编译、启动和接受检查 | Runtime v2、compile／CodeQL 修复、旧构建配方和源码插入实验并行积累。[修复归档](../../baselines/environment-fixes/README.md) | 编译、建库、服务 readiness 和 PoC 确认是不同结果，不能相加 |
| 8 月 20 日，fixed143 目录标签 | P3C64 在固定论文评估集合上表现如何 | 在固定 143 identities 上比较 P3C64 与独立 frozen 4B。[评估目录](../../new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/) | P3 仍是 0.6B 加 MLP，不是 4B 微调；一个 case 的候选数不同 |
| 9 月 15 日，SVulD 文件时间 | triplet 目标的不同解释是否实现正确 | 独立标量参考对照数值和梯度；历史记录为 20 项测试通过。[支线说明](SYSTEM_TMP.zh-CN.md) | 独立的损失重建诊断，不代表作者代码复现或 P3 的训练目标 |
| 9 月 19 日，完成回执 | issue/code 表示和量化检索能否跑通 | 语义表示、issue 扩展、量化检索及查询／代码空间修正；数值流程成功不等于盲审目标完成。[支线记录](SYSTEM_TMP.zh-CN.md) | 这是独立基准支线，不能用其结果替换仓库级召回 |
| 9 月 20 日，完成与选择回执 | 原 HCVR 能否迁移到 issue/snippet 任务，更大模型或 LoRA 是否有帮助 | 同一批 function/window 数据上依次做 HCVR／0.6B、raw 4B、4B LoRA 与 raw 8B 对比；保留负向迁移和训练兼容修复。[协议与记录](SYSTEM_TMP.zh-CN.md) | 316 条 test rows 的探索性实验；此处 LoRA 同时改变 query/code encoder |
| 9 月 20 日 23:13，协议 `created_at` | 原始输入不完整时，能否在 4B 上重建 P3 方法 | 沿用 cases/pairs 与方法逻辑，换 4B、2560 维及重建候选池；协议登记 154 repositories、2,230,711 candidates。[协议摘录](later-research-evidence.json) | 是方法级重建，不是逐字节恢复原实验；与当日上午的 issue/snippet 实验不同 |
| 9 月 26 日，目录标签 | 随机、挖掘和审阅过的弱负例是否改善训练 | source-aligned 数据修正、mixed 对照、扩池与 guideline-balanced 采样；query-only LoRA 配固定 code bank。[协议摘录](later-research-evidence.json) | 扩池记录仍是 0 个新增正例案例、0 个新增安全标签；43-case development 已被反复使用 |
| 9 月 27 日，目录标签 | 是不是训练预算不足 | 固定数据和主要设置，从 3 epochs／42 updates 扩到 60 epochs／840 updates。[预算诊断](later-research-evidence.json) | 验证现有配方是否欠拟合，不是模型容量上限实验 |
| 9 月 28 日，目录标签 | 参数化、项目覆盖和成对监督哪个限制学习 | 低正则 LoRA／free-query 对照，少量新项目，单 pair／联合 pair，再做少量 project-held-out 迁移。[协议摘录](later-research-evidence.json) | 同日有多条分支；free-query 不泛化到新 guideline，新项目采样池指标不是全仓库 Recall |
| 9 月 30 日至 10 月 1 日，整理日期 | 怎样保留已有工作且不搬整台机器 | 已有基线、环境修法与新发现的临时实验建立统一入口；保存精选说明、字段摘录和全目录登记 | 这是知识整理与来源核对，不是新实验，也不是完整环境备份 |
| 10 月 1 日，独立构建及清理回执 | 修复记录能否支撑恢复，哪些重复数据可以清理 | Maven/JStachio 与 Ant/Tomcat 精确归档源码重新建库；其余案例检查登记输入路径；相同缓存文件保留独立恢复副本后清理。[执行记录](../../baselines/environment-fixes/hcvr/rebuild-check-20261001/README.zh-CN.md) | 验证两个样本的编译与建库流程，不泛化为全部案例或运行/PoC 复现；Tomcat 标签与源码版本差异保留 |
| 10 月 2 日，第二批缓存清理回执 | v10 的其他重复依赖缓存能否安全精简 | 另核对 14 份缓存，删除 869,792 个已有独立恢复副本的相同文件，保留独有和未通过核验的文件，估计净释放 121.80 GB。[第二批记录](../../baselines/environment-fixes/hcvr/cache-cleanup-20261002/README.md) | 复用先前两例建库回执并新增缓存恢复抽测；本批没有重新构建项目，源码和数据库不删，恢复库必须保留 |
| 10 月 2 日，第三批缓存清理回执 | 剩余旧缓存是否确实必须保留 | 再核对 35 份缓存、30 个不同案例，删除 1,575,824 个有独立恢复副本的相同文件，保留 59,307 个未匹配或空文件，估计净释放 268.83 GB。[第三批记录](../../baselines/environment-fixes/hcvr/cache-cleanup-20261002-catalog/README.md) | 新增文件恢复抽测及全量清单检查，未新增项目构建；源码、数据库及修复记录保留，剩余占用继续分类，不把未核验等同于永久保留 |
| 10 月 3 日，第四批缓存清理回执 | 其他 seed 版本对应的旧缓存能否继续精简 | 核对 9 份缓存、5 个不同案例，删除 602,096 个有独立恢复副本的相同文件，保留 28,317 个未满足条件的项目，估计净释放 84.29 GB。[第四批记录](../../baselines/environment-fixes/hcvr/cache-cleanup-20261003-v4/README.md) | 全量映射检查、三份文件实际恢复和删除后复查通过；复用两例历史建库回执，不新增构建结论，源码和数据库保留 |
| 10 月 3 日，第五批缓存清理回执 | 失败尝试留下的重复依赖能否精简 | 核对 5 份缓存、4 个不同案例，删除 328,030 个有独立恢复副本的文件，保留 2,248 项，估计净释放 46.49 GB。[第五批记录](../../baselines/environment-fixes/hcvr/cache-cleanup-20261003-v2/README.md) | 全量映射、实际文件恢复与删除后检查通过；五次尝试的历史失败状态不变，本批未重新构建项目 |

旧共享投影探索和 P3 在研究主题上连续，但目前没有证据证明 P3 直接加载了这批早期投影权重。P3 的已知输入链来自其归档中的 M7／generic candidate 记录；不能只因时间接近就补出一条训练继承关系。

## 早期方法为何分成这些分支

最初的共享投影头回答“固定编码器后，小头是否能学到信号”。随后加入符号遮蔽与 strict 词面扰动，检查提升是否过度依赖注释、路径和关键词；固定划分的多种子实验则检查训练随机性。[模型与 split 字段](early-lineage-evidence.json)区分了这些变化，不能把换数据划分的 multiseed 与固定划分的重复训练混算。

困难负例和多视图尝试增加一阶段覆盖，但候选合并又引入新的问题：原说明记录 base＋learned lanes 的并集能覆盖 43/45，固定预算候选包却只留下 41/45；随后 dev-selected 配额方案在 test 上下降到 40/45。这解释了为什么工作从“增加召回路数”转向候选包选择与校准，也说明不能只留下并集上界。[困难负例说明](sources/early-guideline/guideline-hard-negative-nview-projection-v1/hard_negative_nview_section.md)、[配额选择说明](sources/early-guideline/guideline-coverage-aware-packet-v1/coverage_packet_section.md)。

蒸馏并不是一条单线：单视图和多视图蒸馏都引用同一个 strict-consistency 权重及教师排序，应看作同源分支。后来较清楚的一段依赖是 **strict-queryaug 权重 → conf40 蒸馏 → dev-only 模型选择 → consolidated report**；这些输入路径在[摘录](early-lineage-evidence.json)中保留。另一个 45 cases／34 project groups／5000 次 bootstrap 分析针对当时的 four-view reranker，不是 conf40 的置信区间。

[综合报告](sources/early-guideline/guideline-consolidated-eval-v1/devselected_conf40_vs_baselines_split20260722/consolidated_report.md)保存了正面结果；[词面压力比较](sources/early-guideline/guideline-primary-method-lexical-stress-v1/primary_cw05_stress_comparison.md)和[历史审计](sources/early-guideline/guideline-fusion-aware-reranker-v1/training_leakage_audit_current/guideline_reranker_training_leakage_audit.json)也一起保留。matched-only、45-case test、169-case overall 是不同分母，原说明中的跨口径表格不应直接当作严格配对比较。

## 9 月后半段在逐个排除什么问题

仓库级支线以重建的 4B 输入为基础，先改弱负例构造与采样，再增加更新步数，然后比较参数化和正则，最后增加少量项目样本并拆成 pair-level 诊断。这些协议中的 `parent` 或输入哈希支持局部继承关系；不能仅按 9 月 28 日这个共同目录标签给所有分支排先后。

尤其需要保留三个区别：[协议摘录](later-research-evidence.json)逐项保留了原文。

- 扩大负例池或重复少数正例，不等于增加正例多样性。
- free-guideline vectors 是固定 guideline 的诊断工具，不是面向未见 guideline 的模型，也不是理论上限。
- project iteration 只有 5 个新增案例和 3 个限定范围的 reviewed pairs；transfer 记录为 3 个新增 fit pairs 和 3 个 project-held-out pairs，新增池是采样池。不能将这些小规模诊断称为完整跨项目仓库评估。

9 月 20 日重建协议还有一个应保留的文字冲突：顶层 `model` 指向 4B、`dimension=2560`，但复制来的 `training.backbone` 仍写 0.6B。这里照录并标注冲突，不据旧字段把 4B 重建解释成原 P3。

## 环境修复如何接到这条时间线

环境工程负责让已有目标可以进入后续流程，不直接证明召回或漏洞检测有效。现有归档按证据级别分开保存：

| 分支 | 保留下来的知识 | 历史结果的含义 |
| --- | --- | --- |
| Legacy 构建 | 254 份 Dockerfile、43 份历史短注，关联 317 条 catalog 记录 | 部分说明截断，需结合配方；不是 317 个已验证可运行漏洞 |
| Compile／CodeQL | 137 个 fleet 案例、242 份修复决策、11 份 compact ledgers | 编译或数据库构建；不等于运行和漏洞确认 |
| Runtime v2 | 启动配方、补丁和 readiness 索引；143 tasks、152 attempts | 143 passed 和 9 failed 是历史尝试状态，不是 PoC 成功数 |
| Source/runtime | 20 个 source-inserted 实验和 2 个 Superset 对照 | 不应重标为未修改的原版源码复现 |

具体“为什么失败、怎么改、验证到哪一步”，直接读[中文修复说明](../../baselines/environment-fixes/REPAIR_GUIDE.zh-CN.md)。缺少原始日期的旧修法留在这条并行分支中，不强行分配到某一天。

## 保存状态和复查方式

2026 年 10 月 1 日又补充整理了 HCVR 早期环境修复。原始小型控制资料在本地私有保存 7,002 份并核对哈希；共享版为 213 个历史案例建立入口，141 个案例有共 787 组去重后的执行或数据库 readiness 记录，另保存若干未完成诊断及源码恢复说明。62 个案例出现过建库修复成功记录；这不是新复现或动态漏洞确认。此前较晚的 fleet／runtime 归档对 HCVR 路径的引用不能视作对应早期目录的备份。具体保存范围和修法见[新索引](../../baselines/environment-fixes/hcvr/README.zh-CN.md)。这次补收本身没有删除远端文件；随后按用户要求进行的抽样恢复验证及重复缓存清理，单独保存在[后续记录](../../baselines/environment-fixes/hcvr/rebuild-check-20261001/README.zh-CN.md)。

本次把 70 个临时目录全部登记，保存 30 份精选原始说明、审计与回执文件，以及支撑时间线的协议字段摘录。原文副本见 [source manifest](source-manifest.json)，新目录全部交付文件的哈希见 [delivery manifest](delivery-manifest.json)，本地完整性与链接检查见 [verification.json](verification.json)。字段摘录记录原文件 SHA；它们不冒充完整原文件。

大权重、候选池、向量缓存、原始日志和其他未复制的小摘要仍留在原位置。`experiment-register.json` 中 `indexed_only`、`small_models_indexed_not_uploaded` 的材料没有因登记而获得 GitHub 备份。以前的私有本地备份也不等于公开 Git 备份；本次不隐式发布其原始数据。

初次归档时，服务器原文件均保持不动。随后于 2026 年 10 月 1 日按用户要求完成一次有限的[远端清理](remote-cleanup-20261001.json)：逐文件重新核对备份与远端 SHA256 后，删除 277 个已备份的大型数据文件，共 8,575,968,027 bytes（约 7.99 GiB），并复查其原路径均已不存在。没有删除目录、脚本、小型说明、未列入清单的数据或本地备份。

清理清单为每个文件保留了来源路径、SHA256、精确本地副本或压缩包成员的位置。多数备份仍是本地私有归档，不在 GitHub；必须保留这些本地备份。再次使用旧实验路径前，应先恢复所需文件并核对哈希，不能将留下的目录视为完整可直接运行的环境。先前的 inventory／verification 是建档时的快照，后续删除状态以这份清理记录为准。
