# 系统临时目录：迁移实验与兼容性修复

这些记录来自 bobo5090 的 `/tmp` 及少量 workspace 临时目录。它们与早期 guideline 工作相关的 70 个临时目录分开登记：有的是迁移对照，有的是训练兼容性诊断，不能合并成同一条召回指标曲线。

本次保存 4 份原始说明和 14 份小型回执／选择记录；文件来源、SHA256、时间字段及只登记未上传的资产见 [system-tmp-evidence.json](system-tmp-evidence.json)。这里只核对历史材料，没有重新训练或执行测试。

## 日期与分支

下表时间均为北京时间。完成回执只证明对应阶段当时记录的状态，不证明整个研究目标完成。

| 时间及证据 | 做了什么 | 保留下来的说明 |
| --- | --- | --- |
| 9 月 15 日，文件 mtime；无内嵌完成时间 | 对 SVulD triplet 目标的不同解释做数值／梯度核对 | [验证回执](sources/system-tmp/svuld/triplet-objectives-verification.json)：20 tests、24 value/gradient grid cases；是独立重建，不是作者实现一致性认证 |
| 9 月 19 日 17:56，`finished_at` | semantic 表示实验完成数值流程 | [阶段回执](sources/system-tmp/semantic/experiment-v1/receipt.json)明确记录 numeric success，但 blind review、scientific interpretation、goal 均未完成 |
| 9 月 19 日 18:27，`finished_at` | issue 扩展支线完成 27 fits、28 models 的评估记录 | [扩展回执](sources/system-tmp/semantic/issue-extension-v1/results/receipt.json)，不是仓库级漏洞召回 |
| 9 月 19 日 18:39–19:00，各阶段回执 | 量化评估、proper-query 检查、最终审计进程先后结束 | [24 次评估](sources/system-tmp/semantic/issue-quantization-v1/evaluation-v2/receipt.json)、[查询阶段](sources/system-tmp/semantic/issue-quantization-v1/proper-query-supervision/receipt.json)、[审计进程](sources/system-tmp/semantic/issue-quantization-v1/final-audit-supervision/receipt.json)；进程 returncode=0 不等于审计结论通过 |
| 9 月 20 日 11:43，supervisor `finished_at` | raw 0.6B 与历史 P3C64 query adapter 迁移到不变的 function/window issue 数据 | [协议](sources/system-tmp/hcvr/protocol.md)、[function 回执](sources/system-tmp/hcvr/supervision/function/receipt.json)、[window 回执](sources/system-tmp/hcvr/supervision/window/receipt.json) |
| 9 月 20 日 11:56，supervisor `finished_at` | 同一测试数据改用 raw 4B | [协议](sources/system-tmp/qwen4b/protocol.md)、[function 回执](sources/system-tmp/qwen4b/supervision/function/receipt.json)、[window 回执](sources/system-tmp/qwen4b/supervision/window/receipt.json) |
| 9 月 20 日 13:22–14:30，回执与选择时间 | raw 8B 对照、4B LoRA 选择与评估、本地重新计算 | [LoRA 协议](sources/system-tmp/qwen-lora/protocol.md)、[选择记录](sources/system-tmp/qwen-lora/selection/selection.json)、[本地核对](sources/system-tmp/qwen-lora/local-verification.json) |

semantic／量化支线冻结的 issue function/window 数据，被后续 HCVR、raw 4B 和 LoRA 对照复用；方法分支不同，不表示数据完全独立。9 月 20 日夜间创建的 4B 仓库级重建协议是另一条支线，见[总时间线](README.md)。不能把这里的 316 条 test rows 当成那里 43 个 development cases。

## 三次修复值得直接复用

原始 [diagnostics.md](sources/system-tmp/qwen-lora/diagnostics.md)已经说明失败原因和修法，保留这份小文档即可找回经验，不必为此上传整个依赖目录。

1. **tokenize 结果不全是 Tensor。** 当时的 SentenceTransformers 5.6 输出包含 modality 字符串。只对 Tensor 做 CUDA 迁移，避免把元数据当 Tensor；该失败发生在 optimizer step 之前。
2. **PEFT 注入到了错误的属性。** 当时 `auto_model` 是返回 `module.model` 的只读属性；改为替换 `module.model`，验证实际对象为 PeftModel，并检查只保存 adapter。失败诊断遗留的大 base checkpoint 不是选中的训练成果。
3. **分片 8B 被 encode 再次整体迁移设备。** 当时 encode 中的 `.to(device)` 与 accelerate dispatch hooks 冲突。保留 tokenize、module forward 和 pooling，避免移动整个 dispatched model，输入放到 embedding 层所在设备；不是移除分片 hooks。

这些是当时所用版本下的修复记录，不应无条件套到未来版本。依赖版本和不改旧环境的处理方式均留在原说明中。

## 哪个权重才是实验选中的

[选择记录](sources/system-tmp/qwen-lora/selection/selection.json)按 validation MRR、R@10、较低学习率、较早 epoch 的规则选出 `lr-5e-5/adapter-epoch3`，选择时间为 9 月 20 日 13:33。adapter 文件为 47,222,896 bytes，完整 SHA256 在[资产登记](system-tmp-evidence.json)中。

该权重本次**只登记，没有上传**。smoke-v2 失败保存出的约 7.6 GiB base checkpoint 不能替代它。此前已看过这套 test 的结果，因此原协议将此次 LoRA 标为探索性实验，即使当次选型没有读取 test，也不应改称新盲测。

此处 LoRA 为 rank 16、q/k/v/o、共享 query/code encoder，会重算 code vectors；后续仓库级 query-only LoRA 为另一套方法，不能混用名称或配置。

## 其余临时材料如何处理

| 来源 | 这次能确认的内容 | 保存状态 |
| --- | --- | --- |
| `/tmp/svuld-triplet-objectives-check-20260915` | triplet 实现、独立参考测试与回执 | 回执已保存；两个 Python 文件仅登记路径、大小、哈希 |
| `/data/lhq/workspace/tmp/vulrag-func-level-0817-smoke` | 空 smoke JSONL 与 repo-cache | 记录用途，不作为成功结果或完整数据集 |
| `/data/lhq/workspace/tmp/log4j-quick-m2` | Maven 下载失败标记等缓存 | 记录为构建诊断缓存，不冒充修复说明 |
| `/tmp/pgpt-*` | 9,001 个目录；抽样查看 24 个命名族，主要为测试 fixture | [盘点清单](tmp-inventory-20260930.json)保留统计和样例；没有逐个读取全部目录，也没有复制 payload |

所有原目录均未删除。已保存说明／回执、字段摘录、仅有元数据登记是三种不同保存状态，不能因有此文档就认定权重、源数据和日志已有完整备份。
