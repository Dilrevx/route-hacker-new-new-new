# 历史环境修复：怎么修、去哪里查

这里保存的是让项目编译、启动的修复经验，不是完整环境备份。**已有文档能讲清楚怎么修，就保留那份文档即可**，不要求同时上传依赖包、镜像和全部原始日志。已经归档的脚本、补丁及配方继续保留。

一份够用的说明应能回答：哪个项目和版本、遇到什么问题、改了哪里或执行了什么命令、当时验证到了哪一步。没有记录的原因不补猜测，历史成功也不写成今天重新验证成功。

## 按项目找已有说明

| 材料 | 修法在哪里 | 怎么读 |
| --- | --- | --- |
| [HCVR 早期修复](hcvr/README.zh-CN.md) | [按案例索引](hcvr/case-index.json)及对应案例记录 | 串起 v8、v9、v10 的修复方案、命令和历史结果；保留失败过程，不把建库和运行成功混为一谈。 |
| [编译修复 fleet](codeql-compile/fleet-138-v1/)：137 个案例 | 每个目录的 `historical-receipt.json` 和 `Dockerfile` | `review.findings` 解释问题和修法；`recipe.build_command` 给命令；`compile_scope`、`limitations` 或 `evidence` 说明验证范围。Netty 的命令见同目录 Dockerfile。 |
| [早期构建配方](legacy-builds/recipe-index.json)：254 份 Dockerfile、43 份短注 | `recipes/<项目>/<历史标识>/build-notes.md` 和相邻 Dockerfile | 部分短注被原样截断，不是完整教程，需要结合配方；数字目录名不应直接当成 Git commit。 |
| [CodeQL 修复决策](codeql-compile/iris-a26/)：242 份 | `validated-decision*.json` | 查决策中的原因和实际动作，并结合该轮记录确认结果。 |
| [运行环境修复](runtime-v2/README.md) | `recipes/` 下的补丁、Dockerfile、启动脚本；[历史验证索引](runtime-v2/runtime-environment-index.json) | 看实际修改和探测条件，区分“服务可启动”与“漏洞已触发”。 |
| [源码插入实验](source-runtime/README.md) | `files/` 下的装配脚本和补丁；[案例索引](source-runtime/CASE_INDEX.json) | 保留 `source_inserted` 和对照组标签，不当成未经修改的原版漏洞复现。 |

以下是四个读法示例，不是新执行的构建结果。历史命令需要原项目、对应版本及依赖；本轮没有运行这些命令。

## HAPI FHIR：补 Git 元数据，同时保留测试 JAR 的生成

[历史说明](codeql-compile/fleet-138-v1/v8_hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91/historical-receipt.json) · [Dockerfile](codeql-compile/fleet-138-v1/v8_hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91/Dockerfile)

- 问题：源码压缩包没有 `.git`，构建插件需要版本信息；`maven.test.skip=true` 又跳过了后续模块依赖的测试 JAR。
- 修法：用确定性的 Git shim 提供已核对的 revision；改用 `-DskipTests`，不运行测试，但保留所需的测试编译和打包步骤。
- 关键命令：`mvn --offline --batch-mode -e -DskipTests clean package`。
- 历史结果：记录中的 12 个 reactor 项目构建通过。这证明的是编译环境，不是新 CodeQL 数据库或运行时漏洞确认。

## Spring Boot Admin：固定工具链，并处理离线依赖

[历史说明](codeql-compile/fleet-138-v1/v8_codecentric__spring-boot-admin_CVE-2022-46166_2.6.9/historical-receipt.json) · [Dockerfile](codeql-compile/fleet-138-v1/v8_codecentric__spring-boot-admin_CVE-2022-46166_2.6.9/Dockerfile)

- 问题：Maven 3.5 不满足前端插件要求；JDK 21 与旧 Lombok 不兼容。另一次离线重跑失败，是因为依赖只存在于临时 BuildKit cache 中。
- 修法：固定 Maven 3.8.8 与 JDK 8；用项目的 `noNpm` profile 编译生产 Java 模块；将核对过的 Maven 依赖放入构建环境，而不是只依赖临时 cache。
- 命令要点：`-PnoNpm`、明确的 `-pl` 模块列表，以及 `org.apache.maven.plugins:maven-compiler-plugin:3.9.0:compile`。完整命令见说明的 `recipe.build_command`，其中包含清理步骤，不宜直接在有未保存工作的目录执行。
- 历史结果：191 个非示例生产 Java 源文件生成 272 个 class；不代表前端、示例程序和完整发行包都完成构建。

## Flink：暂时排除被 npm 和 S3 阻塞的模块

[原始短注](legacy-builds/recipes/apache__flink/17/build-notes.md) · [Dockerfile](legacy-builds/recipes/apache__flink/17/Dockerfile)

- 问题：`flink-runtime-web_2.11` 遇到 npm 完整性校验问题，`flink-connector-kinesis_2.11` 依赖的 S3 仓库不可达。
- 修法：构建其余模块；配方使用 `-DskipTests package`，并通过 `-pl '!org.apache.flink:flink-runtime-web_2.11,!org.apache.flink:flink-connector-kinesis_2.11'` 排除这两个模块。
- 范围：这是有明确缺口的构建方案，不是完整 Flink 环境的修复证明。如果需要这两个模块，短注要求补齐可用 npm cache 或 S3 mirror。

## Hutool：保留可以直接核对的编译配置改动

[实际补丁](runtime-v2/recipes/u143-054-dromara__hutool-cve-2018-17297/attempts/01-initial/workspace/hutool/__preserved_git_diff.patch) · [启动脚本](runtime-v2/recipes/u143-054-dromara__hutool-cve-2018-17297/attempts/01-initial/workspace/start.sh)

- 改动：根 `pom.xml` 的 Maven compiler `source`、`target` 从 `7` 改成 `8`。补丁能确认改了什么，但公开材料没有初始编译报错，不能据此断言某个具体错误原因。
- 检查：启动脚本等待 `/health` 返回 `OK`；历史索引记录 mechanical/audit passed。
- 范围：这是历史 readiness 记录，不是本轮重新启动或漏洞验证。配方使用的预构建 JAR 未随该配方发布；保存修法不等于保存完整运行环境。

## 后续整理标准

优先保留已有说明；缺少说明时，从现有脚本、补丁和记录补出关键步骤，并注明未知项。无需为了每个 fix 再上传整套依赖和日志，也不需要为此新建私有仓库。服务器原文件未删除，现有归档也未删减；以后若要清理大文件，再单独决定。
