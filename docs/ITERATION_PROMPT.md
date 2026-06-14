# 功能需求迭代提示词

> 复制下方 **「Agent 提示词」** 整段到 Cursor Agent。
> 来源：第 2 轮 `/不满意原因` 审查（依赖图真实连边、scan 接循环检测、matrix 级别、策略/README 缺口）。
> 每轮迭代后更新「变更记录」。

---

## 变更记录

| 轮次 | 日期 | 范围 | 状态 |
|------|------|------|------|
| 1 | 2026-06-14 | scan --path、schema 子集、matrix warning、concurrency/secrets_naming、README | 部分完成 |
| 2 | 2026-06-14 | 依赖图 callee 解析、scan 接 cycle、matrix→warn、策略语义、README、合规分 JSON | 待做 |

---

## Agent 提示词（复制从这里开始）

**项目路径**：`/Users/ext.feixuan3/Desktop/solo/pro_11`
**栈**：Python 3.11 + Typer + PyYAML + Rich；`src/gha_lint/` 已拆包（`rules/`、`scan_paths.py`、`schema_defs.py`）

### 核心需求（不变）

GitHub Actions 工作流 Lint：按 `policy.yaml` 扫 `.github/workflows`，规则含 pin SHA、curl|bash、timeout、permissions、secrets、forbidden actions、schema 子集、matrix 占位提示；支持 reusable workflow **依赖图 + 循环检测**、org 私有 action **allowlist**、**0–100 合规分**；CLI `scan` / `graph` / `init-policy` / `explain`；输出 table / json / sarif / github 注释。

### 已完成（勿重复改，除非回归）

- **路径**：`scan_paths.resolve_workflow_files` 支持仓库根 / `.github/workflows` / 单文件；`cli scan` 经 `WorkflowParser` 使用
- **Schema**：`schema_defs.py` + `schema.py` + `SchemaValidationRule`；ruleId/message 勿随意改文案
- **规则包**：`src/gha_lint/rules/`（9 条规则 + `base.py` + `registry.py`）；`from gha_lint.rules import RuleEngine` 路径不变
- **Formatter**：四格式独立函数 + `Formatter.format` 路由
- **Allowlist（部分）**：`policy.allowed_actions` / `allowed_orgs` 仅豁免 `actions_must_pin_sha`
- **合规分（部分）**：`scan --score` 终端显示 0–100 + 等级
- **依赖图（部分）**：`dependency.py` + `gha-lint graph`（json/mermaid/table）；`cycle_findings_from_graph()` 已写但未接入 scan
- **测试**：71 条 pytest 全绿；`docs/REFACTOR_LOG.md` 已有

### P0 — 必须修复

#### 1. 依赖图无法连接本地 workflow，环检测对真实 YAML 无效

**问题**：`job.uses` 存远程引用串（如 `org/repo/.github/workflows/b.yml@sha`），caller 用本地绝对路径，边两端节点 id 不一致，`detect_cycles()` 检不出同仓库 a→b→a。

**要求**：
- 在 `dependency.py`（或 `scan_paths` 旁新模块）增加 **callee 解析**：同 repo 的 `uses` 映射到 `.github/workflows/` 下本地文件路径（支持 `owner/repo/.github/workflows/x.yml@ref` 与相对路径若存在）
- 解析失败时保留原 ref 字符串，不 silent
- `graph` 命令输出 caller→**本地文件** 边；Mermaid/JSON 同步
- 补 **端到端 pytest**：temp repo 内 a.yml 调 b.yml、b.yml 调 a.yml → `detect_cycles()` ≥1

#### 2. 循环依赖未进入 `scan` 结果

**问题**：`cycle_findings_from_graph()` 存在，但 `cli scan` / `RuleEngine` 未调用；PR 阻断链路接不上。

**要求**：
- `scan` 在 `evaluate_all` 之后（或规则引擎内）构建全量图，合并 `reusable_cycle` findings（error）
- 可选：policy 规则 `reusable_cycle: error`；默认 error
- 环 finding 参与 exit code 与 `--score` 扣分
- 补集成测试：`scan` 对含环 fixture exit 1

#### 3. `matrix_not_expanded` 级别应为 warn

**问题**：需求写「matrix 不展开，仅记 **warning**」，当前默认与 policy 均为 **info**。

**要求**：
- `MatrixExpandWarningRule` 默认 severity → `WARN`
- `policy.py` DEFAULT、`policy.yaml`、`init-policy` 输出改为 `matrix_not_expanded: warn`
- 更新相关 pytest 断言

### P1 — 策略、报告与文档

#### 4. `require_concurrency` 误报普通 CI

**要求**：仅对 deploy/生产类 workflow 触发（文件名/分支/on 事件关键词，policy 可配 `deploy_keywords`）；普通 `ci.yml` / `pull_request` 不报。

#### 5. `secrets_naming` 双格式 policy

**要求**：兼容 `rules.secrets_naming: '^[A-Z0-9_]+$'`（规则值即正则）与现有顶层 `secrets_naming_pattern`；`init-policy` 示例与 spec 一致。

#### 6. allowlist 范围与合规分输出

**要求**：
- 文档或实现：`allowed_orgs` 是否也应豁免 `forbidden_actions`（至少 README/policy 注释写清当前只豁免 pin SHA）
- `scan --format json` 输出增加 `score` / `grade` / `breakdown` 字段（`--score` 时或始终附带）
- 可选：`policy.yaml` 配置 `score_weights`

#### 7. schema 子规则 `explain` 不可用

**要求**：`gha-lint explain schema_missing_jobs` 等子 ruleId 能返回说明，或在 explain 时提示归属 `schema_validation` 并给摘要；勿改现有 finding 的 ruleId 文案。

#### 8. README 为空

**要求**：写安装、`scan`/`graph`/`--score` 示例、policy 字段（含 allowlist）、三种 `--path`、pre-commit 如何传 `--policy`。

### 验收清单

| 项 | 命令 / 动作 | 期望 |
|----|-------------|------|
| 本地环检测 | fixture a↔b 跑 `gha-lint graph --path .` | 显示 cycle ≥1 |
| scan 接环 | 同上跑 `gha-lint scan --policy policy.yaml` | 含 `reusable_cycle` error，exit 1 |
| matrix 级别 | fixture 含 matrix 跑 scan | severity 为 warn |
| path 回归 | `gha-lint scan --path .github/workflows` | 仍能扫到文件 |
| 合规分 JSON | `gha-lint scan --format json --score` | JSON 含 score 字段 |
| 全量回归 | `pytest -q && ruff check src tests` | 全绿 |
| 自举 | `gha-lint scan --path . --policy policy.yaml` | 自身 workflow 无 error |

### 工作方式

1. 先读 `dependency.py`、`cli.py`、`rules/registry.py`、`policy.py`；**最小 diff**，别破坏 rules 包结构与 71 条已有测试
2. 重构后只删/移目标代码；**不要**误删 `dependency.py` / `policy.py` 字段；改完即 `pip install -e . && pytest -q`
3. 更新 `docs/REFACTOR_LOG.md` 追加本轮条目
4. 总结分：**已修复 / 未修复** 列表

## Agent 提示词（复制到这里结束）
