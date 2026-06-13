# 功能需求迭代提示词

> 复制下方 **「Agent 提示词」** 整段到 Cursor Agent。
> 来源：第 1 轮 `/不满意原因` 审查（gha-lint 扫描路径、schema、matrix 警告、策略语义缺口）。
> 每轮迭代后更新「变更记录」。

---

## 变更记录

| 轮次 | 日期 | 范围 | 状态 |
|------|------|------|------|
| 1 | 2026-06-14 | scan --path 语义、GHA schema 子集、matrix 占位 warning、concurrency/secrets_naming 策略、README | 待做 |

---

## Agent 提示词（复制从这里开始）

**项目路径**：`/Users/ext.feixuan3/Desktop/solo/pro_11`
**栈**：Python 3.11 + Typer + PyYAML + Rich；静态分析，不依赖 GitHub API

### 核心需求（不变）

构建可扫描 `.github/workflows` 的 GitHub Actions 工作流 Lint 工具：按自研 `policy.yaml` 执行 pin SHA、禁止 curl|bash、timeout、permissions 最小化、secrets 命名、forbidden actions、reuse workflow 版本固定等规则；支持 CLI（`scan` / `init-policy` / `explain`）、自举 GitHub Action、pre-commit hook；输出终端表格、JSON、SARIF、GitHub PR 注释（`::error file=,line=`）；解析时用 PyYAML，内置 GitHub Actions schema 子集；matrix 不展开，仅记 warning。

### 已完成（勿重复改，除非回归）

- 项目骨架：`pyproject.toml`、src 布局、`gha-lint` CLI 入口
- 数据模型：`Finding`、`WorkflowModel`、`Job`、`Step`、`Severity`
- YAML 解析器（带行号追踪）、Policy 加载器
- 7 条规则主体：`actions_must_pin_sha`、`forbid_curl_pipe_bash`、`require_timeout_minutes`、`permissions_default_read`、`secrets_naming`、`forbidden_actions`、`require_concurrency`
- 报告格式：table / json / sarif / github annotation
- CLI：`scan`、`init-policy`、`explain`、`list-rules`、`--version`
- 自举工作流 `.github/workflows/gha-lint.yml`、composite `action.yml`、`.pre-commit-hooks.yaml`
- 41 条 pytest 测试（当前全绿）

### P0 — 必须修复

#### 1. `scan --path` 与需求示例不一致

**问题**：需求示例为 `gha-lint scan --path .github/workflows`，当前实现把 `--path` 当仓库根，再拼 `.github/workflows/`。直接传 workflows 目录会扫不到任何文件。

**要求**：
- `--path` 同时支持：① 仓库根（现有行为）；② `.github/workflows` 目录；③ 单个 `.yml`/`.yaml` 文件（已有则保持）
- 传 workflows 目录时直接 glob 该目录下 `*.yml`/`*.yaml`，不要再嵌套一层
- 补 pytest 覆盖三种 path 语义

#### 2. 缺少「GitHub Actions schema 子集」校验

**问题**：架构要求内置 GHA schema 子集做静态校验，当前只有 YAML 解析 + 规则，无结构合法性检查。

**要求**：
- 新增轻量 schema 校验模块（内置 dict/规则，不引外网）：至少校验 workflow 顶层必填键（`on`、`jobs`）、`jobs` 为 mapping、每个 job 要么 `runs-on`+`steps` 要么 `uses`（reuse workflow）
- 校验失败产出 `Finding`，ruleId 如 `workflow_schema`，默认 severity `error` 或 `warn`（policy 可配）
- 无效 YAML 结构仍应给出可读错误，不 silent skip

#### 3. matrix 占位 warning 未实现

**问题**：需求要求「matrix 展开占位不展开，仅记 warning」，解析器读了 `strategy.matrix` 但不产出任何 finding。

**要求**：
- 检测到 job 含 `strategy.matrix` 时，产出 info/warn 级 finding（ruleId 如 `matrix_not_expanded`），说明静态分析未展开 matrix、部分规则可能对 matrix job 不完整
- 不实际展开 matrix；仅提醒
- 补 pytest

### P1 — 策略语义与文档补齐

#### 4. `require_concurrency` 误报所有 workflow

**问题**：规格写「生产 deploy workflow」才需要 concurrency，当前对所有缺 concurrency 的 workflow 报 info。

**要求**：
- 仅对「疑似 deploy/生产」workflow 触发：启发式可组合——workflow 名 / job 名 / `on.push.branches` 含 `main`/`production`、或文件名含 `deploy`/`release`/`prod`（policy 可配关键词列表）
- 普通 CI（如 `ci.yml`、`pull_request`）不应被 concurrency 规则骚扰
- 补测试：deploy 缺 concurrency 应报；普通 CI 缺 concurrency 不报

#### 5. `secrets_naming` 策略格式与 spec 不一致

**问题**：spec 示例 `secrets_naming: ^[A-Z0-9_]+$` 表示规则值即正则；当前实现把正则放顶层 `secrets_naming_pattern`，`rules.secrets_naming` 只表 severity。

**要求**：
- 兼容两种写法：① `rules.secrets_naming: warn` + 顶层 `secrets_naming_pattern`（保持）；② `rules.secrets_naming: '^[A-Z0-9_]+$'` 或带 severity 的 dict 内嵌 pattern
- `init-policy` 输出与 spec 一致的示例格式
- 补 policy 解析 roundtrip 测试

#### 6. README 为空

**问题**：`README.md` 仅一行 `# pro_11`，用户无法知道安装、scan、policy、CI 接入方式。

**要求**：
- 写 README：安装（venv + `pip install -e .`）、`gha-lint scan` 示例、policy.yaml 字段说明、`action.yml` / pre-commit 用法
- 注明 `--path` 三种传参方式

#### 7. pre-commit 无法指定项目 policy（可选本轮）

**问题**：`.pre-commit-hooks.yaml` 固定 `--format table --fail-on error`，未传 `--policy policy.yaml`，与仓库根 policy 可能不一致。

**要求**：
- hook 文档或 args 支持通过 pre-commit `args` 覆盖 `--policy`；或在 README 说明如何配置

### 验收清单

| 项 | 命令 / 动作 | 期望 |
|----|-------------|------|
| path=workflows 目录 | `gha-lint scan --path .github/workflows --policy policy.yaml` | 能扫到 workflow，不报「找不到文件」 |
| path=仓库根 | `gha-lint scan --path . --policy policy.yaml` | 行为与现有一致 |
| schema 校验 | 故意写缺 `jobs` 的 yml 到 fixtures，跑 scan | 产出 schema 相关 finding |
| matrix warning | fixture 含 `strategy.matrix` 的 job | 产出 matrix 占位 warning/info |
| concurrency 范围 | deploy 型 vs 普通 CI 各一 fixture | 仅 deploy 型缺 concurrency 时报 |
| secrets_naming 双格式 | policy 用 `secrets_naming: '^[A-Z0-9_]+$'` | 规则生效，坏命名被 warn |
| 回归 | `pytest -q` && `ruff check src/ tests/` | 全绿 |
| 自举 | `gha-lint scan --path . --policy policy.yaml --format github` | 项目自身 workflow 无 error |

### 工作方式

1. 先读 `src/gha_lint/parser.py`、`cli.py`、`rules.py`、`policy.py`，再改；最小 diff，别重写已通过的 7 条规则
2. 新能力各补 pytest；改 path 语义时别破坏单文件 scan
3. 总结分：**已修复 / 未修复** 列表即可

## Agent 提示词（复制到这里结束）
