# gha-lint Refactor Log

本文件记录 2025Q1 对 `gha-lint` 核心源码进行的一次大规模包结构与职责拆分重构，便于 code review 理解动机与验证方式。

## 1. 总体目标

- 让 `rules.py` 从单文件（>600 行，9 条规则耦合）拆成可扩展的规则包。
- 让 `cli.py` 真正只负责 Typer 参数与调用编排，不承担路径解析。
- 让 `schema.py` / `formatter.py` 内部结构清晰，对外 API 不变。
- 补齐模块 docstring 与公共函数 type hints，不改业务逻辑。
- 所有 71 条 pytest 保持全绿，`ruff check` 无 error。

## 2. 逐项改动

### 2.1 拆分 `rules.py` 为规则包

**改动前：**
- `src/gha_lint/rules.py` 单文件包含：BaseRule、RuleInfo、RuleEngine、explain_rule、9 条规则类、共享 regex 常量。
- 任何一条规则改动都会影响整个文件，review 成本高。

**改动后：**
- 新建 `src/gha_lint/rules/` 目录：
  - `base.py`：`RuleInfo`、`BaseRule`、`SHA_PATTERN`、`CURL_BASH_PATTERN`、`SECRET_REF_PATTERN`、`WRITE_ALL_SCOPES` 等共享常量。
  - `registry.py`：`ALL_RULES` 列表、`get_rule_by_id`、`explain_rule`、`RuleEngine`（evaluate / evaluate_all）。
  - 每条规则独立文件（共 9 个）：
    - `actions_must_pin_sha.py`
    - `forbid_curl_pipe_bash.py`
    - `require_timeout_minutes.py`
    - `permissions_default_read.py`
    - `secrets_naming.py`
    - `forbidden_actions.py`
    - `require_concurrency.py`
    - `schema_validation.py`
    - `matrix_not_expanded.py`
  - `__init__.py`：重导出 `RuleEngine` / `explain_rule` / `ALL_RULES` / 各规则类，保持 `from gha_lint.rules import RuleEngine` 等旧路径完全兼容。

**保持不变：**
- 所有 `ruleId` 文案与 `message` 文案。
- 对外导入路径与类/函数签名。

### 2.2 提取扫描路径逻辑到 `scan_paths.py`

**动机：**
- 原 `WorkflowParser` 同时承担「三种 path 语义解析（仓库根 / workflows 目录 / 单文件）」与「YAML 解析」，违反单一职责。
- `cli.py` 的 `scan` 命令还手工分支 `path.is_file()`，与 parser 重复。

**改动后：**
- 新建 `src/gha_lint/scan_paths.py`：
  - `resolve_workflow_files(path: Path) -> list[Path]`：统一处理三种路径语义。
  - `describe_path_scope(path: Path) -> str`（辅助，未被外部使用）。
- `WorkflowParser` 内部调用 `resolve_workflow_files`，不再自己实现 glob/分支。
- `cli.py` 的 `scan` 命令直接走 `parser.find_workflow_files()` + `parser.parse_file()`，删除 `path.is_file()` 分支，逻辑与 `parse_all()` 统一。

### 2.3 轻量整理 `schema.py`

**动机：**
- `schema.py` 原 376 行，超出自定义阈值 300 行；常量集合与校验逻辑混杂。

**改动后：**
- 新建 `src/gha_lint/schema_defs.py`：
  - `KNOWN_TOP_LEVEL_KEYS`、`KNOWN_JOB_KEYS`、`KNOWN_STEP_KEYS`、`VALID_ON_EVENTS`（改为 `frozenset`，去重）。
  - `SchemaIssue` dataclass。
- `src/gha_lint/schema.py` 保留 `WorkflowSchemaValidator` 与对外入口 `validate_workflow_schema`，常量从 `schema_defs` 导入。
- `schema.py` 对外 API（类名、函数名、ruleId、message）完全不变。

### 2.4 `formatter.py` 输出策略化

**改动前：**
- 四种格式（table / json / sarif / github）都以 `Formatter._format_xxx` 静态方法耦合在一个类里。

**改动后：**
- 抽出四个独立顶层函数：
  - `format_table(findings, console) -> str`
  - `format_json(findings) -> str`
  - `format_sarif(findings) -> str`
  - `format_github(findings) -> str`
- 新增 `_sort_findings` 辅助函数，避免三处重复按 (file, line) 排序。
- `Formatter.format()` 仍作为对外唯一入口，只是做路由分发，接口完全不变。

### 2.5 类型与文档补齐

- 为每个模块补顶部 docstring，说明职责：
  - `__init__.py`、`models.py`、`parser.py`、`policy.py`、`scan_paths.py`、`schema.py`、`schema_defs.py`、`scoring.py`、`formatter.py`、`cli.py`、`dependency.py`、`rules/*.py`。
- 公共函数 / 方法补 docstring 与 type hints（未改业务逻辑）。
- 例如 `models.py` 里每个 dataclass、`Severity.to_int`、`Finding.to_dict` 等。

## 3. 兼容性保证

- `from gha_lint.rules import RuleEngine, explain_rule, ActionsMustPinShaRule, ...` 仍然可用。
- `from gha_lint.schema import WorkflowSchemaValidator, validate_workflow_schema` 仍然可用。
- `Formatter.format(findings, fmt, console)` 签名与行为不变。
- 所有 pytest 断言未修改，只是代码移动位置。

## 4. 验证方式

本地已完成以下验证，code review 时可复现：

```bash
# 1. 安装当前版本（src-layout）
source .venv/bin/activate
pip install -e "."

# 2. 全量 pytest（71 条）
pytest -q
# 期望：71 passed

# 3. ruff lint
ruff check src tests
# 期望：0 errors

# 4. CLI 冒烟
gha-lint --help
gha-lint scan --path . --format table --score
gha-lint list-rules
gha-lint explain actions_must_pin_sha
gha-lint graph --path . --format mermaid
```

## 5. Review Checklist

- [ ] rules 包 `__init__.py` 的重导出完整，没有遗漏旧 API。
- [ ] `scan_paths.py` 三种路径（仓库根 / workflows 目录 / 单文件）语义与原实现一致。
- [ ] `schema.py` 的 ruleId / message 文案与旧版完全相同。
- [ ] `formatter.py` 四格式输出字节级与旧版等价（可通过 `pytest tests/test_formatter.py` 验证）。
- [ ] ruff 与 pytest 全绿。
