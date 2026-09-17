# JSON 脱敏网关（JSON Masking Gateway）

供内部系统交换数据时使用的 JSON 脱敏网关 API。技术栈：Python 3.12 · FastAPI · PostgreSQL 16 · SQLAlchemy 2。

核心能力：

- **策略管理**：草稿可编辑；发布后生成**不可变版本**；发布以 `revision` 做 CAS，并发冲突返回 `409 REVISION_CONFLICT`。
- **规则引擎**：路径仅支持 `$`、`.name`、`[n]`、`[*]`；全部命中先在**原始文档**上计算；同一节点按声明顺序只取首条（其余记 `shadowed`）；数组删除按索引**降序**执行；祖先被删除后，后代命中记为 `skipped`。
- **动作**：`delete`（删除）、`mask`（局部遮盖）、`tokenize`（基于服务端密钥的确定性 HMAC-SHA256 令牌化，同一值恒定映射同一 token）。
- **幂等转换**：转换必须携带策略版本与幂等键，键仅在 `(策略, 版本)` 内有效。首次请求保存输入的 JCS 摘要与最终响应；同键同摘要的并发请求只执行一次，其余等待并**回放**；同键异摘要返回 `409 IDEMPOTENCY_KEY_CONFLICT`。提交前失败会回滚幂等占位，同键可重试。结果与审计在**同一事务**提交，回放不产生新审计。
- **数据最小化**：日志、审计、异常响应与追踪只记录请求 ID、策略版本、输入摘要与错误码，绝不包含原始值或脱敏后的敏感值。

---

## 1. 快速启动（Docker Compose 一键启动）

```bash
docker compose up --build
```

- API: http://localhost:8000 （交互文档 http://localhost:8000/docs ）
- PostgreSQL: `localhost:5432`（用户/密码/库均为 `gateway`，仅用于本地开发）

首次启动时 API 会等待数据库就绪并自动建表。健康检查：`GET /healthz`。

## 2. 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+psycopg2://gateway:gateway@db:5432/gateway` | SQLAlchemy 连接串 |
| `MASKING_HMAC_KEY` | `dev-only-insecure-key-change-me` | **令牌化 HMAC 的服务端密钥**。生产必须覆盖（建议 ≥32 字节随机值，经 `.env` 或密钥管理注入）。使用默认值时启动日志会告警。密钥轮换会使历史 token 无法复现 |
| `IDEMPOTENCY_LOCK_TIMEOUT_MS` | `15000` | 同键并发时等待前序事务提交的最长毫秒数，超时返回 `503 IDEMPOTENCY_WAIT_TIMEOUT` |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `DB_STARTUP_RETRIES` / `DB_STARTUP_RETRY_DELAY_SECONDS` | `30` / `1` | 启动时等待数据库的重试参数 |

本地覆盖示例：`MASKING_HMAC_KEY=$(openssl rand -hex 32) docker compose up --build`，或写入 `.env`（compose 自动读取，`.env` 已在 `.gitignore` 中）。

## 3. API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/v1/policies` | 创建策略（可带初始草稿规则） |
| `GET` | `/v1/policies` | 列出策略 |
| `GET` | `/v1/policies/{name}` | 策略详情（含草稿与已发布版本号） |
| `PUT` | `/v1/policies/{name}/draft` | 整体替换草稿规则（校验通过才保存） |
| `POST` | `/v1/policies/{name}/publish` | 发布草稿为不可变版本（CAS） |
| `GET` | `/v1/policies/{name}/versions` | 版本列表 |
| `GET` | `/v1/policies/{name}/versions/{version}` | 版本详情（不可变规则快照） |
| `POST` | `/v1/policies/{name}/transform` | 对文档执行脱敏转换（幂等） |
| `GET` | `/healthz` | 健康检查 |

### 3.1 创建策略并发布

```bash
# 创建策略（草稿）
curl -s -X POST localhost:8000/v1/policies -H 'Content-Type: application/json' -d '{
  "name": "pii",
  "rules": [
    {"id": "r1", "path": "$.users[*].ssn",  "action": "tokenize"},
    {"id": "r2", "path": "$.users[*].name", "action": "mask", "params": {"keep_first": 1}},
    {"id": "r3", "path": "$.debug",         "action": "delete"}
  ]
}'

# 修改草稿（整体替换）
curl -s -X PUT localhost:8000/v1/policies/pii/draft -H 'Content-Type: application/json' \
  -d '{"rules": [{"id": "r1", "path": "$.users[*].ssn", "action": "tokenize"}]}'

# 发布：携带期望的 revision 做 CAS；冲突返回 409 REVISION_CONFLICT
curl -s -X POST localhost:8000/v1/policies/pii/publish -H 'Content-Type: application/json' \
  -d '{"expected_revision": 0}'
# => {"name":"pii","version":1,"revision":1,...}
```

发布流程：客户端先 `GET /v1/policies/{name}` 读取当前 `revision`，再以 `expected_revision` 提交；并发发布只有一个成功，其余收到 409 后应重新读取再试。已发布版本不可修改，只能发布新版本（版本号 = 新 revision，从 1 开始递增）。

### 3.2 转换（幂等）

```bash
curl -s -X POST localhost:8000/v1/policies/pii/transform \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: req-0001' -d '{
    "version": 1,
    "document": {
      "users": [
        {"name": "ann", "ssn": "111-22-3333"},
        {"name": "bob", "ssn": "444-55-6666"}
      ],
      "debug": {"trace": true}
    }
  }'
```

幂等键可放在请求体 `idempotency_key` 字段或 `Idempotency-Key` 请求头（二者至少其一，body 优先）。响应：

```json
{
  "policy": "pii",
  "version": 1,
  "request_id": "9f1c…",
  "replayed": false,
  "result": {
    "users": [
      {"name": "a**", "ssn": "tok_<hmac-sha256-hex>"},
      {"name": "b**", "ssn": "tok_<hmac-sha256-hex>"}
    ]
  },
  "trace": [
    {"rule_id": "r1", "rule_index": 0, "path": "$.users[0].ssn", "action": "tokenize", "status": "applied"},
    {"rule_id": "r1", "rule_index": 0, "path": "$.users[1].ssn", "action": "tokenize", "status": "applied"},
    {"rule_id": "r2", "rule_index": 1, "path": "$.users[0].name", "action": "mask", "status": "applied"},
    {"rule_id": "r3", "rule_index": 2, "path": "$.debug", "action": "delete", "status": "applied"}
  ]
}
```

幂等语义：

- 键作用域为 `(策略, 版本, 键)`；发布新版本后同一键可重新使用。
- 首次请求在事务内写入 `in_progress` 占位；同键同摘要的并发请求在唯一约束上等待，前序提交后读取已存响应**回放**（`replayed: true`，`request_id` 为当前请求的，不新增审计）。
- 同键但输入的 JCS 摘要不同 → `409 IDEMPOTENCY_KEY_CONFLICT`。
- 执行在提交前失败 → 占位随事务回滚，同键可立即重试（被阻塞的并发请求会自动成为新的执行者）。
- 输入摘要 = 对 `document` 做 RFC 8785 JCS 规范化后的 SHA-256。

## 4. 规则语法与执行语义

### 4.1 路径语法（受限 JSONPath）

| 语法 | 含义 |
| --- | --- |
| `$` | 文档根（后须至少跟一段） |
| `.name` | 对象成员，名称须匹配 `[A-Za-z_][A-Za-z0-9_]*` |
| `[n]` | 数组下标（非负整数） |
| `[*]` | 数组全部元素（仅作用于数组） |

### 4.2 动作

| action | params | 行为 |
| --- | --- | --- |
| `delete` | 无 | 删除对象键或数组元素 |
| `mask` | `keep_first`(默认0)、`keep_last`(默认0)、`mask_char`(默认`*`，单字符) | 字符串：保留首尾、中间遮盖（长度 ≤ 保留数则全遮盖，遮盖后长度不变）；数值/布尔/null：替换为 6 个遮盖符；对象/数组：跳过并记 `skipped/unsupported_target_type` |
| `tokenize` | 无 | 标量 → `tok_` + HMAC_SHA256(密钥, JCS(值))，确定性；对象/数组：跳过并记 `skipped` |

### 4.3 执行顺序与轨迹状态

1. 全部规则的全部命中在**原始文档**上计算（命中路径为具体路径，如 `$.users[2].ssn`）。
2. 同一节点被多条规则命中时，仅**声明顺序首条**生效，其余命中轨迹记 `shadowed`。
3. 祖先节点被删除时，其后代命中记 `skipped`（`reason: ancestor_deleted`）。
4. 先按声明顺序应用改值类动作（mask/tokenize），再执行删除；**数组元素删除按索引降序**，保证基于原文档计算的下标仍然有效。
5. 轨迹状态：`applied` / `shadowed` / `skipped`（含 `reason`）/ `no_match`（规则无任何命中）。

规则校验在保存草稿与发布时进行：规则 `id` 须匹配 `^[A-Za-z0-9_-]{1,64}$` 且唯一；`path` 须符合语法；`mask` 参数仅允许上表所列键；`delete`/`tokenize` 不接受 `params`。

## 5. 错误码

错误响应统一为 `{"error": {"code", "message", "request_id"}}`（422 校验错误另含脱敏后的 `fields`，仅字段位置与类型）：

| code | HTTP | 含义 |
| --- | --- | --- |
| `POLICY_NOT_FOUND` / `VERSION_NOT_FOUND` | 404 | 策略 / 版本不存在 |
| `POLICY_EXISTS` | 409 | 策略名已存在 |
| `REVISION_CONFLICT` | 409 | 发布 CAS 冲突（`expected_revision` 过期） |
| `IDEMPOTENCY_KEY_CONFLICT` | 409 | 同键异摘要 |
| `IDEMPOTENCY_WAIT_TIMEOUT` | 503 | 等待同键前序请求超时，可重试 |
| `INVALID_RULES` | 422 | 规则校验失败 |
| `INVALID_DOCUMENT` | 422 | 文档含无法规范化的值（如 NaN、孤立代理项） |
| `VALIDATION_FAILED` | 422 | 请求体校验失败 |
| `TRANSFORM_FAILED` / `INTERNAL_ERROR` | 500 | 执行失败（占位已回滚，可同键重试） |

## 6. 安全与可观测性约束

- 日志为 JSON 结构化输出，仅含：请求 ID、方法/路由、状态码、策略名、版本、输入摘要、错误码。**不记录**请求/响应体、原始值、脱敏值与 HMAC 密钥；uvicorn access log 已关闭。
- 审计表 `audit_events` 与转换结果同事务提交，仅含请求 ID、策略、版本、输入摘要、结果与错误码；回放与校验失败不新增审计（执行失败在回滚后单独事务补记错误审计）。
- 未处理异常统一返回 `500 INTERNAL_ERROR`，异常堆栈不写入日志（可能含值），仅记录异常类型级别的事件。
- 令牌化密钥仅来自环境变量，不出现在任何响应、日志或审计中。

## 7. 本地开发与测试

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # 含 httpx（TestClient）与 pytest

# 纯逻辑单测（路径/JCS/脱敏引擎，无需数据库）
python -m unittest discover -s tests

# 集成测试（需要 PostgreSQL；未安装 httpx 或数据库不可达时自动跳过）
export TEST_DATABASE_URL='postgresql+psycopg2://gateway:gateway@localhost:5432/gateway'
python -m unittest tests.test_api -v
```

项目结构：

```
app/
  main.py            # 应用入口、中间件、异常处理、启动建表
  config.py          # 环境变量配置
  db.py / models.py  # 引擎会话 / ORM 模型
  jcs.py             # RFC 8785 JCS 规范化与摘要
  paths.py           # 受限路径语法解析与匹配
  masking.py         # 规则校验与脱敏引擎
  tokenize.py        # HMAC 令牌化
  audit.py           # 审计写入
  errors.py          # 错误码与 ApiError
  logging_config.py  # JSON 日志
  routers/           # policies / transform 路由
  services/          # 策略与转换事务逻辑
tests/               # 单元 + 集成测试
```
