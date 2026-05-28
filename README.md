# AI-SEC-CHECK

> AI Security Assessment Platform v1.0.0  

---

## 目录

1. [产品概述](#1-产品概述)
2. [安装部署](#2-安装部署)
3. [快速启动](#3-快速启动)
4. [Web界面使用](#4-web界面使用)
5. [CLI命令行使用](#5-cli命令行使用)
6. [API接口参考](#6-api接口参考)
7. [六大扫描模块](#7-六大扫描模块)
8. [AI辅助功能](#8-ai辅助功能)
9. [配置参考](#9-配置参考)
10. [离线部署](#10-离线部署)
11. [常见问题](#11-常见问题)

---

## 1. 产品概述

AI-SEC-CHECK 是一个集成化AI安全评估平台，基于腾讯朱雀实验室的 AI-Infra-Guard 进行二次开发，整合了6大安全扫描能力：

| 模块 | 类别 | 扫描能力 | 实现方式 |
|------|------|----------|----------|
| 敏感词检测 | content_safety | 内容安全/敏感词识别 | Go 原生 (DFA/AC算法，8个内置词库) |
| 提示词注入检测 | model_safety | 提示词注入/越狱检测 | Go 原生 (32个内置探针，7大攻击类别) |
| 基础设施扫描 | infra | AI基础设施漏洞扫描 | Go 原生 (AI-Infra-Guard runner) |
| MCP安全扫描 | mcp | MCP配置安全审计 | Go 原生 (8大安全检查维度，10个规则ID) |
| API授权扫描 | api | API授权漏洞检测 | Go 原生 (Swagger/OpenAPI自动发现+接口解析+端点测试) |
| 限流熔断验证 | ratelimit | 限流/熔断能力验证 | Go 原生 (goroutine并发压测) |

### 核心特性

- **零依赖部署**：6大插件全部 Go 原生实现，纯静态编译，单文件部署
- **实时进度**：扫描过程实时显示进度条和当前操作（如"Testing endpoint [3/150]: GET /api/users"）
- **文件上传**：Web界面支持直接上传文件进行检测（MCP配置、文本文件等）
- **AI辅助**：接入大模型（vLLM/Ollama/TGI/OpenAI）提供智能分析，不可用时自动降级到规则模板
- **AI渗透对话**：在AI Chat中通过自然语言发起扫描（如"请检查 http://example.com 是否有API授权漏洞"），自动识别意图并执行
- **Swagger-UI智能发现**：autoswagger自动发现Swagger-UI页面，解析接口列表并逐一测试授权
- **插件架构**：6大扫描模块即插即用，支持动态启用/禁用
- **多接口**：Web界面 + REST API + CLI命令行
- **配置持久化**：AI配置保存到配置文件，重启后自动恢复

---

## 2. 安装部署

### 2.1 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 (amd64)，支持 Linux/macOS 交叉编译 |
| 磁盘空间 | ≥ 200MB |
| 网络 | 无需互联网连接（完全离线运行） |
| 外部依赖 | **无**（所有功能均为 Go 原生实现） |

### 2.2 使用离线包部署

1. 解压 `ai-sec-check-v1.0.0-windows-amd64.zip` 到目标目录
2. 运行 `install.bat` 检查环境
3. 运行 `start.bat` 启动服务

### 2.3 从源码构建

```bash
# 前置条件：Go 1.21+

# 克隆项目
git clone <repo-url> AI-SEC-CHECK
cd AI-SEC-CHECK

# 一键构建（编译+打包）
build.bat

# 或手动构建
set CGO_ENABLED=0
go build -ldflags "-X ai-sec-check/internal/options.version=v1.0.0 -s -w" -o ai-sec-check.exe ./cmd/cli
```

---

## 3. 快速启动

### 3.1 启动Web服务

```bash
# 默认启动（127.0.0.1:8088）
start.bat

# 自定义地址
start.bat 0.0.0.0:9090

# 或直接运行
ai-sec-check.exe webserver --server 127.0.0.1:8088
```

### 3.2 访问界面

浏览器访问 `http://host:8088/` 自动跳转到仪表盘。

| 页面 | URL | 说明 |
|------|-----|------|
| 仪表盘 | /sec/dashboard.html | 扫描统计概览 |
| 扫描中心 | /sec/scan.html | 发起扫描、实时进度、查看结果 |
| AI对话 | /sec/chat.html | AI安全助手对话（支持自然语言发起扫描） |
| AI配置 | /sec/config.html | AI模型配置管理 |

### 3.3 停止服务

```bash
stop.bat
```

---

## 4. Web界面使用

### 4.1 仪表盘（Dashboard）

访问 `/sec/dashboard.html`，显示扫描统计、AI状态、快捷操作和最近扫描记录。

### 4.2 扫描中心（Scan Center）

访问 `/sec/scan.html`

**操作步骤：**

1. **选择插件**：点击6个插件卡片中的一个，卡片高亮选中
2. **配置扫描参数**：
   - **Target Type**：下拉选择目标类型（不同插件支持不同类型）
     - sensitive_word: text / file（上传文件）
     - garak: url
     - infra_scan: url / ip / cidr
     - mcpsec: mcp_config（可粘贴JSON或上传文件）/ file（上传文件）
     - autoswagger: url
     - ratelimit: url
   - **Target**：输入目标内容或上传文件
   - **插件专属参数**：选择 garak 插件时显示额外参数（见下文）
   - **AI Analysis**：勾选后扫描完成自动触发AI分析
3. **发起扫描**：点击"Scan"按钮
4. **实时进度**：扫描过程中显示进度条和当前操作信息
   - autoswagger：`Testing endpoint [3/50]: GET /api/users`
   - garak：`Probe [5/32]: prompt_injection/system_override - BLOCKED`
   - ratelimit：`Load testing: 146 requests completed (15 req/s)`
   - infra_scan：`Found: Swagger UI at http://...`
5. **查看结果**：扫描完成后显示摘要统计和Findings表格（含Evidence列）

**Garak插件专属参数**（选择garak插件时自动显示）：

| 参数 | 类型 | 说明 |
|------|------|------|
| Model Name | 文本输入 | 目标模型名称，如 `qwen3:0.6b`、`gpt-4o-mini` |
| API Key | 密码输入 | 认证密钥，本地模型（Ollama/vLLM）可留空 |
| Probe Filter | 下拉选择 | 探针过滤：All Probes (32) / Prompt Injection (21) / DAN / Roleplay 等 |
| Concurrency | 下拉选择 | 并发数：1 / 3 / 5 / 10 |

**文件上传**：选择 `file` 类型时自动显示上传按钮，选择 `mcp_config` 时同时支持粘贴JSON和上传文件。

### 4.3 AI对话（AI Chat）

访问 `/sec/chat.html`，与AI安全助手对话。

**核心功能：**

- **自然语言发起扫描**：输入如"请检查 http://example.com 是否有API授权漏洞"，系统自动识别扫描意图并执行对应插件
- **中止请求**：发送消息后按钮变为红色中止按钮，点击可中止正在进行的请求
- **AI状态指示**：页面加载时自动检测AI连接状态
  - 🟢 AI Available：AI已启用且连接正常
  - 🟠 AI Unreachable：AI已配置但连接失败
  - 未配置AI时状态指示器自动隐藏

**支持的扫描意图关键词：**

| 意图 | 关键词示例 | 触发插件 |
|------|-----------|---------|
| API授权检测 | "api授权"、"swagger"、"未授权访问" | autoswagger |
| 基础设施扫描 | "基础设施"、"漏洞扫描"、"组件漏洞" | infra_scan |
| 越狱检测 | "越狱"、"提示注入"、"prompt inject" | garak |
| MCP安全 | "mcp安全"、"mcp配置"、"mcp漏洞" | mcpsec |
| 限流测试 | "限流"、"熔断"、"压测" | ratelimit |
| 敏感词检测 | "敏感词"、"内容安全"、"违禁词" | sensitive_word |

### 4.4 AI配置（AI Config）

访问 `/sec/config.html`，配置AI Provider、Base URL、API Key、Model，测试连接。配置保存后自动持久化到配置文件。

---

## 5. CLI命令行使用

```bash
# 查看版本
ai-sec-check.exe version

# 启动Web服务
ai-sec-check.exe webserver --server 127.0.0.1:8088

# 基础设施扫描
ai-sec-check.exe scan -t 192.168.1.0/24

# 列出所有插件
ai-sec-check.exe plugins list

# AI命令
ai-sec-check.exe ai status
ai-sec-check.exe ai analyze --limit 10
ai-sec-check.exe ai report --format markdown
ai-sec-check.exe ai config --enabled --base-url http://localhost:11434/v1 --model llama3
```

---

## 6. API接口参考

所有API基础路径：`http://host:8088/api/v1`

### 6.1 插件管理

| 端点 | 方法 | 说明 |
|------|------|------|
| /api/v1/plugins | GET | 列出所有插件 |
| /api/v1/plugins/scan | POST | 发起扫描（异步，返回scan_id） |
| /api/v1/plugins/scan-progress/:id | GET | 查询扫描进度 |
| /api/v1/plugins/upload | POST | 上传文件 |
| /api/v1/plugins/multi-scan | POST | 多插件扫描 |
| /api/v1/plugins/results | GET | 查询扫描结果列表 |
| /api/v1/plugins/results/:id | GET | 查询单条扫描结果 |
| /api/v1/plugins/stats | GET | 扫描统计 |

#### 发起扫描（异步）

```bash
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"autoswagger","target_type":"url","target":"http://example.com"}'
```

响应：
```json
{"status":0,"message":"scan started","data":{"scan_id":"abc123..."}}
```

#### 查询扫描进度

```bash
curl http://localhost:8088/api/v1/plugins/scan-progress/abc123...
```

响应：
```json
{
  "status": 0,
  "data": {
    "current": 45,
    "total": 150,
    "message": "Testing endpoint [68/150]: POST /api/users",
    "status": "running",
    "result": null
  }
}
```

当 `status` 为 `completed` 时，`result` 字段包含完整扫描结果。

#### 上传文件

```bash
curl -X POST http://localhost:8088/api/v1/plugins/upload \
  -F "file=@mcp-config.json"
```

响应：
```json
{
  "status": 0,
  "data": {
    "file_name": "mcp-config.json",
    "file_size": 256,
    "file_content": "{\"mcpServers\":{...}}"
  }
}
```

### 6.2 AI辅助

| 端点 | 方法 | 说明 |
|------|------|------|
| /api/v1/ai/status | GET | AI状态（含连接检测结果） |
| /api/v1/ai/analyze | POST | AI分析 |
| /api/v1/ai/report | POST | 生成报告 |
| /api/v1/ai/suggest-fix | POST | 修复建议 |
| /api/v1/ai/chat | POST | AI对话（支持扫描意图识别） |
| /api/v1/ai/config | PUT | 更新AI配置（自动持久化） |

#### AI状态检测

```bash
curl http://localhost:8088/api/v1/ai/status
```

响应：
```json
{
  "status": 0,
  "data": {
    "enabled": true,
    "connected": true,
    "provider": "openai",
    "model": "deepseek-r1:32b"
  }
}
```

- `enabled`: AI是否已启用
- `connected`: AI后端是否可达（通过 `/v1/models` 接口检测）

---

## 7. 六大扫描模块

### 7.1 敏感词检测（sensitive_word）

**类别**：content_safety | **实现**：Go 原生 | **依赖**：无

| 目标类型 | 说明 |
|----------|------|
| text | 直接输入待检测文本 |
| file | 上传文件进行检测 |

内置8个词库（政治、暴力、色情、反动、广告、贪腐、枪爆、民生），支持 DFA/AC 算法。

```bash
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"sensitive_word","target_type":"text","target":"This content contains violence"}'
```

### 7.2 提示词注入/越狱检测（garak）

**类别**：model_safety | **实现**：Go 原生 | **依赖**：需要可访问的LLM API端点

| 目标类型 | 说明 |
|----------|------|
| url | LLM API端点（如 http://localhost:11434） |

内置32个越狱探针，覆盖7大攻击类别：

| 类别 | 探针数 | 示例 |
|------|--------|------|
| prompt_injection | 21 | system_override, instruction_leak, context_escape, json_injection, indirect_injection, priority_instruction |
| dan | 2 | dan_classic, dan_jailbreak |
| roleplay | 2 | evil_advisor, fiction_writer |
| encoding | 2 | base64_instruction, rot13_bypass |
| privilege_escalation | 1 | admin_mode |
| data_exfiltration | 2 | training_data, pii_extraction |
| safety_bypass | 2 | academic_bypass, translation_bypass |

**可配置参数**（通过metadata传递）：

| 参数 | Key | 说明 |
|------|-----|------|
| Model Name | target_name | 目标模型名称（如 `qwen3:0.6b`） |
| API Key | api_key | 认证密钥，本地模型可留空 |
| Probe Filter | probes | 探针过滤（按类别或名称，如 `prompt_injection`） |
| Concurrency | max_concurrency | 并发数（默认3） |

智能响应分析：检测拒绝模式 + 攻击指标匹配双重判定。自动检测 Ollama/vLLM 本地模型并填充默认值。

```bash
# 基础用法
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"garak","target_type":"url","target":"http://localhost:11434","metadata":{"target_name":"llama3"}}'

# 仅运行提示词注入探针
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"garak","target_type":"url","target":"http://localhost:11434","metadata":{"target_name":"qwen3:0.6b","probes":"prompt_injection","api_key":"sk-xxx"}}'
```

### 7.3 基础设施漏洞扫描（infra_scan）

**类别**：infra | **实现**：Go 原生 | **依赖**：data/ 目录

| 目标类型 | 说明 |
|----------|------|
| url | Web服务URL |
| ip | IP地址 |
| cidr | CIDR网段 |

集成 AI-Infra-Guard 原生 runner，69个指纹 + 1360+条漏洞库，实时进度报告。

```bash
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"infra_scan","target_type":"url","target":"https://example.com"}'
```

### 7.4 MCP安全扫描（mcpsec）

**类别**：mcp | **实现**：Go 原生 | **依赖**：无

| 目标类型 | 说明 |
|----------|------|
| mcp_config | MCP配置JSON（可粘贴或上传文件） |
| file | 上传MCP配置文件 |

8大安全检查维度，10个规则ID：

| 维度 | 规则ID | 说明 |
|------|--------|------|
| 命令安全 | MCP01-001/002 | 危险命令、执行标志检测 |
| URL安全 | MCP02-001/002 | HTTP传输、本地绑定 |
| 认证配置 | MCP03-001 | 缺少认证 |
| 传输安全 | MCP04-001 | 未加密传输 |
| 权限检查 | MCP05-001 | 危险工具检测 |
| 环境变量 | MCP06-001 | 敏感数据泄露 |
| 输入验证 | MCP07-001 | 缺少输入Schema |
| 全局策略 | MCP08-001 | 缺少安全策略 |
| 日志配置 | MCP09-001 | 无日志配置 |
| 限流配置 | MCP10-001 | 无限流配置 |

```bash
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"mcpsec","target_type":"mcp_config","target":"{\"mcpServers\":{\"my-server\":{\"command\":\"node\",\"args\":[\"server.js\"]}}}"}'
```

### 7.5 API授权漏洞扫描（autoswagger）

**类别**：api | **实现**：Go 原生 | **依赖**：无

| 目标类型 | 说明 |
|----------|------|
| url | 目标API URL（支持直接输入swagger-ui页面URL） |

**三层发现机制：**

1. **规范文件直接发现**：探测17个常见OpenAPI/Swagger规范路径
2. **Swagger-UI页面发现**：探测9种文档UI路径（`/swagger-ui.html`、`/swagger-ui/`、`/docs/`、`/redoc` 等），从HTML中提取规范URL
3. **目标URL直接解析**：如果用户输入的URL本身就是文档页面，直接从中提取规范

**规范解析能力：**

- 从OpenAPI/Swagger规范中提取所有API端点
- 自动解析路径参数（如 `{id}` → `1`，`{username}` → `admin`）
- 支持内联spec提取（HTML中嵌入的JSON规范对象）
- 规范端点 + 30个常见敏感端点合并去重测试

**检测能力：**

- 未授权访问（敏感端点返回200但无认证）
- 密钥泄露（AWS Key, GitHub Token等10种模式）
- PII数据泄露（Email、手机号、身份证、信用卡）
- 过度数据暴露（响应体>10KB且无认证）
- 智能误报过滤：
  - JSON错误响应（`success:false`、`code:500`、`"服务器异常"`等）不判为漏洞
  - 标准HTML错误页面（Nginx/Apache默认502/500页面）不判为漏洞

```bash
# 扫描API站点（自动发现swagger-ui和规范）
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"autoswagger","target_type":"url","target":"http://example.com:7272"}'

# 直接指定swagger-ui页面
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"autoswagger","target_type":"url","target":"http://example.com:7272/swagger-ui/index.html"}'
```

### 7.6 限流/熔断验证（ratelimit）

**类别**：ratelimit | **实现**：Go 原生 | **依赖**：无

| 目标类型 | 说明 |
|----------|------|
| url | 目标API URL |

Go 原生 goroutine 并发压测引擎，7种判定规则：

| 规则ID | 条件 | 严重级别 |
|--------|------|----------|
| RL-NO-LIMIT | 无429/503/5xx响应 | high |
| RL-WEAK | 429<10% | medium |
| RL-ACTIVE | 10%≤429≤80% | info |
| RL-AGGRESSIVE | 429>80% | medium |
| RL-CIRCUIT-BREAKER | 503>5% | medium |
| RL-SERVER-ERROR | 5xx>10% | critical |
| RL-SLOW | 平均响应>3s | medium |

```bash
curl -X POST http://localhost:8088/api/v1/plugins/scan \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"ratelimit","target_type":"url","target":"http://example.com/api","metadata":{"duration":"30","threads":"10","ramp_up":"5"}}'
```

---

## 8. AI辅助功能

### 8.1 工作模式

| 模式 | 条件 | 能力 |
|------|------|------|
| **AI模式** | 配置了可用的LLM后端且连接正常 | 智能分析、自然语言报告、上下文修复建议、安全对话、扫描意图识别 |
| **降级模式** | AI已配置但连接失败 | 基于规则的模板分析、按severity级别的修复建议 |
| **未配置模式** | AI未启用 | AI状态指示器隐藏，Chat返回配置提示 |

### 8.2 支持的LLM后端

| 后端 | BaseURL示例 | 说明 |
|------|-------------|------|
| Ollama | http://localhost:11434/v1 | 本地部署，无需API Key |
| vLLM | http://localhost:8000/v1 | 高性能推理服务 |
| TGI | http://localhost:8080/v1 | HuggingFace推理 |
| OpenAI | https://api.openai.com/v1 | 需要API Key |

### 8.3 配置AI

**方式1：Web界面** — 访问 `/sec/config.html`，配置后自动持久化到配置文件

**方式2：API**
```bash
curl -X PUT http://localhost:8088/api/v1/ai/config \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"base_url":"http://localhost:11434/v1","api_key":"","model":"llama3"}'
```

**方式3：CLI**
```bash
ai-sec-check.exe ai config --enabled --base-url http://localhost:11434/v1 --model llama3
```

**方式4：配置文件** — 编辑 `configs/config.yaml`

### 8.4 AI连接检测

系统启动时和AI Chat页面加载时自动检测AI后端连接状态：

- 向 `{base_url}/models` 发送GET请求（5秒超时）
- 连接成功 → 显示 "AI Available"（绿色）
- 连接失败 → 显示 "AI Unreachable"（黄色）
- 未配置 → 状态指示器隐藏

### 8.5 AI Chat扫描意图识别

在AI Chat中输入包含扫描意图的自然语言消息，系统自动识别并执行对应扫描：

```
用户: "请检查 http://192.168.1.100:8080 是否有API授权漏洞"
系统: 识别意图 → autoswagger → 执行扫描 → 返回结果

用户: "帮我测试 http://localhost:11434 的模型安全性"
系统: 识别意图 → garak → 执行扫描 → 返回结果

用户: "这个MCP配置有没有安全问题 {\"mcpServers\":{...}}"
系统: 识别意图 → mcpsec → 执行扫描 → 返回结果
```

---

## 9. 配置参考

完整配置文件 `configs/config.yaml`：

```yaml
server:
  addr: "127.0.0.1:8088"

plugins:
  sensitive_word:
    enabled: true
    algorithm: "dfa"
    custom_dict_path: ""
    dicts: [political, violence, pornography, reactionary, advertisement, corruption, gun_explosion, people_life]
    normalizer: "strict"
  garak:
    enabled: true
    api_key: ""
    model_name: ""
    max_concurrency: 3
    timeout: 600
  infra_scan:
    enabled: true
    fp_templates: "data/fingerprints"
    adv_templates: "data/vuln"
    rate_limit: 200
    timeout: 10
  mcpsec:
    enabled: true
    severity_filter: "critical,high,medium"
  autoswagger:
    enabled: true
    brute: false
    rate: 30
    risk: false
    timeout: 300
  ratelimit:
    enabled: true
    threads: 50
    ramp_up: 10
    duration: 60

ai:
  enabled: false
  provider: "openai"
  base_url: ""
  api_key: ""
  model: ""
  fallback_to_template: true

database:
  type: "sqlite"
  path: "data/aig.db"

reports:
  output_dir: "reports"
  formats: [html, json]
```

**注意**：garak 插件的 `api_key`、`model_name` 如果未配置，会自动从 `ai` 配置中继承。

---

## 10. 离线部署

### 10.1 离线包结构

```
ai-sec-check/
├── ai-sec-check.exe          # 主程序（含前端嵌入，~50MB）
├── trpc_go.yaml              # 日志配置
├── configs/
│   └── config.yaml           # 主配置文件
├── data/                     # 指纹库+漏洞库+评测集+MCP配置
│   ├── fingerprints/         # AI应用指纹（69个）
│   ├── vuln/                 # CVE漏洞规则（1360+条）
│   ├── eval/                 # 评测数据集
│   ├── mcp/                  # MCP配置模板
│   └── agents/               # Agent扫描配置
├── start.bat                 # 启动脚本
├── stop.bat                  # 停止脚本
├── install.bat               # 安装检查脚本
└── build.bat                 # 构建脚本
```

### 10.2 构建离线包

```bash
build.bat
```

### 10.3 交叉编译

```bash
# Linux amd64
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-X ai-sec-check/internal/options.version=v1.0.0 -s -w" -o ai-sec-check-linux-amd64 ./cmd/cli

# macOS arm64
set GOOS=darwin
set GOARCH=arm64
go build -ldflags "-X ai-sec-check/internal/options.version=v1.0.0 -s -w" -o ai-sec-check-darwin-arm64 ./cmd/cli
```

---

## 11. 常见问题

### Q: 启动后插件显示 unavailable？

**A:** 所有6个插件均为 Go 原生实现，应该始终显示 Available。如果 infra_scan 不可用，检查 `data/fingerprints/` 和 `data/vuln/` 目录是否存在。

### Q: AI Chat显示"AI 助手尚未配置"？

**A:** 访问 `/sec/config.html` 配置AI：
1. 填写 Base URL（如 `http://localhost:11434/v1`）
2. 填写 Model（如 `deepseek-r1:32b`）
3. 点击"Test Connection"验证连接
4. 点击"Save"保存配置

### Q: AI Chat显示"AI Unreachable"？

**A:** AI已配置但无法连接，检查：
1. LLM后端服务是否正在运行
2. Base URL是否正确（注意需要包含 `/v1` 后缀）
3. API Key是否正确（本地模型可留空）
4. 网络是否可达

### Q: autoswagger扫描没有发现swagger-ui中的接口？

**A:** autoswagger会自动尝试发现swagger-ui页面并提取接口列表。确保：
1. 目标URL可访问
2. swagger-ui页面使用标准路径（如 `/swagger-ui.html`、`/swagger-ui/index.html`、`/docs/` 等）
3. 也可以直接输入swagger-ui页面的完整URL

### Q: garak扫描需要什么参数？

**A:** garak需要可访问的LLM API端点：
1. **必填**：Target URL（LLM API地址，如 `http://localhost:11434`）
2. **必填**：Model Name（模型名称，如 `qwen3:0.6b`，在插件参数中填写）
3. **可选**：API Key（本地Ollama/vLLM不需要）
4. **可选**：Probe Filter（默认运行全部32个探针，可选择仅运行特定类别）

### Q: MCP扫描如何传入配置？

**A:** 两种方式：
1. 在Web界面选择 `mcp_config` 类型，直接粘贴JSON或点击上传按钮
2. 通过API：`{"plugin_name":"mcpsec","target_type":"mcp_config","target":"{\"mcpServers\":{...}}"}`

### Q: 中文文本在CLI中编码乱码？

**A:** Windows PowerShell默认编码可能导致中文乱码。建议使用Web API或在PowerShell中设置 `chcp 65001`。

### Q: 扫描进度如何查看？

**A:** Web界面自动显示进度条。API方式：POST `/api/v1/plugins/scan` 返回 `scan_id`，然后轮询 GET `/api/v1/plugins/scan-progress/{scan_id}`。

### Q: AI配置保存后重启丢失？

**A:** AI配置通过Web界面或API保存后会自动持久化到 `configs/config.yaml`。如果丢失，检查配置文件是否有写入权限。
