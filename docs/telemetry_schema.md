# Agent 遥测字段规范（Windows）

`schema_version` 当前为 **1**。每条时间线事件由 Agent 注入单调递增的 `agent_seq`，平台据此检测上报缺口。

## 公共字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `etype` | string | 事件类型 |
| `summary` | string | 一句话摘要 |
| `severity` | string | info / low / medium / high / critical |
| `ts` | string | 本地时间 `YYYY-MM-DDTHH:MM:SS` |
| `schema_version` | int | 字段规范版本 |
| `agent_seq` | uint64 | Agent 进程内单调序号 |
| `detail` | object | 结构化详情（见下） |

## 关键 `etype`

| etype | 用途 |
|-------|------|
| `process_create_etw` | 进程创建（含路径/命令行/PE 元数据缓存） |
| `file_create` | 热扩展名文件创建（可含 MOTW / PE 元数据） |
| `network_connect_etw` | 内核 TCP 外联 |
| `http_request_etw` | WinINet/WebIO HTTP Host/URL |
| `dns_query` / `dns_summary` / `dns_nx_burst` | DNS |
| `beacon_like` | 准周期外联 |
| `registry_set` / `registry_delete` | 注册表实时变更（可含修改者 PID） |
| `memory_scan_hit` / 完整性子类型 | 注入、反射 PE、ETW/AMSI 补丁、EAT/IAT、模块覆盖 |
| `agent_self_protect` | 服务/ETW 自保护 |
| `agent_seq_gap` | 平台检出的序号缺口 |

## 文件 / PE  enrichment（`detail`）

| 字段 | 说明 |
|------|------|
| `pe_compile_time` / `pe_compile_ts` | PE `TimeDateStamp`（可信年份才填时间字符串） |
| `pe_compile_future` / `pe_compile_ancient` | 异常编译时间弱信号 |
| `imphash` | 导入表哈希（pefile/VT 约定） |
| `pe_max_entropy` / `pe_packed_likely` / `pe_sections` | 节熵摘要 |
| `pe_arch` | x86 / x64 |
| `motw` / `motw_zone` / `motw_zone_label` | Mark-of-the-Web |
| `motw_referrer` / `motw_host_url` | MOTW URL |

## HTTP（`http_request_etw`）

| 字段 | 说明 |
|------|------|
| `source` | `wininet` / `webio` |
| `host` / `port` / `method` / `url` / `url_path` | 请求目标 |
| `pid` / `process_name` / `entity_id` | 进程归属 |

## Beacon（`beacon_like`）

| 字段 | 说明 |
|------|------|
| `host` / `samples` / `mean_interval_sec` / `jitter_cv` | 周期与抖动 |
| `window_min` | 观察窗口（分钟） |

## 处置动作（`response.persist.v1`）

`disable_service` / `enable_service` / `stop_service` / `delete_task` / `disable_task` /
`reg_delete_value` / `reg_set_value` / `reg_rollback` / `clear_persistence` / `recheck_persistence`
