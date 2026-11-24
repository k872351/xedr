# P0 整改验收台账

对照用户 P0-01～P0-08。代码缺口与运维实机项分开记录；实机未跑不得标为已关闭。

| 编号 | 目标 | 代码/自动化 | 实机/运维验收 | 状态 |
|---|---|---|---|---|
| P0-01 | 策略来源及完整性可信 | 服务端 `policy_sign.attach_policy_signature` 已接入心跳/同步下发；`GET /api/agent/policy-pubkey`；`backend/test_policy_sign.py` + `agent/policy_sign_test.go` | Agent 钉扎 `policy_pubkey` 后，改策略→心跳/同步应用；篡改正文被拒 | 代码闭环已补；实机待验 |
| P0-02 | 覆盖安装身份保持 | `install.go` 保留既有 `agent.json`；异平台地址拒绝；注册无 id 发新 UUID | 同机覆盖安装后 `agent_id`/凭据不变、不串档 | 代码在；实机待验 |
| P0-03 | 审批中断恢复 | `recover_stuck_approvals`：陈旧 `dispatching`→`pending`；列表时自动触发；`test_approval_recover.py` | 批准中杀进程后列表可见恢复并可再批 | 代码闭环已补；实机待验 |
| P0-04 | 管理端接口权限 | `scripts/audit_admin_api_auth.py` 静态扫描；诊断/发布等已强制 admin | 按角色账号抽测越权 | 扫描可用；人工抽测待验 |
| P0-05 | Agent↔服务端联调 | 见下方清单 | 注册/心跳/策略/指令/遥测一致 | 待实机 |
| P0-06 | 生产 DB 故障 | `/health/ready`、MySQL 严格模式、备份校验脚本 | 断库/恢复后无脏写、状态一致 | 待演练 |
| P0-07 | HTTPS 与会话 | Cookie HttpOnly/SameSite/Secure；同源校验；`test_session_routes.py` | 反代 HTTPS 下 Secure、无明文会话 | 待部署验收 |
| P0-08 | 备份恢复 | `verify_sqlite_backup.py`、`test_backup_verification.py` | 隔离环境恢复后业务可读 | 待演练 |

## 快速命令

```powershell
python -m unittest backend.test_policy_sign backend.test_approval_recover -v
python scripts/audit_admin_api_auth.py
cd agent; go test ./ -run "PolicySign|OfferReject|OfferAccept" -count=1
```

## P0-05 联调最小清单

1. 新终端注册 → 控制台出现且 `agent_id` 稳定  
2. 心跳周期内在线；停服务后离线  
3. 修改全局策略 → Agent `applied_rev` 追上；`policy.sign.v1` 能力为 OK  
4. 下发低危指令并回执  
5. 高危动作走审批 → 批准 → 命令状态与审批单一致  

## P0-01 钉扎公钥

1. 管理端登录后取 `GET /api/agent/policy-pubkey`  
2. 写入终端 `agent.json` 的 `policy_pubkey`（或构建 `-ldflags`）  
3. 勿开 `insecure_skip_verify` 于生产  
