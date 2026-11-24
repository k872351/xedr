# Web 安全整改台账（WEB-01～WEB-15）

| 编号 | 状态 | 本轮动作 |
|---|---|---|
| WEB-01 | 已加固 | `db_store_heavy` 改为 gzip JSON；遗留 pickle 仅安全 Unpickler 读取后迁移 |
| WEB-02 | 已加固 | `sqlite_schema_tools` / `report_index_schema` 标识符与列 DDL 白名单 |
| WEB-03 | 已加固 | `ssrf_guard.validate_outbound_url` 接入通知出站 |
| WEB-04 | 部分 | 现有 admin/user 会话校验 + `audit_admin_api_auth.py`；资源级归属仍需业务验收 |
| WEB-05 | 已加固 | 升级包上传扩展名/魔数/路径剥离 |
| WEB-06 | 既有 | 诊断/发布下载鉴权测试保留；继续实机验收 |
| WEB-07 | 已审 | `device_ops` 等为固定参数列表、`shell=False`；未见用户拼接注入 |
| WEB-08 | 部分 | 会话 Cookie HttpOnly/SameSite；MFA 未做（产品项） |
| WEB-09 | 已加固 | bootstrap 密码写入 `data/bootstrap_admin.txt`（0600），不落日志 |
| WEB-10 | 已加固 | `EDR_REQUIRE_HTTPS=1` → `RequireHttpsMiddleware`；nginx 示例已强制跳转 |
| WEB-11 | 已加固 | 导航 SVG `safeRailIcon`；AI Markdown 先转义再有限标签 |
| WEB-12 | 既有 | Origin 同源写保护 + SameSite=Strict；部署验收见 nginx 示例 |
| WEB-13 | 既有 | `paths.py` stem 约束 + 诊断访问测试 |
| WEB-14 | 已加固 | 登录限流字典容量剪枝；反代层建议叠加 `limit_req` |
| WEB-15 | 既有 | `scripts/check_dependency_versions.py`；建议 CI 加 pip-audit/npm audit |

## 生产建议

```bash
set EDR_REQUIRE_HTTPS=1
set EDR_BOOTSTRAP_ADMIN_PASSWORD=<一次性强密码>
```

反代必须传 `X-Forwarded-Proto https`，并启用 nginx/Caddy HTTPS 跳转。
