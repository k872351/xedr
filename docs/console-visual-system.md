# 管理端视觉体系（SOC）

品牌主色保留 `#E2562C`；侧栏石墨黑；内容区浅灰蓝 `#EEF2F6`。

## 入口

- 设计令牌：`agent_admin/src/styles.css` + `socConsole.css`
- 密度 / 深色：用户菜单切换，持久化到 `localStorage`（`edr.console.density` / `edr.console.theme`）
- 共享组件：`ConsolePageHeader`、`ConsoleEmptyState`、`ConsoleSkeleton`、`ConsoleDrawer`

## 已覆盖（本轮）

P1：总览威胁卡、终端列表/详情头、狩猎查询区、登录品牌、全局表格密度与空态骨架。  
P2：存储/规则/案件等页面继承全局面板与表格样式，专项可视化可继续叠加。

## 交互

- 紧凑 / 标准密度
- 浅色 / 深色
- 侧滑抽屉组件已提供，告警/终端详情可逐步迁入 `ConsoleDrawer`
