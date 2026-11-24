# 管理端 UI 美化进展（相对 DataProtector 壳层）

| 编号 | 项 | 状态 |
|---|---|---|
| UI-01 | 双层导航 | 既有石墨侧栏；选中态沿用 |
| UI-02 | 顶部工具栏 | `ConsoleWorkbenchBar`（面包屑 / 搜索 / 密度 / 主题 / 偏好） |
| UI-03 | 多页签 | `ConsoleWorkspaceTabs` + 本地持久化 |
| UI-04 | 深浅色 | 既有；工具栏与主题抽屉可切换 |
| UI-05 | 页头 | `ConsolePageHeader` 既有 |
| UI-06～09 | 卡片 / 表格 / 标签 / 筛选 | `socConsole.css` + `ConsoleStatusTag` |
| UI-10 | 详情抽屉 | `ConsoleDrawer` 组件；告警侧栏 `ed-side` 主题变量统一 |
| UI-11 | 主题配置面板 | `ConsoleThemeDrawer`（字号 / 圆角 / 密度 / 主题） |
| UI-12 | 页面水印 | `ConsoleWatermark`（偏好开关） |
| UI-13 | 骨架屏 | `ConsoleSkeleton` 既有；终端列表等已接入 |
| UI-14 | 异常页面 | `ConsoleExceptionPage`（403 / 404 / 500） |
| UI-15 | 登录品牌 | `Login.vue` 砖色品牌层已加强 |
| UI-16 | 响应式 | 宽屏 padding / 小屏工具栏折叠 |
| F-01 | 全局搜索 | `ConsoleGlobalSearch`（Ctrl+K） |
| F-04 / F-15 | 页签与偏好 | 密度 / 主题 / 圆角 / 字号 / 水印本地保存 |

参考：DataProtector `layouts/modules/global-*`、`theme-drawer`，未照搬 UI 框架。

## 业务页进展

| 页面 | 状态 |
|---|---|
| 总览 / 终端列表 / 账号 / 审计 / 存储 | 页头 + 卡片 / 状态标签 / CSS 变量统一 |
| 告警中心详情侧栏 | `ed-side` 主题化 |
| 时间线 / 终端详情筛选 | 筛选条与 chip 统一 |
| 其余业务页 | 沿用全局 `socConsole` 层，后续按需细修 |

## 待扩展（F-02～F-14）

我的工作台、收藏、报告中心、合规 / 健康 / 发布 / 兼容性 / 通知 / 归档 / 帮助等运营模块仍按需迭代。
