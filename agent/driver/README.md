# FaKmon 内核监控驱动

**默认安装包不下发、不安装本驱动**（蓝屏风险；生产需 EV/Attestation 签名）。
图形安装器（`Install-GUI.ps1`）可勾选「可选驱动」——仅当包内附带 `fakmon.sys` 时才会 `sc create/start`。

## 与 DataProtector 的分层对齐（只学架构，不拷 GPL 代码）

开源 DataProtector 把重检测放在用户态，内核做事件发现与可选阻断：
`minifilter` 透明保护、`ObRegisterCallbacks` 凭据/自保护、`WFP` 网络、LateralDefense 等。

本仓库对应策略：

| 能力 | 用户态（默认） | 内核（FaKmon 可选） |
| --- | --- | --- |
| 横向移动 | Winlog 5140–5145 + 命令行规则（schtasks/sc/wmic/WinRM/PsExec） | 不仿 LateralDefense 阻断 |
| Web/脚本落地 | FIM Web 根 + dropScan | — |
| 凭据访问 | Sysmon 10 + Threat-Intelligence ETW → 内存扫描 | ObRegister 打开 lsass |
| 文件改名绕过 | Kernel-File ETW 重命名/删除 + FIM | — |
| 自保护 | 用户态服务监视 | ObRegister / 注册表回调 |

以下为实验室可选能力：驱动加载后 Agent 可上报 `kernel_*` 时间线；未加载时使用 ETW / WMI / 事件日志等用户态采集，不影响运行。

| 能力 | 内核接口 | 时间线 etype |
| --- | --- | --- |
| 进程创建 / 退出 | `PsSetCreateProcessNotifyRoutineEx` | `process_create_kernel` / `process_exit_kernel` |
| 映像加载（DLL/驱动） | `PsSetLoadImageNotifyRoutine` | `image_load_kernel`（仅上报可疑路径） |
| 远程线程（注入面） | `PsSetCreateThreadNotifyRoutine` | `remote_thread_kernel` |
| Agent 进程防结束 / 防写内存 | `ObRegisterCallbacks` | `protect_block_kernel` |
| 打开 lsass（VM 读/写/线程等） | `ObRegisterCallbacks` | `process_access_kernel` |
| ASEP 注册表写入 | `CmRegisterCallbackEx` | `registry_write_kernel` |
| Agent 服务注册表键防篡改 | `CmRegisterCallbackEx` | `reg_protect_kernel` |

> **Minifilter 文件自保护**：尚未接入（需 FltMgr 与独立 altitude）；当前文件完整性仍由用户态 FIM 负责。

## 编译

需要 Visual Studio + WDK（Windows Driver Kit）。

**一键检测 / 编译（推荐）**：

```powershell
cd agent\driver
.\build-driver.ps1 -CheckOnly   # 只看 VS / WDK / 测试签名 / 服务是否就绪
.\build-driver.ps1              # 有工具链则编出 out\fakmon.sys
.\build-driver.ps1 -Install     # 编完后复制到 ProgramData 并 sc create/start
```

若脚本因环境差异编不过，可手动：

1. VS 新建 “Kernel Mode Driver, Empty (KMDF)” 或 WDM 空项目，加入 `fakmon.c`、`fakmon.h`。
2. 链接器 → 命令行追加 `/INTEGRITYCHECK`（`PsSetCreateProcessNotifyRoutineEx` 与 `ObRegisterCallbacks` 强制要求）。
3. 目标平台 x64，Release 生成 `fakmon.sys`。

## 签名与安装

生产环境必须使用 EV 证书并经微软 Attestation 签名。测试环境：

```bat
bcdedit /set testsigning on
:: 重启后
sc create FaKmon type= kernel start= auto binPath= C:\ProgramData\ForensicAgent\fakmon.sys
sc start FaKmon
```

卸载：`sc stop FaKmon && sc delete FaKmon`。

## 协议

`fakmon.h` 中 `FA_EVENT` 的布局与 `agent/driver_windows.go` 中的 `faEvent` 一一对应，修改任一侧都要同步另一侧。
