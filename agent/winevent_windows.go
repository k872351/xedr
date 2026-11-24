//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// globalWinEvent 供 Sysmon 装好后重启通道订阅。
var globalWinEvent *winEventWatcher

// winEventWatcher：Wazuh 风格 Event Log 订阅（登录/账号/服务/任务），默认 XPath 压噪。
type winEventWatcher struct {
	mu          sync.Mutex
	events      []map[string]any
	cancel      context.CancelFunc
	running     bool
	state       int
	stateMsg    string
	bookmarkDir string
}

func newWinEventWatcher() *winEventWatcher { return &winEventWatcher{} }

func (w *winEventWatcher) start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.running = true
	w.state = cStateStarting
	w.stateMsg = "Windows Event Log subscription is starting"
	w.mu.Unlock()
	recordComponentObservation("winevent", cStateStarting, "Windows Event Log subscription is starting")
	go w.loop(cctx)
}

func (w *winEventWatcher) stop() {
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
	}
	w.running = false
	state, message := w.state, w.stateMsg
	if w.state != cStateFailed {
		w.state = cStateStopped
		w.stateMsg = "Windows Event Log subscription stopped"
		state, message = w.state, w.stateMsg
	}
	w.mu.Unlock()
	if state == cStateStopped {
		recordComponentObservation("winevent", state, message)
	}
}

func (w *winEventWatcher) setState(state int, message string) {
	w.mu.Lock()
	w.state = state
	w.stateMsg = message
	w.mu.Unlock()
	recordComponentObservation("winevent", state, message)
}

func (w *winEventWatcher) status() (int, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state, w.stateMsg
}

// restart 在 Sysmon 等新通道就绪后重订 EvtSubscribe。
func (w *winEventWatcher) restart(ctx context.Context) {
	w.stop()
	time.Sleep(400 * time.Millisecond)
	w.start(ctx)
}

func (w *winEventWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	if len(out) > 200 {
		// 一次最多转发 200 条，剩余留到下一轮，避免突发时整批丢弃
		w.events = append([]map[string]any(nil), out[200:]...)
		captureAdd("winevent", "drained", 200)
		return out[:200]
	}
	captureAdd("winevent", "drained", len(out))
	return out
}

func (w *winEventWatcher) push(ev map[string]any) {
	captureTag(ev, "winevent")
	captureAdd("winevent", "received", 1)
	if asString(ev["etype"]) == "winevent_status" {
		message := asString(ev["summary"])
		if message == "" {
			message = "Windows Event Log subscription active"
		}
		w.setState(cStateHealthy, message)
	}
	if isTimelineNoiseEvent(ev) {
		captureFiltered(ev)
		return
	}
	teleIncSource(ev)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	captureAdd("winevent", "queued", 1)
	if len(w.events) > 400 {
		captureAdd("winevent", "buffer_dropped", len(w.events)-400)
		w.events = w.events[len(w.events)-400:]
	}
}

func (w *winEventWatcher) loop(ctx context.Context) {
	dir := w.bookmarkDir
	if dir == "" && globalCfg.StateDir != "" {
		dir = filepath.Join(globalCfg.StateDir, "bookmarks")
	}
	if dir != "" {
		err := winevtTryNative(ctx, dir, w.push)
		if err == nil || ctx.Err() != nil {
			return
		}
		w.setState(cStateDegraded, "Native Event Log subscription failed; trying PowerShell fallback: "+err.Error())
		log.Printf("winevent: wevtapi 不可用 (%v)，回退 PowerShell", err)
	}
	w.loopPowerShell(ctx)
}

func (w *winEventWatcher) loopPowerShell(ctx context.Context) {
	ps := winEventSubscribeScript()
	tmp, err := os.CreateTemp("", "fa-wevt-*.ps1")
	if err != nil {
		w.setState(cStateFailed, "Cannot create Event Log subscriber script: "+err.Error())
		log.Printf("winevent: temp %v", err)
		return
	}
	path := tmp.Name()
	_, _ = tmp.Write([]byte{0xEF, 0xBB, 0xBF})
	_, _ = tmp.WriteString(ps)
	_ = tmp.Close()
	defer os.Remove(path)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
		hideWindow(cmd)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			w.setState(cStateDegraded, "Cannot open Event Log subscriber output: "+err.Error())
			time.Sleep(3 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			w.setState(cStateDegraded, "Cannot start Event Log subscriber: "+err.Error())
			log.Printf("winevent start: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("winevent: subscriber started (%s)", filepath.Base(path))
		rd := bufio.NewReader(stdout)
		for {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			default:
			}
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				var raw map[string]any
				if json.Unmarshal(line, &raw) == nil && raw["etype"] != nil {
					w.push(raw)
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("winevent read: %v", err)
				}
				break
			}
		}
		if ctx.Err() == nil {
			w.setState(cStateDegraded, "Event Log subscriber exited; restarting")
		}
		_ = cmd.Wait()
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func winEventSubscribeScript() string {
	// 压噪：不订 5156/4663/4656 等高量审计；只订登录/账号/服务/任务/进程访问(Sysmon10)
	return `
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
function Enq($obj){ [void]$queue.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6)) }

$queries = @()
try {
  $null = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
  $xpath = @'
*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4697 or EventID=4698 or EventID=4702 or EventID=1102)]]
'@
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath.Trim())
  $queries += @{ Name='security'; Query=$q }
} catch {}
try {
  $null = Get-WinEvent -ListLog 'System' -ErrorAction Stop
  $xpath = '*[System[(EventID=7045 or EventID=7036 or EventID=7040)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('System',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='system'; Query=$q }
} catch {}
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $xpath = '*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=6 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=15 or EventID=17 or EventID=19 or EventID=20 or EventID=21 or EventID=22 or EventID=23 or EventID=25 or EventID=26)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-Sysmon/Operational',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='sysmon'; Query=$q }
} catch {}
# 可选：需本机开启 PowerShell 模块/脚本块日志（见安装包 README）
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop
  $xpath = '*[System[(EventID=4103 or EventID=4104)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-PowerShell/Operational',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='powershell'; Query=$q }
} catch {}

if($queries.Count -eq 0){
  Enq @{ etype='winevent_status'; summary='Windows 事件通道不可用'; severity='info'; ts=(Get-Date).ToString('s') }
  while($true){ Start-Sleep -Seconds 30 }
}

foreach($item in $queries){
  try {
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($item.Query)
    $watcher.Enabled = $true
    $null = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -MessageData $queue -Action {
      try {
        $rec = $Event.SourceEventArgs.EventRecord
        if(-not $rec){ return }
        $q = $Event.MessageData
        $xml = [xml]$rec.ToXml()
        $data = @{}
        foreach($n in $xml.Event.EventData.Data){ if($n.Name){ $data[$n.Name]=[string]$n.'#text' } }
        $eid=[int]$rec.Id
        $ts=$rec.TimeCreated.ToString('s')
        $chan=[string]$rec.LogName
        $obj=$null
        switch($eid){
          4624 {
            $logonType=[string]$data['LogonType']
            if($logonType -in @('0','5','11')){ return } # 系统/服务/缓存噪声
            $user=[string]$data['TargetUserName']
            if($user -in @('ANONYMOUS LOGON','SYSTEM','LOCAL SERVICE','NETWORK SERVICE')){ return }
            if($user -match '(?i)^(DWM-|UMFD-)' -or $user.EndsWith('$')){ return }
            $ip=[string]$data['IpAddress']
            if($logonType -eq '3' -and ($ip -in @('127.0.0.1','::1','-',''))){ return }
            $obj=@{ etype='win_logon'; summary=('登录成功: '+$user+' type='+$logonType); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$user; domain=[string]$data['TargetDomainName']
              logon_type=$logonType; ip=$ip; process=[string]$data['ProcessName']
            } }
          }
          4625 {
            $u=[string]$data['TargetUserName']
            if($u.EndsWith('$') -or $u -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-','')){ return }
            # 单次失败只进时间线；暴破由后端/规则按频次判断
            $obj=@{ etype='win_logon_fail'; summary=('登录失败: '+$u); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$u; ip=[string]$data['IpAddress']
              status=[string]$data['Status']; substatus=[string]$data['SubStatus']
            } }
          }
          4648 {
            $proc=[string]$data['ProcessName']
            if($proc -match '(?i)\\(svchost|taskhostw|trustedinstaller|lsass|services|winlogon|consent)\.exe$'){ return }
            $obj=@{ etype='win_explicit_logon'; summary=('显式凭据登录: '+[string]$data['TargetUserName']); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=[string]$data['TargetUserName']; process=$proc
              target=[string]$data['TargetServerName']
            } }
          }
          4720 { $obj=@{ etype='win_account_create'; summary=('账号创建: '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName']; by=[string]$data['SubjectUserName'] } } }
          4722 { $obj=@{ etype='win_account_enable'; summary=('账号启用: '+[string]$data['TargetUserName']); severity='medium'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName'] } } }
          4724 { $obj=@{ etype='win_password_reset'; summary=('密码重置: '+[string]$data['TargetUserName']); severity='medium'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName'] } } }
          4728 { $obj=@{ etype='win_group_add'; summary=('加入组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4732 { $obj=@{ etype='win_group_add'; summary=('加入本地组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4756 { $obj=@{ etype='win_group_add'; summary=('加入通用组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4697 {
            $sp=[string]$data['ServiceFileName']
            if($sp -match '(?i)\\windows\\(system32|syswow64|winsxs)\\'){ return }
            $obj=@{ etype='win_service_install'; summary=('服务安装: '+[string]$data['ServiceName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; name=[string]$data['ServiceName']; path=$sp; account=[string]$data['ServiceAccount'] } }
          }
          4698 {
            $tn=[string]$data['TaskName']
            if($tn -match '(?i)^\\Microsoft\\'){ return }
            $obj=@{ etype='win_task_create'; summary=('计划任务创建: '+$tn); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; task=$tn; content=[string]$data['TaskContent'] } }
          }
          4702 {
            $tn=[string]$data['TaskName']
            if($tn -match '(?i)^\\Microsoft\\'){ return }
            $obj=@{ etype='win_task_update'; summary=('计划任务更新: '+$tn); severity='info'; ts=$ts; detail=@{ source='security'; event_id=$eid; task=$tn } }
          }
          1102 { $obj=@{ etype='win_audit_clear'; summary='安全日志被清空'; severity='critical'; ts=$ts; detail=@{ source='security'; event_id=$eid } } }
          4672 {
            $su=[string]$data['SubjectUserName']
            if($su -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -or $su.EndsWith('$') -or $su -match '(?i)^(DWM-|UMFD-)'){ return }
            $priv=[string]$data['PrivilegeList']
            if(-not $priv -or $priv -notmatch '(?i)SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege'){ return }
            # 管理员交互登录常带 Impersonate；仅 Debug/Tcb/LoadDriver 进时间线，且不作中危告警
            $obj=@{ etype='win_special_priv'; summary=('特殊权限分配: '+$su); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$su; domain=[string]$data['SubjectDomainName']; privileges=$priv
            } }
          }
          7045 {
            $ip=[string]$data['ImagePath']
            if($ip -match '(?i)\\windows\\(system32|syswow64|winsxs)\\'){ return }
            $obj=@{ etype='win_service_install'; summary=('服务安装: '+[string]$data['ServiceName']); severity='high'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=[string]$data['ServiceName']; path=$ip
              account=[string]$data['AccountName']; start_type=[string]$data['StartType']
            } }
          }
          7036 {
            $obj=@{ etype='win_service_state'; summary=('服务状态: '+[string]$data['param1']+' → '+[string]$data['param2']); severity='info'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=[string]$data['param1']; state=[string]$data['param2']
            } }
          }
          7040 {
            $disp=[string]$data['param1']
            # param4 为服务短名（中英文系统一致）；无则退回显示名
            $short=[string]$data['param4']
            if(-not $short){ $short=$disp }
            $noise='(?i)^(BITS|wuauserv|UsoSvc|DoSvc|TrustedInstaller|WaaSMedicSvc|wlidsvc|DiagTrack|WpnService|SystemEventsBroker|WinDefend|WdNisSvc|Sense|edgeupdate|edgeupdatem|gupdate|gupdatem|gpsvc|Schedule|WSearch|SysMain|ClickToRunSvc|MapsBroker|lfsvc|InstallService|AppXSvc|ClipSVC|StorSvc|TokenBroker|CDPSvc|CDPUserSvc.*|OneSyncSvc.*|PimIndexMaintenanceSvc.*|UnistoreSvc.*|UserDataSvc.*|WpnUserService.*)$'
            if($short -match $noise){ return }
            # 只关心改成「禁用」或非系统映像的启动类型变更
            $to=[string]$data['param3']
            if($to -notmatch '(?i)(disabled|禁用)'){ return }
            $obj=@{ etype='win_service_config'; summary=('服务被禁用: '+$disp); severity='medium'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=$disp; service=$short; from=[string]$data['param2']; to=$to
            } }
          }
          4103 {
            $payload=[string]$data['Payload']
            if(-not $payload){ $payload=[string]$data['MessageNumber'] }
            $snip = if($payload.Length -gt 180){ $payload.Substring(0,180)+'…' } else { $payload }
            $obj=@{ etype='win_ps_module'; summary=('PowerShell 模块日志: '+$snip); severity='info'; ts=$ts; detail=@{
              source='powershell'; event_id=$eid; payload=$payload; context=[string]$data['ContextInfo']
            } }
          }
          4104 {
            $script=[string]$data['ScriptBlockText']
            if(-not $script){ return }
            $sev='info'; $sum='PowerShell 脚本块'
            if($script -match '(?i)(-enc|frombase64string|iex\s|invoke-expression|downloadstring|system\.reflection\.assembly)'){
              $sev='high'; $sum='可疑 PowerShell 脚本块'
            }
            $snip = if($script.Length -gt 160){ $script.Substring(0,160)+'…' } else { $script }
            $obj=@{ etype='win_ps_scriptblock'; summary=($sum+': '+$snip); severity=$sev; ts=$ts; detail=@{
              source='powershell'; event_id=$eid; script_block=$script
              script_block_id=[string]$data['ScriptBlockId']; path=[string]$data['Path']
            } }
          }
          8 {
            $src=[string]$data['SourceImage']
            if($src -match '(?i)\\(MsMpEng|NisSrv|csrss|wininit|services|lsass|svchost|smss|dwm|audiodg|MpDefenderCoreService|SecurityHealthService)\.exe$'){ return }
            if($src -match '(?i)\\(chrome|msedge|firefox|opera|brave)\.exe$' -and [string]$data['TargetImage'] -match '(?i)\\(chrome|msedge|firefox|opera|brave)\.exe$'){ return }
            $obj=@{ etype='remote_thread'; summary=('远程线程(Sysmon): '+[IO.Path]::GetFileName($src)+' → '+[IO.Path]::GetFileName([string]$data['TargetImage'])); severity='high'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$src; target_path=[string]$data['TargetImage']
              pid=[int]($data['SourceProcessId']); target_pid=[int]($data['TargetProcessId']); start_address=[string]$data['StartAddress']
            } }
          }
          10 {
            $am=[string]$data['GrantedAccess']
            if(-not $am){ return }
            # 按位判断：仅 VM_WRITE(0x20) / CREATE_THREAD(0x2) / VM_OPERATION(0x8) / 全权限
            $mask=0
            try { $mask=[Convert]::ToInt64(($am -replace '^0x',''),16) } catch { return }
            $want=0x20 -bor 0x2 -bor 0x8
            if((($mask -band $want) -eq 0) -and ($mask -ne 0x1FFFFF) -and ($mask -ne 0x1F0FFF)){ return }
            $src=[string]$data['SourceImage']
            if($src -match '(?i)\\(MsMpEng|NisSrv|csrss|wininit|services|lsass|svchost|taskmgr|procexp|procexp64|vmtoolsd)\.exe$'){ return }
            $tgt=[string]$data['TargetImage']
            $etype='process_access'; $sev='medium'
            $sum=('进程打开(Sysmon): '+[IO.Path]::GetFileName($src)+' → '+[IO.Path]::GetFileName($tgt))
            $det=@{
              source='sysmon'; event_id=$eid; path=$src; target_path=$tgt
              pid=[int]($data['SourceProcessId']); target_pid=[int]($data['TargetProcessId']); access=$am
              call_trace=[string]$data['CallTrace']
            }
            if($tgt -match '(?i)\\lsass\.exe$'){
              $etype='credential_access'; $sev='high'
              $sum=('凭据访问(Sysmon): '+[IO.Path]::GetFileName($src)+' → lsass.exe')
              $det['technique']='T1003.001'; $det['target_name']='lsass.exe'; $det['credential_access']=$true
            }
            $obj=@{ etype=$etype; summary=$sum; severity=$sev; ts=$ts; detail=$det }
          }
          12 {
            $to=[string]$data['TargetObject']
            if($to -notmatch '(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)'){ return }
            $evType=[string]$data['EventType']
            $etype='registry_create'; $sum=('注册表创建(Sysmon): '+$to)
            if($evType -match '(?i)delete'){ $etype='registry_delete'; $sum=('注册表删除(Sysmon): '+$to) }
            $obj=@{ etype=$etype; summary=$sum; severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$to; operation=$evType
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          13 {
            $to=[string]$data['TargetObject']
            # 只保留 ASEP / 安全相关键
            if($to -notmatch '(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)'){ return }
            $obj=@{ etype='registry_write'; summary=('注册表写入(Sysmon): '+$to); severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$to; value=[string]$data['Details']
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          14 {
            $to=[string]$data['TargetObject']
            if($to -notmatch '(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)'){ return }
            $obj=@{ etype='registry_rename'; summary=('注册表重命名(Sysmon): '+$to); severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$to; new_name=[string]$data['NewName']; operation=[string]$data['EventType']
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          6 {
            $img=[string]$data['ImageLoaded']; if(-not $img){ $img=[string]$data['Image'] }
            if(-not $img){ return }
            $sev='info'; if([string]$data['SignatureStatus'] -match '(?i)not.?signed|expired|unavailable'){ $sev='high' }
            $obj=@{ etype='driver_load_sysmon'; summary=('驱动加载(Sysmon): '+[IO.Path]::GetFileName($img)); severity=$sev; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$img; name=[IO.Path]::GetFileName($img)
              signed=[string]$data['SignatureStatus']; signer=[string]$data['Signature']; hash=[string]$data['Hashes']
            } }
          }
          19;20;21 {
            $name=[string]$data['Name']; if(-not $name){ $name=[string]$data['Consumer'] }; if(-not $name){ $name=[string]$data['Filter'] }
            $etype='wmi_persist_add'; $sum=('WMI 永久订阅(Sysmon): '+$name)
            if($eid -eq 19){ $sum=('WMI Filter(Sysmon): '+$name) }
            elseif($eid -eq 20){ $sum=('WMI Consumer(Sysmon): '+$name) }
            elseif($eid -eq 21){ $sum=('WMI Binding(Sysmon): '+$name) }
            $op=[string]$data['Operation']
            if($op -match '(?i)delet'){ $etype='wmi_persist_delete' }
            elseif($op -match '(?i)modif'){ $etype='wmi_persist_modify' }
            $obj=@{ etype=$etype; summary=$sum; severity='high'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; name=$name; operation=$op; user=[string]$data['User']
              consumer=[string]$data['Consumer']; filter=[string]$data['Filter']; topic='startup'
            } }
          }
          22 {
            $qname=[string]$data['QueryName']
            if(-not $qname -or $qname -match '(?i)\.(arpa|local)$'){ return }
            $obj=@{ etype='dns_query'; summary=('DNS(Sysmon): '+$qname); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; query=$qname; type=[string]$data['QueryType']
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          1 {
            $img=[string]$data['Image']
            if($img -match '(?i)\\(MsMpEng|NisSrv|csrss|wininit|services|lsass|svchost|smss|dwm|audiodg)\.exe$'){ return }
            $pimg=[string]$data['ParentImage']
            $obj=@{ etype='process_create_sysmon'; summary=('进程创建(Sysmon): '+[IO.Path]::GetFileName($img)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; pid=[int]($data['ProcessId']); ppid=[int]($data['ParentProcessId'])
              name=[IO.Path]::GetFileName($img); path=$img; command_line=[string]$data['CommandLine']; user=[string]$data['User']
              parent_path=$pimg; parent_name=[IO.Path]::GetFileName($pimg); parent_command_line=[string]$data['ParentCommandLine']
              hash=[string]$data['Hashes']; hashes=[string]$data['Hashes']
              company=[string]$data['Company']; product=[string]$data['Product']; integrity=[string]$data['IntegrityLevel']
            } }
          }
          3 {
            $obj=@{ etype='network_connect'; summary=('网络(Sysmon): '+[string]$data['DestinationIp']+':'+[string]$data['DestinationPort']); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; remote_ip=[string]$data['DestinationIp']; remote_port=[string]$data['DestinationPort']
              local=[string]$data['SourceIp']; proto=[string]$data['Protocol']; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          5 {
            $img=[string]$data['Image']
            $obj=@{ etype='process_exit_sysmon'; summary=('进程退出(Sysmon): '+[IO.Path]::GetFileName($img)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; pid=[int]($data['ProcessId']); name=[IO.Path]::GetFileName($img); path=$img
            } }
          }
          7 {
            $img=[string]$data['ImageLoaded']; if(-not $img){ $img=[string]$data['Image'] }
            $obj=@{ etype='image_load_sysmon'; summary=('DLL 加载(Sysmon): '+[IO.Path]::GetFileName($img)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$img; module=[IO.Path]::GetFileName($img); pid=[int]($data['ProcessId'])
              signed=[string]$data['SignatureStatus']; signer=[string]$data['Signature']
            } }
          }
          11 {
            $target=[string]$data['TargetFilename']; if(-not $target){ return }
            $obj=@{ etype='file_create'; summary=('文件创建(Sysmon): '+[IO.Path]::GetFileName($target)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$target; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          15 {
            $target=[string]$data['TargetFilename']; if(-not $target){ return }
            $obj=@{ etype='file_stream_create'; summary=('ADS/流创建(Sysmon): '+[IO.Path]::GetFileName($target)); severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$target; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          17 {
            $pipe=[string]$data['PipeName']; if(-not $pipe){ return }
            $obj=@{ etype='pipe_created'; summary=('命名管道(Sysmon): '+$pipe); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; pipe=$pipe; path=$pipe; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          23 {
            $target=[string]$data['TargetFilename']; if(-not $target){ return }
            $obj=@{ etype='file_delete'; summary=('文件删除(Sysmon): '+[IO.Path]::GetFileName($target)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$target; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          25 {
            $img=[string]$data['Image']
            $obj=@{ etype='process_tampering'; summary=('进程篡改(Sysmon): '+[IO.Path]::GetFileName($img)); severity='high'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$img; name=[IO.Path]::GetFileName($img); pid=[int]($data['ProcessId'])
              tamper_type=[string]$data['Type']
            } }
          }
          26 {
            $target=[string]$data['TargetFilename']; if(-not $target){ return }
            $obj=@{ etype='file_delete_detected'; summary=('文件删除检测(Sysmon): '+[IO.Path]::GetFileName($target)); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$target; pid=[int]($data['ProcessId'])
              process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          default {
            # 兜底：带 EventID 进时间线，供日志规则匹配（避免 XPath 扩了但 switch 未覆盖时静默丢弃）
            if($eid -gt 0){
              $src='winevent'
              if($chan -match '(?i)sysmon'){ $src='sysmon' }
              $obj=@{ etype='winevent_generic'; summary=($chan+' E'+$eid); severity='info'; ts=$ts; detail=@{
                source=$src; event_id=$eid; channel=$chan
              } }
            }
          }
        }
        if($obj){
          if($obj.detail -is [hashtable]){ $obj.detail['channel'] = $chan }
          [void]$q.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6))
        }
      } catch {}
    }
  } catch {}
}

Enq @{ etype='winevent_status'; summary=('事件通道: '+(($queries|ForEach-Object Name) -join ',')); severity='info'; ts=(Get-Date).ToString('s'); detail=@{ sources=@($queries|ForEach-Object Name) } }
while($true){
  $line=$null
  while($queue.TryDequeue([ref]$line)){ Write-Output $line }
  Start-Sleep -Milliseconds 250
}
`
}
