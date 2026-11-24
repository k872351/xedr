//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// collectSoftware：HKLM + 各用户 HKU 卸载表 + AppX（对标 DataProtector / Wazuh 覆盖面）。
func collectSoftware() ([]any, error) {
	return collectSoftwareLimited(maxItems)
}

func collectSoftwareLimited(limit int) ([]any, error) {
	var out []any
	seen := map[string]bool{}
	addUninstall := func(root registry.Key, path, arch, hive, user string) error {
		if len(out) >= limit {
			return nil
		}
		k, err := registry.OpenKey(root, path, registry.READ)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("software inventory root: %w", err)
		}
		defer k.Close()
		names, err := k.ReadSubKeyNames(0)
		if err != nil {
			return fmt.Errorf("software inventory enumeration: %w", err)
		}
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.READ)
			if err != nil {
				if errors.Is(err, registry.ErrNotExist) {
					continue
				}
				return fmt.Errorf("software inventory entry: %w", err)
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			loc, _, _ := sk.GetStringValue("InstallLocation")
			src, _, _ := sk.GetStringValue("InstallSource")
			uninstall, _, _ := sk.GetStringValue("UninstallString")
			sk.Close()
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			key := strings.ToLower(name + "|" + ver + "|" + arch + "|" + hive + "|" + user)
			if seen[key] {
				continue
			}
			seen[key] = true
			item := map[string]any{
				"name":         name,
				"version":      ver,
				"publisher":    pub,
				"arch":         arch,
				"install_path": loc,
				"source":       src,
				"uninstall":    uninstall,
				"hive":         hive,
				"inventory":    "software",
			}
			if user != "" {
				item["user"] = user
			}
			out = append(out, item)
			if len(out) >= limit {
				return nil
			}
		}
		return nil
	}
	if err := addUninstall(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "64", "HKLM", ""); err != nil {
		return out, err
	}
	if err := addUninstall(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "32", "HKLM", ""); err != nil {
		return out, err
	}
	// 已加载用户配置的 HKCU 卸载项（LocalSystem 下 CurrentUser 采不到个人软件）
	sidToUser := map[string]string{}
	for _, p := range userProfiles() {
		sidToUser[p.sid] = p.name
	}
	if uk, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := uk.ReadSubKeyNames(0)
		uk.Close()
		for _, sid := range sids {
			if !strings.HasPrefix(sid, "S-1-5-21-") || strings.Contains(sid, "_Classes") {
				continue
			}
			user := sidToUser[sid]
			if user == "" {
				user = sid
			}
			base := sid + `\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
			_ = addUninstall(registry.USERS, base, "64", "HKCU", user)
			if len(out) >= limit {
				return out, nil
			}
			_ = addUninstall(registry.USERS, sid+`\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "32", "HKCU", user)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	// Store / AppX 应用（AllUsers）
	if len(out) < limit {
		remain := limit - len(out)
		for _, raw := range collectAppXPackages(remain) {
			it, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := asString(it["name"])
			ver := asString(it["version"])
			user := asString(it["user"])
			key := strings.ToLower(name + "|" + ver + "|appx|" + user)
			if name == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, it)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func collectAppXPackages(limit int) []any {
	if limit <= 0 {
		return nil
	}
	ps := fmt.Sprintf(`
$lim = %d
$out = @()
try {
  Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Select-Object -First ($lim * 2) | ForEach-Object {
    if($out.Count -ge $lim){ return }
    $n = [string]$_.Name
    if(-not $n){ return }
    $user = ''
    try { if($_.PackageUserInformation){ $user = [string](($_.PackageUserInformation | Select-Object -First 1).UserSecurityId.Sid) } } catch {}
    $out += [PSCustomObject]@{
      name = $n
      version = [string]$_.Version
      publisher = [string]$_.Publisher
      install_path = [string]$_.InstallLocation
      package = [string]$_.PackageFullName
      arch = [string]$_.Architecture
      hive = 'AppX'
      user = $user
      source = 'AppX'
      inventory = 'software'
    }
  }
} catch {}
$out
`, limit)
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		item := map[string]any{
			"name":         name,
			"version":      asString(r["version"]),
			"publisher":    asString(r["publisher"]),
			"install_path": asString(r["install_path"]),
			"package":      asString(r["package"]),
			"arch":         asString(r["arch"]),
			"hive":         "AppX",
			"source":       "AppX",
			"inventory":    "software",
		}
		if u := asString(r["user"]); u != "" {
			item["user"] = u
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// collectNetif：网卡 / IP / 网关（Wazuh syscollector 缺口补齐）。
func collectNetif() ([]any, error) {
	ps := `
$out = @()
try {
  Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    $if = $_.InterfaceAlias
    $desc = [string]$_.InterfaceDescription
    $mac = ''
    try { $mac = [string](Get-NetAdapter -Name $if -ErrorAction SilentlyContinue).MacAddress } catch {}
    $ips = @()
    foreach($a in @($_.IPv4Address)){ if($a.IPAddress){ $ips += [string]$a.IPAddress } }
    foreach($a in @($_.IPv6Address)){ if($a.IPAddress){ $ips += [string]$a.IPAddress } }
    $gw = @()
    foreach($g in @($_.IPv4DefaultGateway)){ if($g.NextHop){ $gw += [string]$g.NextHop } }
    foreach($g in @($_.IPv6DefaultGateway)){ if($g.NextHop){ $gw += [string]$g.NextHop } }
    $dns = @()
    foreach($d in @($_.DNSServer)){ foreach($s in @($d.ServerAddresses)){ if($s){ $dns += [string]$s } } }
    $out += [PSCustomObject]@{
      name = $if
      description = $desc
      mac = $mac
      ip = ($ips -join ',')
      gateway = ($gw -join ',')
      dns = ($dns -join ',')
      status = if($_.NetAdapter.Status){ [string]$_.NetAdapter.Status } else { '' }
      inventory = 'netif'
    }
  }
} catch {
  try {
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
      $out += [PSCustomObject]@{
        name = [string]$_.Description
        description = [string]$_.Description
        mac = [string]$_.MACAddress
        ip = (($_.IPAddress) -join ',')
        gateway = (($_.DefaultIPGateway) -join ',')
        dns = (($_.DNSServerSearchOrder) -join ',')
        status = 'Up'
        inventory = 'netif'
      }
    }
  } catch {}
}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":        name,
			"description": asString(r["description"]),
			"mac":         asString(r["mac"]),
			"ip":          asString(r["ip"]),
			"gateway":     asString(r["gateway"]),
			"dns":         asString(r["dns"]),
			"status":      asString(r["status"]),
			"inventory":   "netif",
		})
	}
	return truncateItems(out), nil
}

// collectGroups：本地用户组及成员（资产基线）。
func collectGroups() ([]any, error) {
	ps := `
$out = @()
try {
  Get-LocalGroup | ForEach-Object {
    $g = $_
    $members = @()
    try {
      Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object {
        $members += [string]($_.Name)
      }
    } catch {}
    $out += [PSCustomObject]@{
      name = [string]$g.Name
      description = [string]$g.Description
      sid = [string]$g.SID
      members = ($members -join '; ')
      member_count = $members.Count
      source = 'local_group'
      inventory = 'groups'
    }
  }
} catch {}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":         name,
			"description":  asString(r["description"]),
			"sid":          asString(r["sid"]),
			"members":      asString(r["members"]),
			"member_count": asInt(r["member_count"]),
			"source":       asString(r["source"]),
			"inventory":    "groups",
		})
	}
	return truncateItems(out), nil
}

// collectFirewall：启用中的防火墙规则（轻量字段，避免全量 PortFilter 联表拖死）。
func collectFirewall() ([]any, error) {
	ps := `
$out = @()
try {
  Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 450 | ForEach-Object {
    $out += [PSCustomObject]@{
      name = [string]$_.Name
      display_name = [string]$_.DisplayName
      direction = [string]$_.Direction
      action = [string]$_.Action
      profile = [string]$_.Profile
      enabled = [bool]$_.Enabled
      inventory = 'firewall'
    }
  }
} catch {}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			name = asString(r["display_name"])
		}
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":         name,
			"display_name": asString(r["display_name"]),
			"direction":    asString(r["direction"]),
			"action":       asString(r["action"]),
			"profile":      asString(r["profile"]),
			"enabled":      r["enabled"],
			"inventory":    "firewall",
		})
	}
	return truncateItems(out), nil
}

// collectShares：SMB 共享清单。
func collectShares() ([]any, error) {
	ps := `
$out = @()
try {
  Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
    $out += [PSCustomObject]@{
      name = [string]$_.Name
      path = [string]$_.Path
      description = [string]$_.Description
      share_type = [string]$_.ShareType
      current_users = [int]$_.CurrentUsers
      encrypt = [bool]$_.EncryptData
      caching = [string]$_.CachingMode
      folder_enum = [string]$_.FolderEnumerationMode
      inventory = 'shares'
    }
  }
} catch {
  try {
    Get-CimInstance Win32_Share | ForEach-Object {
      $out += [PSCustomObject]@{
        name = [string]$_.Name
        path = [string]$_.Path
        description = [string]$_.Description
        share_type = [string]$_.Type
        current_users = 0
        encrypt = $false
        caching = ''
        folder_enum = ''
        inventory = 'shares'
      }
    }
  } catch {}
}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":          name,
			"path":          asString(r["path"]),
			"description":   asString(r["description"]),
			"share_type":    asString(r["share_type"]),
			"current_users": asInt(r["current_users"]),
			"encrypt":       r["encrypt"],
			"caching":       asString(r["caching"]),
			"inventory":     "shares",
		})
	}
	return truncateItems(out), nil
}

// collectCerts：计算机证书（个人 + 受信任根截断）。
func collectCerts() ([]any, error) {
	ps := `
$out = @()
function Add-Cert($c, $store) {
  if(-not $c){ return }
  $notAfter = ''
  try { if($c.NotAfter){ $notAfter = $c.NotAfter.ToString('s') } } catch {}
  $notBefore = ''
  try { if($c.NotBefore){ $notBefore = $c.NotBefore.ToString('s') } } catch {}
  $out.Add([PSCustomObject]@{
    name = [string]$c.Subject
    issuer = [string]$c.Issuer
    thumbprint = [string]$c.Thumbprint
    store = $store
    not_before = $notBefore
    not_after = $notAfter
    has_private = [bool]$c.HasPrivateKey
    inventory = 'certs'
  }) | Out-Null
}
$out = [System.Collections.Generic.List[object]]::new()
try {
  Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object { Add-Cert $_ 'LocalMachine\\My' }
} catch {}
try {
  Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Select-Object -First 120 | ForEach-Object { Add-Cert $_ 'LocalMachine\\Root' }
} catch {}
try {
  Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue | Select-Object -First 80 | ForEach-Object { Add-Cert $_ 'LocalMachine\\TrustedPublisher' }
} catch {}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		tp := asString(r["thumbprint"])
		subj := asString(r["name"])
		if tp == "" && subj == "" {
			continue
		}
		key := strings.ToLower(tp + "|" + asString(r["store"]))
		if tp != "" && seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, map[string]any{
			"name":        subj,
			"issuer":      asString(r["issuer"]),
			"thumbprint":  tp,
			"store":       asString(r["store"]),
			"not_before":  asString(r["not_before"]),
			"not_after":   asString(r["not_after"]),
			"has_private": r["has_private"],
			"inventory":   "certs",
		})
	}
	return truncateItems(out), nil
}

// collectUSB：当前 PnP USB 设备快照（补 device_watch 事件流）。
func collectUSB() ([]any, error) {
	ps := `
$out = @()
try {
  Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
    $_.InstanceId -like 'USB*'
  } | Select-Object -First 400 | ForEach-Object {
    $out += [PSCustomObject]@{
      name = [string]$_.FriendlyName
      class = [string]$_.Class
      status = [string]$_.Status
      manufacturer = [string]$_.Manufacturer
      instance_id = [string]$_.InstanceId
      service = [string]$_.Service
      inventory = 'usb'
    }
  }
} catch {
  try {
    Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -like 'USB*' } | Select-Object -First 300 | ForEach-Object {
      $out += [PSCustomObject]@{
        name = [string]$_.Name
        class = [string]$_.PNPClass
        status = [string]$_.Status
        manufacturer = [string]$_.Manufacturer
        instance_id = [string]$_.DeviceID
        service = [string]$_.Service
        inventory = 'usb'
      }
    }
  } catch {}
}
$out
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		id := asString(r["instance_id"])
		name := asString(r["name"])
		if id == "" && name == "" {
			continue
		}
		key := strings.ToLower(id)
		if key != "" && seen[key] {
			continue
		}
		if key != "" {
			seen[key] = true
		}
		out = append(out, map[string]any{
			"name":         name,
			"class":        asString(r["class"]),
			"status":       asString(r["status"]),
			"manufacturer": asString(r["manufacturer"]),
			"instance_id":  id,
			"service":      asString(r["service"]),
			"inventory":    "usb",
		})
	}
	return truncateItems(out), nil
}

// collectBrowserExt：各用户 Chrome/Edge/Firefox 扩展（读 manifest，不读历史）。
func collectBrowserExt() ([]any, error) {
	var out []any
	seen := map[string]bool{}
	add := func(item map[string]any) {
		if len(out) >= maxItems {
			return
		}
		key := strings.ToLower(asString(item["browser"]) + "|" + asString(item["ext_id"]) + "|" + asString(item["user"]) + "|" + asString(item["version"]))
		if key == "|||" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, item)
	}
	type browserRoot struct {
		browser string
		rel     string
	}
	roots := []browserRoot{
		{"chrome", `AppData\Local\Google\Chrome\User Data`},
		{"edge", `AppData\Local\Microsoft\Edge\User Data`},
		{"brave", `AppData\Local\BraveSoftware\Brave-Browser\User Data`},
	}
	for _, p := range userProfiles() {
		for _, br := range roots {
			base := filepath.Join(p.dir, br.rel)
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				name := e.Name()
				if name != "Default" && !strings.HasPrefix(name, "Profile") {
					continue
				}
				extRoot := filepath.Join(base, name, "Extensions")
				extDirs, err := os.ReadDir(extRoot)
				if err != nil {
					continue
				}
				for _, ed := range extDirs {
					if !ed.IsDir() || strings.HasPrefix(ed.Name(), ".") {
						continue
					}
					verDirs, err := os.ReadDir(filepath.Join(extRoot, ed.Name()))
					if err != nil || len(verDirs) == 0 {
						continue
					}
					// 取最新版本目录名（字典序近似）
					verName := ""
					for _, vd := range verDirs {
						if vd.IsDir() {
							verName = vd.Name()
						}
					}
					if verName == "" {
						continue
					}
					manPath := filepath.Join(extRoot, ed.Name(), verName, "manifest.json")
					b, err := os.ReadFile(manPath)
					if err != nil {
						continue
					}
					var man map[string]any
					if json.Unmarshal(b, &man) != nil {
						continue
					}
					extName := asString(man["name"])
					if strings.HasPrefix(extName, "__MSG_") {
						extName = ed.Name()
					}
					if extName == "" {
						extName = ed.Name()
					}
					add(map[string]any{
						"name":      extName,
						"ext_id":    ed.Name(),
						"version":   asString(man["version"]),
						"browser":   br.browser,
						"profile":   name,
						"user":      p.name,
						"path":      filepath.Join(extRoot, ed.Name(), verName),
						"inventory": "browser_ext",
					})
					if len(out) >= maxItems {
						return out, nil
					}
				}
			}
		}
		// Firefox
		ffBase := filepath.Join(p.dir, `AppData\Roaming\Mozilla\Firefox\Profiles`)
		ffProfiles, err := os.ReadDir(ffBase)
		if err == nil {
			for _, fp := range ffProfiles {
				if !fp.IsDir() {
					continue
				}
				extJSON := filepath.Join(ffBase, fp.Name(), "extensions.json")
				b, err := os.ReadFile(extJSON)
				if err != nil {
					continue
				}
				var root map[string]any
				if json.Unmarshal(b, &root) != nil {
					continue
				}
				addons, _ := root["addons"].([]any)
				for _, a := range addons {
					am, ok := a.(map[string]any)
					if !ok {
						continue
					}
					id := asString(am["id"])
					if id == "" {
						continue
					}
					def, _ := am["defaultLocale"].(map[string]any)
					name := asString(def["name"])
					if name == "" {
						name = id
					}
					add(map[string]any{
						"name":      name,
						"ext_id":    id,
						"version":   asString(am["version"]),
						"browser":   "firefox",
						"profile":   fp.Name(),
						"user":      p.name,
						"path":      asString(am["path"]),
						"inventory": "browser_ext",
					})
					if len(out) >= maxItems {
						return out, nil
					}
				}
			}
		}
	}
	return out, nil
}

// collectHotfix：CBS Packages 中的 KB（多源去重的轻量实现）。
func collectHotfix() ([]any, error) {
	return collectHotfixLimited(maxItems)
}

func collectHotfixLimited(limit int) ([]any, error) {
	ps := `
$seen = @{}
$out = @()
try {
  Get-HotFix | ForEach-Object {
    $id = [string]$_.HotFixID
    if(-not $id -or $seen.ContainsKey($id)){ return }
    $seen[$id] = $true
    $out += [PSCustomObject]@{
      kb = $id
      description = [string]$_.Description
      installed_on = if($_.InstalledOn){ $_.InstalledOn.ToString('s') } else { '' }
      installed_by = [string]$_.InstalledBy
      source = 'Get-HotFix'
    }
  }
} catch {}
try {
  $k = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages' -ErrorAction SilentlyContinue
  if($k){
    Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
      $n = $_.PSChildName
      if($n -match 'KB(\d{6,})'){
        $id = 'KB' + $Matches[1]
        if($seen.ContainsKey($id)){ return }
        $seen[$id] = $true
        $out += [PSCustomObject]@{
          kb = $id
          description = 'CBS Package'
          installed_on = ''
          installed_by = ''
          source = 'CBS'
        }
      }
    }
  }
} catch {}
$out | Sort-Object kb
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		kb := asString(r["kb"])
		if kb == "" {
			continue
		}
		out = append(out, map[string]any{
			"kb":           kb,
			"description":  asString(r["description"]),
			"installed_on": asString(r["installed_on"]),
			"installed_by": asString(r["installed_by"]),
			"source":       asString(r["source"]),
			"inventory":    "hotfix",
		})
	}
	return truncateItemsAt(out, limit), nil
}

// collectListen：仅监听端口（与 network 连接表分离，对标 Wazuh ports）。
func collectListen() ([]any, error) {
	items, err := collectNetwork()
	if err != nil {
		return nil, err
	}
	var out []any
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		state := strings.ToUpper(asString(m["state"]))
		proto := strings.ToUpper(asString(m["proto"]))
		remote := asString(m["remote"])
		isListen := state == "LISTENING" || state == "LISTEN"
		if !isListen && strings.HasPrefix(proto, "UDP") {
			// UDP 无 LISTEN 态：远端为 *:* / 0.0.0.0:* 视为监听
			if remote == "*.*" || remote == "*:*" || strings.HasSuffix(remote, ":*") || remote == "0.0.0.0:0" || remote == "[::]:0" {
				isListen = true
			}
		}
		if !isListen {
			continue
		}
		out = append(out, map[string]any{
			"proto":        proto,
			"local":        asString(m["local"]),
			"state":        state,
			"pid":          asInt(m["pid"]),
			"process_name": asString(m["process_name"]),
			"inventory":    "listen",
			"collected_at": time.Now().Format("2006-01-02T15:04:05"),
		})
	}
	return truncateItems(out), nil
}
