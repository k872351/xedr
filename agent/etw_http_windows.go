//go:build windows

package main

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// WinINet / WebIO：补齐 Host/URL（内核 TCP 外联只有 IP:Port）。

var (
	guidWinINet = etw.MustParseGUIDFromString("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}")
	guidWebIO   = etw.MustParseGUIDFromString("{50B3E73C-9370-461D-BB9F-26F32D68887D}")
)

// WinINet：HTTP 句柄创建相关；关键词 HANDLES|HTTP|HTTPS = 0x13
const winINetHTTPKeywords = uint64(0x1 | 0x2 | 0x10)

// WebIO：API 关键词即可拿到 CreateHttpRequest
const webIOAPIKeyword = uint64(0x1)

var winINetWantIDs = map[uint16]bool{
	102: true, // InternetOpenURL → URL
	103: true, // InternetConnect → Server:Port
	104: true, // HttpOpenRequest → Verb + Target
	105: true, // HttpSendRequest / headers
	106: true, // response / status（若 provider 暴露）
	108: true, // Server Details
	541: true, // WININET_HTTP_RESPONSE（部分系统）
}

var webIOWantIDs = map[uint16]bool{
	17: true, // WebCreateHttpRequest → URI/Method/Server
	21: true, // response-ish（兼容不同 manifest）
}

type httpDedupe struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var httpETWDedup = &httpDedupe{seen: map[string]time.Time{}}

func (d *httpDedupe) allow(key string, window time.Duration) bool {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.seen[key]; ok && now.Sub(t) < window {
		return false
	}
	d.seen[key] = now
	if len(d.seen) > 20000 {
		for k, t := range d.seen {
			if now.Sub(t) > window {
				delete(d.seen, k)
			}
		}
	}
	return true
}

func propAny(e *etw.Event, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(propStr(e, k)); v != "" && v != "0" && !strings.EqualFold(v, "null") {
			return v
		}
	}
	// 容错：属性名大小写/前缀不一致时扫一遍
	want := map[string]bool{}
	for _, k := range keys {
		want[strings.ToLower(k)] = true
	}
	for k, v := range e.EventData {
		lk := strings.ToLower(k)
		if !want[lk] {
			continue
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" && s != "0" {
			return s
		}
	}
	return ""
}

func (st *etwNativeState) convertWinINet(e *etw.Event, ts string) map[string]any {
	id := e.System.EventID
	if !winINetWantIDs[id] {
		return nil
	}
	pid := uint32(e.System.Execution.ProcessID)
	p := st.proc(pid)
	if httpBrowserNoise(p.name) {
		return nil
	}
	host, port, rawURL, method, path, status := "", "", "", "", "", ""
	switch id {
	case 102:
		rawURL = propAny(e, "URL", "Url", "url")
	case 103:
		host = propAny(e, "ServerName", "Server", "HostName", "Host")
		port = propAny(e, "ServerPort", "Port")
	case 104, 105:
		method = propAny(e, "Verb", "Method", "HttpMethod")
		path = propAny(e, "ObjectName", "Target", "Object", "Path")
		rawURL = propAny(e, "URL", "Url", "url")
	case 106, 541:
		host = propAny(e, "ServerName", "Server", "HostName", "Host")
		port = propAny(e, "ServerPort", "Port")
		status = propAny(e, "StatusCode", "Status", "HttpStatus", "ResponseCode", "StatusText")
		path = propAny(e, "ObjectName", "Target", "Object", "Path", "URI")
		method = propAny(e, "Verb", "Method", "HttpMethod")
	case 108:
		host = propAny(e, "ServerName", "Server", "HostName", "Host")
		port = propAny(e, "ServerPort", "Port")
	}
	return st.emitHTTPRequest(ts, "wininet", pid, p.name, host, port, rawURL, method, path, status)
}

func (st *etwNativeState) convertWebIO(e *etw.Event, ts string) map[string]any {
	id := e.System.EventID
	if !webIOWantIDs[id] {
		return nil
	}
	pid := uint32(e.System.Execution.ProcessID)
	p := st.proc(pid)
	if httpBrowserNoise(p.name) {
		return nil
	}
	rawURL := propAny(e, "URI", "Url", "URL", "RequestURI")
	method := propAny(e, "Method", "HttpMethod", "Verb")
	host := propAny(e, "ServerName", "Server", "HostName", "Host")
	port := propAny(e, "ServerPort", "Port")
	status := propAny(e, "StatusCode", "Status", "HttpStatus", "ResponseCode")
	return st.emitHTTPRequest(ts, "webio", pid, p.name, host, port, rawURL, method, "", status)
}

func (st *etwNativeState) emitHTTPRequest(ts, src string, pid uint32, proc, host, port, rawURL, method, path, status string) map[string]any {
	if rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil {
			if host == "" {
				host = u.Hostname()
			}
			if port == "" {
				port = u.Port()
			}
			if path == "" {
				path = u.RequestURI()
				if path == "" {
					path = u.Path
				}
			}
			if method == "" {
				// OpenURL 常无 method
			}
			if u.Scheme != "" && port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else if u.Scheme == "http" {
					port = "80"
				}
			}
		} else if host == "" {
			// 非标准 URL：尽量当 host/path
			host = rawURL
		}
	}
	host = strings.TrimSpace(strings.ToLower(host))
	path = strings.TrimSpace(path)
	method = strings.ToUpper(strings.TrimSpace(method))
	if host == "" && rawURL == "" && path == "" {
		return nil
	}
	if host == "" && path != "" {
		// HttpOpenRequest 只有 Target，等 InternetConnect 才能拼 host；单独 Target 噪声大
		return nil
	}
	key := fmt.Sprintf("%d|%s|%s|%s|%s|%s", pid, host, port, method, path, status)
	if !httpETWDedup.allow(key, 2*time.Minute) {
		return nil
	}
	now := time.Now()
	detail := map[string]any{
		"source": src, "pid": pid, "host": host, "port": port,
	}
	if proc != "" {
		detail["process_name"] = proc
	}
	if method != "" {
		detail["method"] = method
	}
	if path != "" {
		detail["url_path"] = path
	}
	if rawURL != "" {
		detail["url"] = rawURL
	}
	status = strings.TrimSpace(status)
	if status != "" {
		// 归一成数字状态码（若夹带文字）
		code := status
		for i := 0; i < len(status); i++ {
			if status[i] < '0' || status[i] > '9' {
				if i > 0 {
					code = status[:i]
				}
				break
			}
		}
		detail["status_code"] = code
		if code != status {
			detail["status_text"] = status
		}
	}
	target := host
	if port != "" {
		target = host + ":" + port
	}
	if path != "" {
		target = target + path
	}
	atFT := filetimeOf(now)
	procEntities.annotate(detail, atFT)
	attachHostProcessDetails(detail, atFT)
	beaconWatch.observeHTTP(detail, now)
	sev := "info"
	sum := fmt.Sprintf("HTTP请求(%s): %s → %s", src, nameOr2(proc, pid), target)
	if status != "" {
		sum = fmt.Sprintf("HTTP响应(%s): %s → %s [%s]", src, nameOr2(proc, pid), target, status)
	}
	if pathLooksHot(asString(detail["path"])) || pathLooksHot(asString(detail["process_path"])) {
		sev = "medium"
		sum = "可疑路径进程HTTP: " + nameOr2(proc, pid) + " → " + target
	}
	return map[string]any{
		"etype": "http_request_etw", "summary": sum, "severity": sev, "ts": ts, "detail": detail,
	}
}
