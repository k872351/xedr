//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// pollStaticScanLocked：驱动静态扫描闭环（审计模式）
// 读取请求 → 用户态轻量判定 → 回传 verdict → 记入时间线事件。
func (d *dpDriver) pollStaticScanLocked() {
	hdr := make([]byte, dpStaticScanReqHeaderLen)
	if _, err := d.sendLocked(dpCmdQueryStaticScanRequests, nil, hdr); err != nil {
		// 旧驱动可能不支持该命令，静默跳过
		return
	}
	count := binary.LittleEndian.Uint32(hdr[4:8])
	need := int(binary.LittleEndian.Uint32(hdr[8:12]))
	if count == 0 || need <= dpStaticScanReqHeaderLen {
		return
	}
	if need > dpMaxQueryBytes {
		need = dpMaxQueryBytes
	}
	buf := make([]byte, need)
	n, err := d.sendLocked(dpCmdQueryStaticScanRequests, nil, buf)
	if err != nil || n < dpStaticScanReqHeaderLen {
		return
	}
	returned := int(binary.LittleEndian.Uint32(buf[12:16]))
	if returned > n {
		returned = n
	}
	for off := dpStaticScanReqHeaderLen; off+dpStaticScanReqEntryLen <= returned; off += dpStaticScanReqEntryLen {
		e := buf[off : off+dpStaticScanReqEntryLen]
		reqID := binary.LittleEndian.Uint64(e[0:8])
		pid := binary.LittleEndian.Uint64(e[16:24])
		size := binary.LittleEndian.Uint64(e[24:32])
		op := binary.LittleEndian.Uint32(e[32:36])
		pathLen := binary.LittleEndian.Uint32(e[36:40])
		path := dpUTF16(e[48:48+dpStaticScanPathChars*2], pathLen)
		verdict, score, reason, reasonText := auditStaticScanFile(path, size)
		msg := encodeStaticScanVerdict(reqID, pid, size, op, path, verdict, score, reason, reasonText)
		if _, err := d.sendLocked(dpCmdSubmitStaticScanVerdict, msg, nil); err != nil {
			log.Printf("dp_driver: 回传静态扫描判定失败: %v", err)
			continue
		}
		if len(d.events) < 5000 {
			d.events = append(d.events, map[string]any{
				"etype":    "dp_static_scan",
				"summary":  fmt.Sprintf("静态扫描(审计): %s · %s", filepath.Base(path), staticVerdictName(verdict)),
				"severity": staticVerdictSeverity(verdict),
				"detail": map[string]any{
					"source": "dp_driver", "request_id": reqID, "pid": pid,
					"path": path, "size": size, "operation": op,
					"verdict": verdict, "score": score, "reason_flags": reason,
					"reason": reasonText, "mode": "audit",
				},
			})
		}
	}
}

func staticVerdictName(v uint32) string {
	switch v {
	case dpStaticVerdictMalicious:
		return "malicious"
	case dpStaticVerdictSuspicious:
		return "suspicious"
	case dpStaticVerdictLowRisk:
		return "low_risk"
	default:
		return "clean"
	}
}

func staticVerdictSeverity(v uint32) string {
	switch v {
	case dpStaticVerdictMalicious:
		return "high"
	case dpStaticVerdictSuspicious:
		return "medium"
	case dpStaticVerdictLowRisk:
		return "low"
	default:
		return "info"
	}
}

// auditStaticScanFile：用户态轻量启发式（审计模式，不自动处置）。
func auditStaticScanFile(path string, size uint64) (verdict, score, reason uint32, reasonText string) {
	verdict = dpStaticVerdictClean
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".sys", ".scr", ".com":
		reason |= 0x1 // VALID_PE-ish by extension
	case ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta":
		reason |= 0x100 // SCRIPT_DROPPER-ish
		score = 20
		verdict = dpStaticVerdictLowRisk
		reasonText = "script dropper extension"
	}
	low := strings.ToLower(path)
	if strings.Contains(low, `\users\public\`) || strings.Contains(low, `\temp\`) || strings.Contains(low, `\appdata\local\temp\`) {
		score += 25
		reason |= 0x10
		if reasonText == "" {
			reasonText = "written under temp/public"
		} else {
			reasonText += "; temp/public path"
		}
		if verdict < dpStaticVerdictSuspicious && score >= 40 {
			verdict = dpStaticVerdictSuspicious
		}
	}
	if size > 0 && size < 2048 && (ext == ".exe" || ext == ".dll") {
		score += 15
		reason |= 0x80 // TINY_IMAGE
		if verdict < dpStaticVerdictLowRisk {
			verdict = dpStaticVerdictLowRisk
		}
		if reasonText == "" {
			reasonText = "tiny image"
		}
	}
	// 可选：存在则读文件头确认 MZ（失败不影响闭环）
	if f, err := os.Open(path); err == nil {
		var hdr [2]byte
		_, _ = f.Read(hdr[:])
		_ = f.Close()
		if hdr[0] == 'M' && hdr[1] == 'Z' {
			reason |= 0x1
		}
	}
	if reasonText == "" {
		reasonText = "audit clean"
	}
	return verdict, score, reason, reasonText
}

func encodeStaticScanVerdict(reqID, pid, size uint64, op uint32, path string, verdict, score, reason uint32, reasonText string) []byte {
	b := make([]byte, dpStaticScanVerdictLen)
	binary.LittleEndian.PutUint32(b[0:4], 1) // version
	binary.LittleEndian.PutUint32(b[4:8], verdict)
	binary.LittleEndian.PutUint32(b[8:12], score)
	binary.LittleEndian.PutUint32(b[12:16], reason)
	binary.LittleEndian.PutUint64(b[16:24], reqID)
	binary.LittleEndian.PutUint64(b[24:32], pid)
	binary.LittleEndian.PutUint64(b[32:40], size)
	binary.LittleEndian.PutUint32(b[40:44], op)
	pathU := utf16.Encode([]rune(path))
	if len(pathU) > dpStaticScanPathChars {
		pathU = pathU[:dpStaticScanPathChars]
	}
	reasonU := utf16.Encode([]rune(reasonText))
	if len(reasonU) > dpStaticScanReasonChars {
		reasonU = reasonU[:dpStaticScanReasonChars]
	}
	binary.LittleEndian.PutUint32(b[44:48], uint32(len(pathU)*2))
	binary.LittleEndian.PutUint32(b[48:52], uint32(len(reasonU)*2))
	pathOff := 56
	for i, u := range pathU {
		binary.LittleEndian.PutUint16(b[pathOff+i*2:], u)
	}
	reasonOff := pathOff + dpStaticScanPathChars*2
	for i, u := range reasonU {
		binary.LittleEndian.PutUint16(b[reasonOff+i*2:], u)
	}
	return b
}
