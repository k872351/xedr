package main

// Wire format of the DataProtector driver policy port (\DataProtectorPolicyPort).
// Mirrors agent/driver/dataprotector/DataProtector.h; all little-endian, default packing.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	dpMsgVersion   = 1
	dpMsgHeaderLen = 16

	dpCmdSetHashProtectPolicy = 81
	dpCmdSetLateralPolicy     = 91
	dpCmdQueryThreatEvents    = 140
	dpCmdSetThreatPolicy      = 142
	dpCmdSetStaticScanPolicy       = 161
	dpCmdQueryStaticScanRequests   = 164
	dpCmdSubmitStaticScanVerdict   = 165
	dpCmdSetCryptoKeys             = 170
	dpCmdQueryCryptoStatus         = 171

	dpStaticScanPathChars    = 512
	dpStaticScanProcessChars = 64
	dpStaticScanReasonChars  = 256
	dpStaticScanReqHeaderLen = 24
	dpStaticScanReqEntryLen  = 8*4 + 4*4 + dpStaticScanPathChars*2 + dpStaticScanProcessChars*2 // 1200
	dpStaticScanVerdictLen   = 4*4 + 8*3 + 4*4 + dpStaticScanPathChars*2 + dpStaticScanReasonChars*2 // 1592

	dpStaticVerdictClean      = 0
	dpStaticVerdictLowRisk    = 1
	dpStaticVerdictSuspicious = 2
	dpStaticVerdictMalicious  = 3

	dpThreatHeaderLen = 24
	dpThreatEntryLen  = 1488 // 5*u64 + 10*u32 + WCHAR[320] + WCHAR[384]
	dpThreatImageOff  = 80
	dpThreatImageLen  = 640
	dpThreatDetailOff = 720
	dpThreatDetailLen = 768

	dpCryptoKeyBytes  = 32
	dpCryptoMaxKeys   = 8
	dpCryptoKeysLen   = 16 + dpCryptoMaxKeys*(4+dpCryptoKeyBytes)
	dpCryptoStatusLen = 16 + dpCryptoMaxKeys*4
)

// Policy flag sets: audit (XEDR default) vs block (the reference project's original defaults).
const (
	dpThreatFlagsAudit  = 0x01 | 0x02 | 0x04 | 0x40
	dpThreatFlagsBlock  = 0x01 | 0x02 | 0x04 | 0x08 | 0x10
	dpHashFlagsAudit    = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20
	dpHashFlagsBlock    = 0x01 | 0x02 | 0x04 | 0x08 | 0x10
	dpLateralFlagsAudit = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20
	dpLateralFlagsBlock = 0x01 | 0x02 | 0x04 | 0x08 | 0x10
	dpStaticFlagsAudit  = 0x01 | 0x02 | 0x04 | 0x20
	dpStaticFlagsBlock  = 0x01 | 0x02 | 0x04 | 0x08
)

func dpMessage(cmd uint32, value []byte) []byte {
	msg := make([]byte, dpMsgHeaderLen+len(value))
	binary.LittleEndian.PutUint32(msg[0:4], dpMsgVersion)
	binary.LittleEndian.PutUint32(msg[4:8], cmd)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(len(value)))
	copy(msg[dpMsgHeaderLen:], value)
	return msg
}

// dpPolicyStruct encodes {Version, Flags, 0...} padded to size bytes.
func dpPolicyStruct(size int, flags uint32) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b[0:4], 1)
	binary.LittleEndian.PutUint32(b[4:8], flags)
	return b
}

type dpKeyRing struct {
	ActiveKeyID uint32
	Keys        map[uint32][]byte
}

// parseDPCrypto reads the platform's dp_crypto bundle: {"active_key_id": n, "keys": [{"id": n, "key": base64}]}.
func parseDPCrypto(m map[string]any) (*dpKeyRing, error) {
	if m == nil {
		return nil, nil
	}
	ring := &dpKeyRing{Keys: map[uint32][]byte{}}
	if n, ok := numberOf(m["active_key_id"]); ok && n > 0 {
		ring.ActiveKeyID = uint32(n)
	}
	arr, _ := m["keys"].([]any)
	for _, x := range arr {
		km, _ := x.(map[string]any)
		id, ok := numberOf(km["id"])
		if !ok || id <= 0 {
			return nil, fmt.Errorf("dp_crypto: bad key id")
		}
		raw, err := base64.StdEncoding.DecodeString(asString(km["key"]))
		if err != nil || len(raw) != dpCryptoKeyBytes {
			return nil, fmt.Errorf("dp_crypto: key %d must be %d bytes", int(id), dpCryptoKeyBytes)
		}
		ring.Keys[uint32(id)] = raw
	}
	if len(ring.Keys) == 0 || len(ring.Keys) > dpCryptoMaxKeys {
		return nil, fmt.Errorf("dp_crypto: need 1..%d keys", dpCryptoMaxKeys)
	}
	if _, ok := ring.Keys[ring.ActiveKeyID]; !ok {
		return nil, fmt.Errorf("dp_crypto: active key %d not in ring", ring.ActiveKeyID)
	}
	return ring, nil
}

// encodeDPCryptoKeys builds DP_CRYPTO_KEYS.
func encodeDPCryptoKeys(r *dpKeyRing) []byte {
	b := make([]byte, dpCryptoKeysLen)
	binary.LittleEndian.PutUint32(b[0:4], 1)
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(r.Keys)))
	binary.LittleEndian.PutUint32(b[8:12], r.ActiveKeyID)
	off := 16
	for id, k := range r.Keys {
		binary.LittleEndian.PutUint32(b[off:off+4], id)
		copy(b[off+4:off+4+dpCryptoKeyBytes], k)
		off += 4 + dpCryptoKeyBytes
	}
	return b
}

func dpUTF16(b []byte, lenBytes uint32) string {
	if int(lenBytes) > len(b) {
		lenBytes = uint32(len(b))
	}
	u := make([]uint16, lenBytes/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

var dpSignalNames = map[uint32]string{
	1: "进程创建", 2: "可疑父子进程", 3: "LOLBin 执行", 4: "脚本解释器派生", 5: "Office 派生子进程",
	10: "访问 LSASS 句柄", 11: "访问凭据文件", 12: "访问注册表 Hive", 13: "裸磁盘读取",
	20: "远程线程注入", 21: "进程句柄篡改", 22: "可疑模块加载", 23: "ETW 篡改", 24: "未签名运行时被拒", 25: "安全工具被篡改",
	30: "远程服务工具", 31: "远程计划任务", 32: "远程 WMI 执行", 33: "远程 PowerShell", 34: "SMB 投递可执行文件", 35: "远程 IPC 控制",
	40: "C2 连接被拦", 41: "可疑 DNS 信标", 42: "SMTP 外泄",
	50: "WebShell 落地", 51: "勒索式批量文件访问", 52: "敏感数据收集", 53: "移动介质暂存",
	60: "恶意可执行文件写入", 61: "可疑可执行文件写入", 62: "加壳可执行文件写入",
}

var dpTacticNames = map[uint32]string{
	1: "执行", 2: "持久化", 3: "权限提升", 4: "防御绕过", 5: "凭据访问", 6: "发现",
	7: "横向移动", 8: "收集", 9: "数据外泄", 10: "命令与控制", 11: "影响",
}

var dpResponseNames = map[uint32]string{0: "none", 1: "audit", 2: "alert", 3: "block", 4: "isolate", 5: "terminate"}

func dpSeverity(s uint32) string {
	switch s {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	}
	return "info"
}

// filetimeToLocal converts KeQuerySystemTime (100ns since 1601-01-01 UTC).
func filetimeToLocal(ft uint64) time.Time {
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Now()
	}
	return time.Unix(0, int64(ft-epochDiff)*100).Local()
}

// parseDPThreatEvents turns a DP_THREAT_EVENT_QUERY buffer into timeline events.
func parseDPThreatEvents(buf []byte) ([]map[string]any, error) {
	if len(buf) < dpThreatHeaderLen {
		return nil, fmt.Errorf("short threat header")
	}
	returned := binary.LittleEndian.Uint32(buf[12:16])
	if int(returned) > len(buf) {
		returned = uint32(len(buf))
	}
	var out []map[string]any
	for off := dpThreatHeaderLen; off+dpThreatEntryLen <= int(returned); off += dpThreatEntryLen {
		e := buf[off : off+dpThreatEntryLen]
		u64 := func(i int) uint64 { return binary.LittleEndian.Uint64(e[i:]) }
		u32 := func(i int) uint32 { return binary.LittleEndian.Uint32(e[i:]) }
		signal, tactic, tech := u32(40), u32(44), u32(48)
		image := dpUTF16(e[dpThreatImageOff:dpThreatImageOff+dpThreatImageLen], u32(72))
		detail := dpUTF16(e[dpThreatDetailOff:dpThreatDetailOff+dpThreatDetailLen], u32(76))
		name := filepath.Base(strings.ReplaceAll(image, "/", `\`))
		sigName := dpSignalNames[signal]
		if sigName == "" {
			sigName = fmt.Sprintf("signal %d", signal)
		}
		technique := ""
		if tech > 0 {
			technique = fmt.Sprintf("T%04d", tech)
		}
		sum := "驱动检测: " + sigName
		if name != "" && name != "." {
			sum += " · " + name
		}
		out = append(out, map[string]any{
			"etype":    "dp_threat",
			"summary":  sum,
			"severity": dpSeverity(u32(60)),
			"ts":       filetimeToLocal(u64(8)).Format("2006-01-02T15:04:05"),
			"detail": map[string]any{
				"source": "dp_driver", "sequence": u64(0),
				"pid": u64(16), "ppid": u64(24), "lineage_root_pid": u64(32),
				"signal": signal, "signal_name": sigName,
				"tactic": tactic, "tactic_name": dpTacticNames[tactic], "technique": technique,
				"score_delta": u32(52), "score": u32(56),
				"response": dpResponseNames[u32(64)], "response_status": fmt.Sprintf("0x%08X", u32(68)),
				"path": image, "process_name": name, "matched": detail,
			},
		})
	}
	return out, nil
}
