//go:build windows

package main

import (
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

// peFileMeta 磁盘 PE 静态元数据（编译时间 / imphash / 节熵），供文件与进程遥测 enrichment。
type peFileMeta struct {
	Path           string
	CompileTS      uint32
	CompileTime    string // RFC3339 UTC
	CompileFuture  bool
	CompileAncient bool
	ImpHash        string
	Sections       []peSectionMeta
	MaxEntropy     float64
	PackedLikely   bool
	Is64           bool
	SizeOfImage    uint32
}

type peSectionMeta struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	RawSize uint32  `json:"raw_size"`
	VirtSize uint32 `json:"virt_size"`
	Exec    bool    `json:"exec"`
}

type peFileMetaCacheEntry struct {
	meta    *peFileMeta
	err     error
	size    int64
	mod     time.Time
	touched time.Time
}

var (
	peFileMetaMu    sync.Mutex
	peFileMetaCache = map[string]*peFileMetaCacheEntry{}
)

const peFileMetaCacheMax = 1024
const peEntropySampleMax = 256 << 10 // 每节最多采样 256KB

func peFileMetaOf(path string) (*peFileMeta, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(path)
	peFileMetaMu.Lock()
	if e, ok := peFileMetaCache[key]; ok && e.size == fi.Size() && e.mod.Equal(fi.ModTime()) {
		e.touched = time.Now()
		peFileMetaMu.Unlock()
		return e.meta, e.err
	}
	peFileMetaMu.Unlock()

	meta, perr := parsePEFileMeta(path)
	peFileMetaMu.Lock()
	if len(peFileMetaCache) >= peFileMetaCacheMax {
		var oldK string
		var oldT time.Time
		for k, e := range peFileMetaCache {
			if oldK == "" || e.touched.Before(oldT) {
				oldK, oldT = k, e.touched
			}
		}
		delete(peFileMetaCache, oldK)
	}
	peFileMetaCache[key] = &peFileMetaCacheEntry{meta: meta, err: perr, size: fi.Size(), mod: fi.ModTime(), touched: time.Now()}
	peFileMetaMu.Unlock()
	return meta, perr
}

func parsePEFileMeta(path string) (*peFileMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	m := &peFileMeta{Path: path, CompileTS: pf.FileHeader.TimeDateStamp}
	// TimeDateStamp==0 / 0xFFFFFFFF 常见于 Go 与部分工具链；微软确定性构建会把哈希写入该字段（落在 1980 年前），不能当编译时间。
	if m.CompileTS != 0 && m.CompileTS != 0xFFFFFFFF {
		t := time.Unix(int64(m.CompileTS), 0).UTC()
		y := t.Year()
		if y >= 1980 && y <= 2100 {
			m.CompileTime = t.Format(time.RFC3339)
			now := time.Now().UTC()
			if t.After(now.Add(48 * time.Hour)) {
				m.CompileFuture = true
			}
			// 过旧编译时间仅作弱信号；系统目录由调用方忽略
			if y < 2000 {
				m.CompileAncient = true
			}
		}
	}

	var dirs []pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		m.Is64, m.SizeOfImage, dirs = true, oh.SizeOfImage, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader32:
		m.SizeOfImage, dirs = oh.SizeOfImage, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	default:
		return m, nil
	}

	for _, s := range pf.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		rawN := s.Size
		if rawN > peEntropySampleMax {
			rawN = peEntropySampleMax
		}
		ent := 0.0
		if rawN > 0 {
			buf := make([]byte, rawN)
			n, _ := s.ReadAt(buf, 0)
			if n > 0 {
				ent = shannonEntropy(buf[:n])
			}
		}
		exec := s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0
		sm := peSectionMeta{Name: name, Entropy: round2(ent), RawSize: s.Size, VirtSize: s.VirtualSize, Exec: exec}
		m.Sections = append(m.Sections, sm)
		if ent > m.MaxEntropy {
			m.MaxEntropy = ent
		}
		if exec && ent >= 7.0 && s.Size >= 512 {
			m.PackedLikely = true
		}
	}
	m.MaxEntropy = round2(m.MaxEntropy)

	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
		m.ImpHash = peImpHash(pf, f, dirs[pe.IMAGE_DIRECTORY_ENTRY_IMPORT])
	}
	return m, nil
}

// peImpHash 按 pefile/VirusTotal 约定：dll.func 小写逗号拼接后 MD5。
func peImpHash(pf *pe.File, f *os.File, dir pe.DataDirectory) string {
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return ""
	}
	type secMap struct {
		va, vsize, off, rawLen uint32
	}
	var secs []secMap
	for _, s := range pf.Sections {
		secs = append(secs, secMap{s.VirtualAddress, s.VirtualSize, s.Offset, s.Size})
	}
	rvaRead := func(rva, n uint32) []byte {
		for _, s := range secs {
			if rva >= s.va && rva < s.va+max32(s.vsize, s.rawLen) {
				off := s.off + (rva - s.va)
				if off >= s.off+s.rawLen {
					return nil
				}
				avail := s.off + s.rawLen - off
				if n > avail {
					n = avail
				}
				buf := make([]byte, n)
				if _, err := f.ReadAt(buf, int64(off)); err != nil {
					return nil
				}
				return buf
			}
		}
		return nil
	}
	cstr := func(rva uint32) string {
		b := rvaRead(rva, 256)
		if len(b) == 0 {
			return ""
		}
		if i := indexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		return string(b)
	}

	var parts []string
	for i := uint32(0); i+20 <= dir.Size && i/20 < 2048; i += 20 {
		desc := rvaRead(dir.VirtualAddress+i, 20)
		if len(desc) < 20 {
			break
		}
		ilt := binary.LittleEndian.Uint32(desc[0:])
		nameRVA := binary.LittleEndian.Uint32(desc[12:])
		iat := binary.LittleEndian.Uint32(desc[16:])
		if ilt == 0 && nameRVA == 0 && iat == 0 {
			break
		}
		dll := strings.ToLower(cstr(nameRVA))
		if dll == "" {
			continue
		}
		thunk := ilt
		if thunk == 0 {
			thunk = iat
		}
		width := uint32(4)
		ordFlag := uint32(0x80000000)
		if pf.Machine == pe.IMAGE_FILE_MACHINE_AMD64 || pf.Machine == pe.IMAGE_FILE_MACHINE_ARM64 {
			width = 8
			ordFlag = 0x80000000 // still check high bit on low 32 for compatibility; 64-bit uses bit 63
		}
		for t := uint32(0); t/width < 4096; t += width {
			raw := rvaRead(thunk+t, width)
			if len(raw) < int(width) {
				break
			}
			var val uint64
			if width == 8 {
				val = binary.LittleEndian.Uint64(raw)
			} else {
				val = uint64(binary.LittleEndian.Uint32(raw))
			}
			if val == 0 {
				break
			}
			var fn string
			isOrd := false
			if width == 8 {
				isOrd = val&0x8000000000000000 != 0
			} else {
				isOrd = uint32(val)&ordFlag != 0
			}
			if isOrd {
				fn = fmt.Sprintf("ord%d", val&0xffff)
			} else {
				nb := rvaRead(uint32(val&0xffffffff)+2, 128)
				if len(nb) == 0 {
					continue
				}
				if j := indexByte(nb, 0); j >= 0 {
					nb = nb[:j]
				}
				fn = string(nb)
			}
			parts = append(parts, dll+"."+strings.ToLower(fn))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, x := range b {
		freq[x]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func peExtHot(path string) bool {
	ext := strings.ToLower(filepathExt(path))
	switch ext {
	case ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".drv":
		return true
	default:
		return false
	}
}

func filepathExt(path string) string {
	base := path
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		base = path[i+1:]
	}
	if i := strings.LastIndex(base, "."); i >= 0 {
		return base[i:]
	}
	return ""
}
