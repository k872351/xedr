//go:build windows

package main

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 磁盘 PE 视图：内存完整性比对用。只缓存头部、节表、重定位位置与导出表，按需 ReadAt 读字节。

type diskSection struct {
	va, vsize   uint32
	off, rawLen uint32
	exec        bool
}

type diskPE struct {
	path        string
	is64        bool
	timeStamp   uint32
	sizeOfImage uint32
	sections    []diskSection
	relocRVA    []uint32 // 升序
	relocWidth  []uint8
	eatRVA      uint32   // 导出地址表在镜像中的 RVA
	eat         []uint32 // 磁盘 EAT（函数 RVA）
	exportName  map[uint32]string
	exportSort  []uint32 // 代码导出 RVA 升序，用于就近命名
	iatRVA      uint32
	iatSize     uint32
}

type diskPECacheEntry struct {
	pe      *diskPE
	err     error
	size    int64
	mod     time.Time
	touched time.Time
}

var (
	diskPEMu    sync.Mutex
	diskPECache = map[string]*diskPECacheEntry{}
)

const diskPECacheMax = 512

func loadDiskPE(path string) (*diskPE, error) {
	key := strings.ToLower(path)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	diskPEMu.Lock()
	if e, ok := diskPECache[key]; ok && e.size == fi.Size() && e.mod.Equal(fi.ModTime()) {
		e.touched = time.Now()
		diskPEMu.Unlock()
		return e.pe, e.err
	}
	diskPEMu.Unlock()

	p, perr := parseDiskPE(path)
	diskPEMu.Lock()
	if len(diskPECache) >= diskPECacheMax {
		var oldK string
		var oldT time.Time
		for k, e := range diskPECache {
			if oldK == "" || e.touched.Before(oldT) {
				oldK, oldT = k, e.touched
			}
		}
		delete(diskPECache, oldK)
	}
	diskPECache[key] = &diskPECacheEntry{pe: p, err: perr, size: fi.Size(), mod: fi.ModTime(), touched: time.Now()}
	diskPEMu.Unlock()
	return p, perr
}

func parseDiskPE(path string) (*diskPE, error) {
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
	d := &diskPE{path: path, timeStamp: pf.FileHeader.TimeDateStamp, exportName: map[uint32]string{}}
	var dirs []pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		d.is64, d.sizeOfImage, dirs = true, oh.SizeOfImage, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader32:
		d.sizeOfImage, dirs = oh.SizeOfImage, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	default:
		return nil, errors.New("no optional header")
	}
	for _, s := range pf.Sections {
		d.sections = append(d.sections, diskSection{
			va: s.VirtualAddress, vsize: s.VirtualSize, off: s.Offset, rawLen: s.Size,
			exec: s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0,
		})
	}
	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
		d.parseRelocs(f, dirs[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC])
	}
	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		d.parseExports(f, dirs[pe.IMAGE_DIRECTORY_ENTRY_EXPORT])
	}
	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_IAT {
		d.iatRVA, d.iatSize = dirs[pe.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, dirs[pe.IMAGE_DIRECTORY_ENTRY_IAT].Size
	}
	return d, nil
}

func (d *diskPE) fileOff(rva uint32) (uint32, uint32, bool) {
	for _, s := range d.sections {
		if rva >= s.va && rva < s.va+s.rawLen {
			return s.off + (rva - s.va), s.rawLen - (rva - s.va), true
		}
	}
	return 0, 0, false
}

func (d *diskPE) readFrom(f *os.File, rva, n uint32) []byte {
	off, avail, ok := d.fileOff(rva)
	if !ok || n == 0 {
		return nil
	}
	if n > avail {
		n = avail
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, int64(off)); err != nil {
		return nil
	}
	return buf
}

// readRVA 读取磁盘镜像在 rva 处的 n 字节（按节映射到文件偏移）。
func (d *diskPE) readRVA(rva, n uint32) []byte {
	f, err := os.Open(d.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return d.readFrom(f, rva, n)
}

func (d *diskPE) parseRelocs(f *os.File, dir pe.DataDirectory) {
	if dir.VirtualAddress == 0 || dir.Size == 0 || dir.Size > 16<<20 {
		return
	}
	raw := d.readFrom(f, dir.VirtualAddress, dir.Size)
	for i := 0; i+8 <= len(raw); {
		page := binary.LittleEndian.Uint32(raw[i:])
		size := int(binary.LittleEndian.Uint32(raw[i+4:]))
		if size < 8 || i+size > len(raw) {
			break
		}
		for j := i + 8; j+2 <= i+size; j += 2 {
			e := binary.LittleEndian.Uint16(raw[j:])
			var w uint8
			switch e >> 12 {
			case 10: // DIR64
				w = 8
			case 3: // HIGHLOW
				w = 4
			default:
				continue
			}
			d.relocRVA = append(d.relocRVA, page+uint32(e&0xFFF))
			d.relocWidth = append(d.relocWidth, w)
		}
		i += size
	}
	if !sort.SliceIsSorted(d.relocRVA, func(a, b int) bool { return d.relocRVA[a] < d.relocRVA[b] }) {
		idx := make([]int, len(d.relocRVA))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return d.relocRVA[idx[a]] < d.relocRVA[idx[b]] })
		rv, rw := make([]uint32, len(idx)), make([]uint8, len(idx))
		for i, k := range idx {
			rv[i], rw[i] = d.relocRVA[k], d.relocWidth[k]
		}
		d.relocRVA, d.relocWidth = rv, rw
	}
}

// relocMask 标出 [rva, rva+n) 中被重定位改写的字节（这些字节内存与磁盘本来就不同）。
func (d *diskPE) relocMask(rva, n uint32) []bool {
	mask := make([]bool, n)
	start := uint32(0)
	if rva > 8 {
		start = rva - 8
	}
	i := sort.Search(len(d.relocRVA), func(k int) bool { return d.relocRVA[k] >= start })
	for ; i < len(d.relocRVA) && d.relocRVA[i] < rva+n; i++ {
		r, w := d.relocRVA[i], uint32(d.relocWidth[i])
		for b := r; b < r+w; b++ {
			if b >= rva && b < rva+n {
				mask[b-rva] = true
			}
		}
	}
	return mask
}

func (d *diskPE) parseExports(f *os.File, dir pe.DataDirectory) {
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return
	}
	hdr := d.readFrom(f, dir.VirtualAddress, 40)
	if len(hdr) < 40 {
		return
	}
	nFuncs := binary.LittleEndian.Uint32(hdr[20:])
	nNames := binary.LittleEndian.Uint32(hdr[24:])
	addrFuncs := binary.LittleEndian.Uint32(hdr[28:])
	addrNames := binary.LittleEndian.Uint32(hdr[32:])
	addrOrd := binary.LittleEndian.Uint32(hdr[36:])
	if nFuncs == 0 || nFuncs > 65536 || nNames > 65536 {
		return
	}
	eat := d.readFrom(f, addrFuncs, nFuncs*4)
	if len(eat) < int(nFuncs*4) {
		return
	}
	d.eatRVA = addrFuncs
	d.eat = make([]uint32, nFuncs)
	for i := range d.eat {
		d.eat[i] = binary.LittleEndian.Uint32(eat[i*4:])
	}
	names := d.readFrom(f, addrNames, nNames*4)
	ords := d.readFrom(f, addrOrd, nNames*2)
	if len(names) < int(nNames*4) || len(ords) < int(nNames*2) {
		return
	}
	for i := uint32(0); i < nNames; i++ {
		ord := binary.LittleEndian.Uint16(ords[i*2:])
		if uint32(ord) >= nFuncs {
			continue
		}
		rva := d.eat[ord]
		if rva >= dir.VirtualAddress && rva < dir.VirtualAddress+dir.Size {
			continue // 转发导出
		}
		nb := d.readFrom(f, binary.LittleEndian.Uint32(names[i*4:]), 128)
		if j := indexByte(nb, 0); j > 0 {
			d.exportName[rva] = string(nb[:j])
		}
	}
	for rva := range d.exportName {
		d.exportSort = append(d.exportSort, rva)
	}
	sort.Slice(d.exportSort, func(a, b int) bool { return d.exportSort[a] < d.exportSort[b] })
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// nearestExport 返回不大于 rva 的最近导出名及偏移。
func (d *diskPE) nearestExport(rva uint32) (string, uint32) {
	i := sort.Search(len(d.exportSort), func(k int) bool { return d.exportSort[k] > rva })
	if i == 0 {
		return "", 0
	}
	r := d.exportSort[i-1]
	return d.exportName[r], rva - r
}

func (d *diskPE) execSection(rva uint32) bool {
	for _, s := range d.sections {
		if s.exec && rva >= s.va && rva < s.va+max32(s.vsize, s.rawLen) {
			return true
		}
	}
	return false
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
