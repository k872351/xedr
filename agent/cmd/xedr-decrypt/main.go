// xedr-decrypt: offline recovery of files protected by the XEDR (DataProtector) driver,
// using master keys exported from the platform (key escrow).
//
//	xedr-decrypt -keys xedr-keys.json -in report.docx -out report.plain.docx
//	xedr-decrypt -keys xedr-keys.json -dir D:\data -outdir D:\recovered
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"forensic-agent/xedrcrypt"
)

type keyFile struct {
	Keys []struct {
		ID  uint32 `json:"id"`
		Key string `json:"key"` // base64, 32 bytes
	} `json:"keys"`
}

func loadKeys(path string) (map[uint32][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[uint32][]byte{}
	for _, k := range kf.Keys {
		b, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil || len(b) != xedrcrypt.KeyBytes {
			return nil, fmt.Errorf("key id %d: need base64 of %d bytes", k.ID, xedrcrypt.KeyBytes)
		}
		out[k.ID] = b
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no keys in %s", path)
	}
	return out, nil
}

func decryptOne(in, out string, keys map[uint32][]byte) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	plain, err := xedrcrypt.DecryptFile(raw, keys)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, plain, 0o644)
}

func main() {
	keysPath := flag.String("keys", "", "master key export (JSON) from the platform")
	in := flag.String("in", "", "single protected file")
	out := flag.String("out", "", "output path for -in")
	dir := flag.String("dir", "", "directory to scan recursively")
	outDir := flag.String("outdir", "", "output directory for -dir (mirrors the tree)")
	flag.Parse()

	if *keysPath == "" || (*in == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "usage: xedr-decrypt -keys keys.json (-in FILE -out FILE | -dir DIR -outdir DIR)")
		os.Exit(2)
	}
	keys, err := loadKeys(*keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *in != "" {
		if *out == "" {
			*out = *in + ".decrypted"
		}
		if err := decryptOne(*in, *out, keys); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("ok:", *out)
		return
	}

	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "-dir requires -outdir")
		os.Exit(2)
	}
	var okN, skipN, failN int
	_ = filepath.WalkDir(*dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(*dir, p)
		if err := decryptOne(p, filepath.Join(*outDir, rel), keys); err != nil {
			if err.Error() == "no XEDR protection footer" || err.Error() == "file too small to be protected" {
				skipN++
			} else {
				failN++
				fmt.Fprintf(os.Stderr, "fail %s: %v\n", p, err)
			}
			return nil
		}
		okN++
		return nil
	})
	fmt.Printf("decrypted %d, not protected %d, failed %d\n", okN, skipN, failN)
	if failN > 0 {
		os.Exit(1)
	}
}
