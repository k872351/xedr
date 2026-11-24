// Package xedrcrypt is the user-mode twin of the DataProtector driver's file encryption
// (agent/driver/dataprotector/DpCrypto.c). It must stay byte-for-byte compatible:
// it is what decrypts files offline when the driver is unavailable.
package xedrcrypt

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	KeyBytes        = 32
	FileKeyLength   = 32
	FileKeyMagic    = 0x314B4558 // 'XEK1'
	FooterSize      = 512
	ProtectionMagic = 0x32465044
)

var ErrWrongKey = errors.New("file key check failed: wrong or missing master key")

// FileKeyBlob mirrors DP_FILE_KEY_BLOB (packed, little-endian).
type FileKeyBlob struct {
	Magic    uint32
	KeyID    uint32
	Check    uint32
	Reserved uint32
	Nonce    [16]byte
}

func ParseFileKeyBlob(b []byte) (FileKeyBlob, error) {
	var k FileKeyBlob
	if len(b) != FileKeyLength {
		return k, fmt.Errorf("file key blob must be %d bytes", FileKeyLength)
	}
	k.Magic = binary.LittleEndian.Uint32(b[0:4])
	k.KeyID = binary.LittleEndian.Uint32(b[4:8])
	k.Check = binary.LittleEndian.Uint32(b[8:12])
	k.Reserved = binary.LittleEndian.Uint32(b[12:16])
	copy(k.Nonce[:], b[16:32])
	if k.Magic != FileKeyMagic || k.KeyID == 0 {
		return k, errors.New("not an XEDR file key blob")
	}
	return k, nil
}

func (k FileKeyBlob) Bytes() []byte {
	b := make([]byte, FileKeyLength)
	binary.LittleEndian.PutUint32(b[0:4], k.Magic)
	binary.LittleEndian.PutUint32(b[4:8], k.KeyID)
	binary.LittleEndian.PutUint32(b[8:12], k.Check)
	binary.LittleEndian.PutUint32(b[12:16], k.Reserved)
	copy(b[16:32], k.Nonce[:])
	return b
}

// kdf returns AES-ECB_KEK(nonce^1) || AES-ECB_KEK(nonce^2) || AES-ECB_KEK(nonce^3).
func kdf(kek []byte, nonce [16]byte) ([48]byte, error) {
	var out [48]byte
	c, err := aes.NewCipher(kek)
	if err != nil {
		return out, err
	}
	for i := 0; i < 3; i++ {
		in := nonce
		in[15] ^= byte(i + 1)
		c.Encrypt(out[i*16:(i+1)*16], in[:])
	}
	return out, nil
}

// NewFileKeyBlob builds the blob for a nonce under kek (used by tests and tooling).
func NewFileKeyBlob(kek []byte, keyID uint32, nonce [16]byte) (FileKeyBlob, error) {
	d, err := kdf(kek, nonce)
	if err != nil {
		return FileKeyBlob{}, err
	}
	return FileKeyBlob{
		Magic: FileKeyMagic, KeyID: keyID, Nonce: nonce,
		Check: binary.LittleEndian.Uint32(d[32:36]),
	}, nil
}

// DataKey derives and verifies the per-file AES-256 key.
func DataKey(kek []byte, blob FileKeyBlob) ([]byte, error) {
	d, err := kdf(kek, blob.Nonce)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(d[32:36]) != blob.Check {
		return nil, ErrWrongKey
	}
	key := make([]byte, 32)
	copy(key, d[:32])
	return key, nil
}

// Transform XORs buf (located at file offset off) with the AES-256-CTR keystream.
// Counter block = little-endian uint64 block index in bytes 0..7, zeros after.
func Transform(dataKey []byte, buf []byte, off uint64) error {
	c, err := aes.NewCipher(dataKey)
	if err != nil {
		return err
	}
	var ctr, ks [16]byte
	done := 0
	for done < len(buf) {
		abs := off + uint64(done)
		block := abs / 16
		skip := int(abs % 16)
		for i := range ctr {
			ctr[i] = 0
		}
		binary.LittleEndian.PutUint64(ctr[0:8], block)
		c.Encrypt(ks[:], ctr[:])
		n := 16 - skip
		if n > len(buf)-done {
			n = len(buf) - done
		}
		for i := 0; i < n; i++ {
			buf[done+i] ^= ks[skip+i]
		}
		done += n
	}
	return nil
}

// Footer mirrors DP_PROTECTION_FOOTER (packed, 512 bytes, at end of file).
type Footer struct {
	LogicalSize uint64
	KeyLength   uint32
	FileKey     [FileKeyLength]byte
}

func ParseFooter(f []byte) (Footer, error) {
	var ft Footer
	if len(f) != FooterSize {
		return ft, fmt.Errorf("footer must be %d bytes", FooterSize)
	}
	if binary.LittleEndian.Uint32(f[0:4]) != ProtectionMagic {
		return ft, errors.New("no XEDR protection footer")
	}
	ft.LogicalSize = binary.LittleEndian.Uint64(f[16:24])
	ft.KeyLength = binary.LittleEndian.Uint32(f[24:28])
	copy(ft.FileKey[:], f[28:60])
	return ft, nil
}

// DecryptFile returns the plaintext of a protected file's raw bytes.
// keys maps KEK id -> 32-byte KEK.
func DecryptFile(raw []byte, keys map[uint32][]byte) ([]byte, error) {
	if len(raw) < FooterSize {
		return nil, errors.New("file too small to be protected")
	}
	ft, err := ParseFooter(raw[len(raw)-FooterSize:])
	if err != nil {
		return nil, err
	}
	if ft.LogicalSize > uint64(len(raw)-FooterSize) {
		return nil, errors.New("footer logical size out of range")
	}
	blob, err := ParseFileKeyBlob(ft.FileKey[:])
	if err != nil {
		return nil, err
	}
	kek, ok := keys[blob.KeyID]
	if !ok {
		return nil, fmt.Errorf("master key id %d not provided", blob.KeyID)
	}
	dk, err := DataKey(kek, blob)
	if err != nil {
		return nil, err
	}
	out := make([]byte, ft.LogicalSize)
	copy(out, raw[:ft.LogicalSize])
	if err := Transform(dk, out, 0); err != nil {
		return nil, err
	}
	return out, nil
}
