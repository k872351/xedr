package xedrcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func testKEK(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripAndRandomAccess(t *testing.T) {
	kek := testKEK(t)
	var nonce [16]byte
	rand.Read(nonce[:])
	blob, err := NewFileKeyBlob(kek, 7, nonce)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := DataKey(kek, blob)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 10000)
	rand.Read(plain)

	whole := append([]byte(nil), plain...)
	if err := Transform(dk, whole, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(whole, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	// Same ciphertext when produced in odd-sized, unaligned pieces (driver I/O is random access).
	pieces := append([]byte(nil), plain...)
	for off := 0; off < len(pieces); {
		n := 1 + (off*7919)%613
		if off+n > len(pieces) {
			n = len(pieces) - off
		}
		Transform(dk, pieces[off:off+n], uint64(off))
		off += n
	}
	if !bytes.Equal(pieces, whole) {
		t.Fatal("piecewise transform differs from whole-buffer transform")
	}

	Transform(dk, whole, 0)
	if !bytes.Equal(whole, plain) {
		t.Fatal("round trip failed")
	}
}

func TestMatchesPlainAESCTRDefinition(t *testing.T) {
	kek := testKEK(t)
	var nonce [16]byte
	blob, _ := NewFileKeyBlob(kek, 1, nonce)
	dk, _ := DataKey(kek, blob)

	buf := make([]byte, 40)
	Transform(dk, buf, 32) // keystream for blocks 2,3,4 (zero plaintext => keystream)

	c, _ := aes.NewCipher(dk)
	for b := 0; b < 3; b++ {
		var ctr, ks [16]byte
		binary.LittleEndian.PutUint64(ctr[:8], uint64(2+b))
		c.Encrypt(ks[:], ctr[:])
		end := (b + 1) * 16
		if end > len(buf) {
			end = len(buf)
		}
		if !bytes.Equal(buf[b*16:end], ks[:end-b*16]) {
			t.Fatalf("block %d keystream mismatch", 2+b)
		}
	}
}

func TestWrongKeyAndUniquePerFile(t *testing.T) {
	kek := testKEK(t)
	var n1, n2 [16]byte
	rand.Read(n1[:])
	rand.Read(n2[:])
	b1, _ := NewFileKeyBlob(kek, 3, n1)
	b2, _ := NewFileKeyBlob(kek, 3, n2)
	k1, _ := DataKey(kek, b1)
	k2, _ := DataKey(kek, b2)
	if bytes.Equal(k1, k2) {
		t.Fatal("two files derived the same data key")
	}
	if _, err := DataKey(testKEK(t), b1); err != ErrWrongKey {
		t.Fatalf("wrong KEK not detected: %v", err)
	}
}

func TestDecryptFileWithFooter(t *testing.T) {
	kek := testKEK(t)
	var nonce [16]byte
	rand.Read(nonce[:])
	blob, _ := NewFileKeyBlob(kek, 9, nonce)
	dk, _ := DataKey(kek, blob)

	plain := []byte("quarterly report: confidential numbers")
	ct := append([]byte(nil), plain...)
	Transform(dk, ct, 0)

	footer := make([]byte, FooterSize)
	binary.LittleEndian.PutUint32(footer[0:4], ProtectionMagic)
	binary.LittleEndian.PutUint32(footer[4:8], 1)
	binary.LittleEndian.PutUint32(footer[8:12], FooterSize)
	binary.LittleEndian.PutUint64(footer[16:24], uint64(len(plain)))
	binary.LittleEndian.PutUint32(footer[24:28], FileKeyLength)
	copy(footer[28:60], blob.Bytes())

	got, err := DecryptFile(append(ct, footer...), map[uint32][]byte{9: kek})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted %q", got)
	}
	if _, err := DecryptFile(append(ct, footer...), map[uint32][]byte{8: kek}); err == nil {
		t.Fatal("missing key id not reported")
	}
}
