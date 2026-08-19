package tfmeta

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMetaSizeConstant(t *testing.T) {
	// The eBPF program reads exactly this many bytes for traceflow_meta.
	if MetaSize != 30 {
		t.Fatalf("MetaSize = %d, want 30 (must match struct traceflow_meta)", MetaSize)
	}
}

func TestMarshalLenAndMagic(t *testing.T) {
	m := Meta{Timestamp: 123}
	b := m.Marshal()
	if len(b) != MetaSize {
		t.Fatalf("Marshal len = %d, want %d", len(b), MetaSize)
	}
	// Magic must be the ASCII "TFLO" in network order.
	if !bytes.Equal(b[0:4], []byte("TFLO")) {
		t.Fatalf("magic on wire = %x, want %q", b[0:4], "TFLO")
	}
	if !bytes.Equal(b[0:4], MagicBytes()) {
		t.Fatalf("MagicBytes() = %x disagrees with Marshal %x", MagicBytes(), b[0:4])
	}
}

func TestTimestampLittleEndian(t *testing.T) {
	const ts = 0x0102030405060708
	m := Meta{Timestamp: ts}
	b := m.Marshal()
	// Contract: timestamp is little-endian at offset 22 (host order on x86-64).
	if got := binary.LittleEndian.Uint64(b[22:30]); got != ts {
		t.Fatalf("timestamp decode = %#x, want %#x", got, ts)
	}
}

func TestRoundTrip(t *testing.T) {
	in := Meta{
		ID:           [16]byte{0x3f, 0x2b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
		Intercept:    true,
		NeedResponse: true,
		Timestamp:    1_700_000_000_123_456_789,
	}
	out, err := Unmarshal(in.Marshal())
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestFlagBytes(t *testing.T) {
	// intercept at offset 20, need_response at offset 21.
	b := Meta{Intercept: true, NeedResponse: false}.Marshal()
	if b[20] != 1 || b[21] != 0 {
		t.Fatalf("intercept/need_response bytes = %d/%d, want 1/0", b[20], b[21])
	}
	b = Meta{Intercept: false, NeedResponse: true}.Marshal()
	if b[20] != 0 || b[21] != 1 {
		t.Fatalf("intercept/need_response bytes = %d/%d, want 0/1", b[20], b[21])
	}
}

func TestUnmarshalRejectsBadMagic(t *testing.T) {
	b := Meta{}.Marshal()
	b[1] ^= 0xFF // corrupt magic
	if _, err := Unmarshal(b); err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestUnmarshalRejectsShort(t *testing.T) {
	if _, err := Unmarshal(make([]byte, MetaSize-1)); err == nil {
		t.Fatal("expected error for short payload, got nil")
	}
}

func TestHMACSignVerify(t *testing.T) {
	key := []byte("s3cret-shared-key")
	m := Meta{ID: [16]byte{1, 2, 3}, NeedResponse: true, Timestamp: 42}

	signed := m.Signed(key)
	if len(signed) != SignedSize {
		t.Fatalf("signed len = %d, want %d", len(signed), SignedSize)
	}
	if !Verify(signed, key) {
		t.Fatal("valid signature rejected")
	}
	// Tampering with the core must invalidate the HMAC.
	bad := append([]byte(nil), signed...)
	bad[21] ^= 1 // flip need_response
	if Verify(bad, key) {
		t.Fatal("tampered payload accepted")
	}
	// Wrong key must fail.
	if Verify(signed, []byte("other-key")) {
		t.Fatal("wrong key accepted")
	}
	// Empty key = auth disabled -> always true, and Signed returns bare core.
	if len(m.Signed(nil)) != MetaSize {
		t.Fatal("unsigned Signed() should be the bare core")
	}
	if !Verify(m.Marshal(), nil) {
		t.Fatal("empty key should accept any payload")
	}
	// A key set but no HMAC present must fail.
	if Verify(m.Marshal(), key) {
		t.Fatal("unsigned payload accepted under a key")
	}
}
