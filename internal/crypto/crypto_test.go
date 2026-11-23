package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// TestPBKDF2SHA256Vectors verifies PBKDF2-HMAC-SHA256 against RFC 7914 / standard test vectors.
func TestPBKDF2SHA256Vectors(t *testing.T) {
	cases := []struct {
		password string
		salt     string
		iter     int
		keyLen   int
		wantHex  string
	}{
		{
			password: "password",
			salt:     "salt",
			iter:     1,
			keyLen:   32,
			wantHex:  "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
		},
		{
			password: "password",
			salt:     "salt",
			iter:     2,
			keyLen:   32,
			wantHex:  "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
		},
		{
			password: "password",
			salt:     "salt",
			iter:     4096,
			keyLen:   32,
			wantHex:  "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
		},
	}

	for i, tc := range cases {
		got := PBKDF2SHA256([]byte(tc.password), []byte(tc.salt), tc.iter, tc.keyLen)
		gotHex := hex.EncodeToString(got)
		if gotHex != tc.wantHex {
			t.Fatalf("case %d: got %s, want %s", i, gotHex, tc.wantHex)
		}
	}
}

func TestEncryptDecryptRoundTripAndTamper(t *testing.T) {
	plaintext := []byte(`{"hosts":[{"name":"prod-vps","host":"203.0.113.10"}]}`)
	password := "super-secret-master-pass"

	envBytes, err := EncryptBlobWithIterations(plaintext, password, 2000)
	if err != nil {
		t.Fatalf("EncryptBlobWithIterations error: %v", err)
	}

	got, err := DecryptBlob(envBytes, password)
	if err != nil {
		t.Fatalf("DecryptBlob error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}

	if _, err := DecryptBlob(envBytes, "wrong-password"); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("expected ErrDecryptFailed on wrong password, got: %v", err)
	}

	// Tamper with ciphertext byte
	var env Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	b := []byte(env.Ciphertext)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	env.Ciphertext = string(b)
	tampered, _ := json.Marshal(env)
	if _, err := DecryptBlob(tampered, password); err == nil {
		t.Fatalf("expected error on tampered ciphertext")
	}

	// Tamper with AAD header (iterations)
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	env.Iterations++
	tamperedAAD, _ := json.Marshal(env)
	if _, err := DecryptBlob(tamperedAAD, password); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("expected ErrDecryptFailed on tampered iteration count, got: %v", err)
	}
}
