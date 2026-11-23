package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	EnvelopeMagic      = "SFV1"
	DefaultKDF         = "pbkdf2-sha256"
	DefaultIterations  = 210000
	SaltSize           = 16
	NonceSize          = 12
	KeySize            = 32
	MinPasswordLen     = 1
)

var (
	ErrInvalidEnvelope = errors.New("invalid encrypted vault envelope")
	ErrDecryptFailed   = errors.New("decryption failed: wrong password or corrupted data")
)

type Envelope struct {
	Magic      string `json:"magic"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iter"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// PBKDF2SHA256 implements RFC 2898 / RFC 8018 PBKDF2 with HMAC-SHA256 using only the standard library.
func PBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(data)
		return h.Sum(nil)
	}

	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte

	for block := 1; block <= numBlocks; block++ {
		uInput := make([]byte, len(salt)+4)
		copy(uInput, salt)
		uInput[len(salt)] = byte(block >> 24)
		uInput[len(salt)+1] = byte(block >> 16)
		uInput[len(salt)+2] = byte(block >> 8)
		uInput[len(salt)+3] = byte(block)

		u := prf(password, uInput)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 2; i <= iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}

	return dk[:keyLen]
}

// EncryptBlob encrypts plaintext with AES-256-GCM using a key derived via PBKDF2-HMAC-SHA256.
func EncryptBlob(plaintext []byte, password string) ([]byte, error) {
	return EncryptBlobWithIterations(plaintext, password, DefaultIterations)
}

// EncryptBlobWithIterations encrypts plaintext using the specified PBKDF2 iteration count.
func EncryptBlobWithIterations(plaintext []byte, password string, iterations int) ([]byte, error) {
	if len(password) < MinPasswordLen {
		return nil, errors.New("password cannot be empty")
	}
	if iterations < 1000 {
		iterations = DefaultIterations
	}

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	key := PBKDF2SHA256([]byte(password), salt, iterations, KeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	// Bind envelope metadata as AAD so tampering with header fields fails auth.
	aad := fmt.Sprintf("%s|%s|%d", EnvelopeMagic, DefaultKDF, iterations)
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))

	env := Envelope{
		Magic:      EnvelopeMagic,
		KDF:        DefaultKDF,
		Iterations: iterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return append(out, '\n'), nil
}

// DecryptBlob decrypts an SFV1 envelope produced by EncryptBlob.
func DecryptBlob(rawEnvelope []byte, password string) ([]byte, error) {
	if len(password) < MinPasswordLen {
		return nil, errors.New("password cannot be empty")
	}

	var env Envelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.Magic != EnvelopeMagic || env.KDF != DefaultKDF || env.Iterations <= 0 {
		return nil, ErrInvalidEnvelope
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) != SaltSize {
		return nil, ErrInvalidEnvelope
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != NonceSize {
		return nil, ErrInvalidEnvelope
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return nil, ErrInvalidEnvelope
	}

	key := PBKDF2SHA256([]byte(password), salt, env.Iterations, KeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	aad := fmt.Sprintf("%s|%s|%d", env.Magic, env.KDF, env.Iterations)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}
