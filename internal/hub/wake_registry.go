package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type WakeRelayRecord struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	SecretHash      string     `json:"secret_hash"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	FirmwareVersion string     `json:"firmware_version,omitempty"`
}

type WakeRelayRegistry struct {
	mu      sync.RWMutex
	path    string
	records map[string]*WakeRelayRecord
}

func NewWakeRelayRegistry(dataDir string) *WakeRelayRegistry {
	p := ""
	if dataDir != "" {
		p = filepath.Join(dataDir, "hub-wake-relays.json")
	}
	r := &WakeRelayRegistry{
		path:    p,
		records: make(map[string]*WakeRelayRecord),
	}
	r.load()
	return r
}

func (r *WakeRelayRegistry) load() {
	if r.path == "" {
		return
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var list []WakeRelayRecord
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	for i := range list {
		rec := list[i]
		if rec.ID != "" && len(rec.SecretHash) == 64 {
			r.records[rec.ID] = &rec
		}
	}
}

func (r *WakeRelayRegistry) saveLocked() {
	if r.path == "" {
		return
	}
	list := make([]WakeRelayRecord, 0, len(r.records))
	for _, rec := range r.records {
		list = append(list, *rec)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = writeFileAtomic(r.path, append(b, '\n'), 0600)
}

func (r *WakeRelayRegistry) Create(name string) (*WakeRelayRecord, string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return nil, "", errors.New("relay name cannot be empty")
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	base := slugify(clean)
	id := base
	for i := 2; r.records[id] != nil; i++ {
		id = base + "-" + string(rune('0'+i))
		if i > 9 {
			id = base + "-" + newRandomID(2)
		}
	}

	secret := randomBase64URL(32)
	rec := &WakeRelayRecord{
		ID:         id,
		Name:       clean,
		SecretHash: sha256Hex(secret),
		CreatedAt:  time.Now().UTC(),
	}
	r.records[id] = rec
	r.saveLocked()
	cp := *rec
	return &cp, id + "." + secret, nil
}

func (r *WakeRelayRegistry) Rotate(id string) (*WakeRelayRecord, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[id]
	if rec == nil {
		return nil, "", false
	}
	secret := randomBase64URL(32)
	rec.SecretHash = sha256Hex(secret)
	r.saveLocked()
	cp := *rec
	return &cp, id + "." + secret, true
}

func (r *WakeRelayRegistry) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records[id] == nil {
		return false
	}
	delete(r.records, id)
	r.saveLocked()
	return true
}

func (r *WakeRelayRegistry) Get(id string) (*WakeRelayRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec := r.records[id]
	if rec == nil {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

func (r *WakeRelayRegistry) List() []WakeRelayRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]WakeRelayRecord, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (r *WakeRelayRegistry) MarkSeen(id, fw string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[id]
	if rec == nil {
		return
	}
	now := time.Now().UTC()
	rec.LastSeenAt = &now
	if fw != "" {
		rec.FirmwareVersion = fw
	}
	r.saveLocked()
}

func (r *WakeRelayRegistry) VerifyBearer(authHeader string) (*WakeRelayRecord, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return nil, false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot >= len(tok)-1 {
		return nil, false
	}
	id := tok[:dot]
	secret := tok[dot+1:]

	r.mu.RLock()
	rec := r.records[id]
	r.mu.RUnlock()
	if rec == nil {
		return nil, false
	}

	gotHash := sha256Hex(secret)
	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(rec.SecretHash)) != 1 {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomBase64URL(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return "esp32"
	}
	if len(res) > 24 {
		res = strings.TrimRight(res[:24], "-")
	}
	return res
}
