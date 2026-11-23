package hub

import (
	"crypto/subtle"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const DefaultJoinTokenTTL = 5 * time.Minute

type joinTokenEntry struct {
	ID         string
	SecretHash string
	ExpiresAt  time.Time
}

type JoinTokenStore struct {
	mu      sync.Mutex
	entries map[string]joinTokenEntry
}

func NewJoinTokenStore() *JoinTokenStore {
	return &JoinTokenStore{
		entries: make(map[string]joinTokenEntry),
	}
}

func (s *JoinTokenStore) Create(ttl time.Duration) (string, time.Time) {
	if ttl <= 0 {
		ttl = DefaultJoinTokenTTL
	}
	id := "sfj_" + newRandomID(6)
	secret := randomBase64URL(24)
	exp := time.Now().UTC().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Prune expired tokens opportunistically.
	now := time.Now().UTC()
	for k, v := range s.entries {
		if now.After(v.ExpiresAt) {
			delete(s.entries, k)
		}
	}

	s.entries[id] = joinTokenEntry{
		ID:         id,
		SecretHash: sha256Hex(secret),
		ExpiresAt:  exp,
	}
	return id + "." + secret, exp
}

// Consume validates a one-time join token and immediately deletes it if valid.
func (s *JoinTokenStore) Consume(rawToken string) bool {
	tok := strings.TrimSpace(rawToken)
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot >= len(tok)-1 {
		return false
	}
	id := tok[:dot]
	secret := tok[dot+1:]
	if !strings.HasPrefix(id, "sfj_") {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ent, ok := s.entries[id]
	if !ok {
		return false
	}
	if time.Now().UTC().After(ent.ExpiresAt) {
		delete(s.entries, id)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(secret)), []byte(ent.SecretHash)) != 1 {
		return false
	}

	// Single-use: burn immediately on successful verification.
	delete(s.entries, id)
	return true
}

type nodeCredRecord struct {
	NodeID     string    `json:"node_id"`
	SecretHash string    `json:"secret_hash"`
	CreatedAt  time.Time `json:"created_at"`
}

type NodeCredStore struct {
	mu      sync.RWMutex
	path    string
	records map[string]nodeCredRecord
}

func NewNodeCredStore(dataDir string) *NodeCredStore {
	p := ""
	if dataDir != "" {
		p = filepath.Join(dataDir, "hub-node-creds.json")
	}
	st := &NodeCredStore{
		path:    p,
		records: make(map[string]nodeCredRecord),
	}
	st.load()
	return st
}

func (s *NodeCredStore) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var list []nodeCredRecord
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	for _, r := range list {
		if r.NodeID != "" && len(r.SecretHash) == 64 {
			s.records[r.NodeID] = r
		}
	}
}

func (s *NodeCredStore) saveLocked() {
	if s.path == "" {
		return
	}
	list := make([]nodeCredRecord, 0, len(s.records))
	for _, r := range s.records {
		list = append(list, r)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.path, append(b, '\n'), 0600)
}

func (s *NodeCredStore) Issue(nodeID string) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		nodeID = "node-" + newRandomID(4)
	}
	secret := randomBase64URL(32)

	s.mu.Lock()
	s.records[nodeID] = nodeCredRecord{
		NodeID:     nodeID,
		SecretHash: sha256Hex(secret),
		CreatedAt:  time.Now().UTC(),
	}
	s.saveLocked()
	s.mu.Unlock()

	return "sfn_" + nodeID + "." + secret
}

func (s *NodeCredStore) Verify(rawToken string) (string, bool) {
	tok := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(tok, "sfn_") {
		return "", false
	}
	rest := strings.TrimPrefix(tok, "sfn_")
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot >= len(rest)-1 {
		return "", false
	}
	nodeID := rest[:dot]
	secret := rest[dot+1:]

	s.mu.RLock()
	rec, ok := s.records[nodeID]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(secret)), []byte(rec.SecretHash)) != 1 {
		return "", false
	}
	return nodeID, true
}
