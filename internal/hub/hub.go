package hub

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssh-fleet/internal/protocol"
	"ssh-fleet/internal/ws"
)

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

func wrapHijackedConn(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw == nil || rw.Reader.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{
		Conn: conn,
		r:    io.MultiReader(rw.Reader, conn),
	}
}

type activeAgent struct {
	nodeID string
	conn   net.Conn
	writeM sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func (a *activeAgent) send(f protocol.ControlFrame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	a.writeM.Lock()
	defer a.writeM.Unlock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = a.conn.Write(b)
	_ = a.conn.SetWriteDeadline(time.Time{})
	return err
}

func (a *activeAgent) close() {
	a.once.Do(func() {
		close(a.closed)
		_ = a.conn.Close()
	})
}

type pendingAck struct {
	ch chan protocol.ControlFrame
}

type Options struct {
	Token            string
	DataDir          string
	TrustCFAccess    bool
	CFAccessEmail    string
	AgentReadTimeout time.Duration
	ESP32ReadTimeout time.Duration
	SoftWakeTimeout  time.Duration
	KeyringUnlockTTL time.Duration
}

type authRole int

const (
	authNone authRole = iota
	authNode
	authAdmin
)

type pendingKeyringUnlock struct {
	password  string
	expiresAt time.Time
	timer     *time.Timer
}

type keyringUnlockStatus struct {
	pending bool
	err     string
}

type esp32WakeRelay struct {
	id      string
	ws      *ws.Conn
	pending map[string]chan struct {
		ok  bool
		err string
	}
	mu     sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func (r *esp32WakeRelay) close() {
	r.once.Do(func() {
		close(r.closed)
		_ = r.ws.Close()
	})
}

type Server struct {
	token                 string
	dataDir               string
	trustCFAccess         bool
	cfEmails              []string
	agentReadTimeout      time.Duration
	esp32ReadTimeout      time.Duration
	softWakeTimeout       time.Duration
	keyringUnlockTTL      time.Duration
	wakeReg               *WakeRelayRegistry
	joinTokens            *JoinTokenStore
	nodeCreds             *NodeCredStore
	mu                    sync.RWMutex
	nodes                 map[string]*protocol.NodeInfo
	agents                map[string]*activeAgent
	esp32Relays           map[string]*esp32WakeRelay
	pendingReq            map[string]*pendingAck
	pendingKeyringUnlocks map[string]*pendingKeyringUnlock
	keyringStatus         map[string]keyringUnlockStatus
	streams               map[string]chan net.Conn
	httpSrv               *http.Server
}

func NewServer(token, dataDir string) (*Server, error) {
	return NewServerWithOptions(Options{
		Token:   token,
		DataDir: dataDir,
	})
}

func NewServerWithOptions(opts Options) (*Server, error) {
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("hub token cannot be empty")
	}
	if opts.DataDir != "" {
		if err := os.MkdirAll(opts.DataDir, 0700); err != nil {
			return nil, err
		}
	}
	if opts.AgentReadTimeout <= 0 {
		opts.AgentReadTimeout = 45 * time.Second
	}
	if opts.ESP32ReadTimeout <= 0 {
		opts.ESP32ReadTimeout = 90 * time.Second
	}
	if opts.SoftWakeTimeout <= 0 {
		opts.SoftWakeTimeout = 3 * time.Second
	}
	if opts.KeyringUnlockTTL <= 0 {
		opts.KeyringUnlockTTL = 5 * time.Minute
	}
	var emails []string
	for _, e := range strings.Split(opts.CFAccessEmail, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			emails = append(emails, e)
		}
	}
	trustCF := opts.TrustCFAccess || len(emails) > 0
	s := &Server{
		token:                 opts.Token,
		dataDir:               opts.DataDir,
		trustCFAccess:         trustCF,
		cfEmails:              emails,
		agentReadTimeout:      opts.AgentReadTimeout,
		esp32ReadTimeout:      opts.ESP32ReadTimeout,
		softWakeTimeout:       opts.SoftWakeTimeout,
		keyringUnlockTTL:      opts.KeyringUnlockTTL,
		wakeReg:               NewWakeRelayRegistry(opts.DataDir),
		joinTokens:            NewJoinTokenStore(),
		nodeCreds:             NewNodeCredStore(opts.DataDir),
		nodes:                 make(map[string]*protocol.NodeInfo),
		agents:                make(map[string]*activeAgent),
		esp32Relays:           make(map[string]*esp32WakeRelay),
		pendingReq:            make(map[string]*pendingAck),
		pendingKeyringUnlocks: make(map[string]*pendingKeyringUnlock),
		keyringStatus:         make(map[string]keyringUnlockStatus),
		streams:               make(map[string]chan net.Conn),
	}
	s.loadPersistedNodes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/v1/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/v1/hub-info", s.withAdminAuth(s.handleHubInfo))
	mux.HandleFunc("/api/v1/join-tokens", s.withAdminAuth(s.handleCreateJoinToken))
	mux.HandleFunc("/api/v1/join/exchange", s.handleJoinExchange)
	mux.HandleFunc("/api/v1/ws/terminal", s.withAdminAuth(s.handleTerminalWS))
	mux.HandleFunc("/api/v1/nodes", s.withAuth(s.handleListNodes))
	mux.HandleFunc("/api/v1/nodes/", s.withAuth(s.handleNodeAction))
	mux.HandleFunc("/api/v1/wake-relays", s.withAdminAuth(s.handleWakeRelays))
	mux.HandleFunc("/api/v1/wake-relays/", s.withAdminAuth(s.handleWakeRelayByID))
	mux.HandleFunc("/api/v1/vault", s.withAuth(s.handleVault))
	mux.HandleFunc("/tunnel/control", s.withAuth(s.handleControlTunnel))
	mux.HandleFunc("/tunnel/agent-stream", s.withAuth(s.handleAgentStream))
	mux.HandleFunc("/tunnel/client-proxy", s.withAuth(s.handleClientProxy))
	mux.HandleFunc("/hub/ws/wake", s.handleESP32WakeTunnel)
	mux.Handle("/", webHandler())
	return mux
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.httpSrv = &http.Server{Handler: s.Handler()}
	return s.httpSrv.Serve(ln)
}

func (s *Server) Close() error {
	s.mu.Lock()
	for _, a := range s.agents {
		a.close()
	}
	for _, er := range s.esp32Relays {
		er.close()
	}
	for id, p := range s.pendingKeyringUnlocks {
		if p.timer != nil {
			p.timer.Stop()
		}
		p.password = ""
		delete(s.pendingKeyringUnlocks, id)
	}
	for id := range s.keyringStatus {
		delete(s.keyringStatus, id)
	}
	s.mu.Unlock()
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

func (s *Server) classifyToken(tok string) (authRole, string) {
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1 {
		return authAdmin, ""
	}
	if nodeID, ok := s.nodeCreds.Verify(tok); ok {
		return authNode, nodeID
	}
	return authNone, ""
}

func (s *Server) authenticateRequest(r *http.Request) (authRole, string) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		got := strings.TrimPrefix(auth, prefix)
		if role, sub := s.classifyToken(got); role != authNone {
			return role, sub
		}
	}

	if c, err := r.Cookie("sf_token"); err == nil && c.Value != "" {
		if role, sub := s.classifyToken(c.Value); role != authNone {
			return role, sub
		}
	}

	if qTok := strings.TrimSpace(r.URL.Query().Get("token")); qTok != "" {
		if role, sub := s.classifyToken(qTok); role != authNone {
			return role, sub
		}
	}

	if s.trustCFAccess {
		cfEmail := strings.ToLower(strings.TrimSpace(r.Header.Get("Cf-Access-Authenticated-User-Email")))
		if cfEmail != "" {
			if len(s.cfEmails) == 0 {
				return authAdmin, cfEmail
			}
			for _, allowed := range s.cfEmails {
				if cfEmail == allowed {
					return authAdmin, cfEmail
				}
			}
		} else if len(s.cfEmails) == 0 && strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion")) != "" {
			return authAdmin, "cf-access-user"
		}
	}

	return authNone, ""
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := s.authenticateRequest(r)
		if role == authNone {
			http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) withAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := s.authenticateRequest(r)
		switch role {
		case authAdmin:
			next(w, r)
		case authNode:
			http.Error(w, `{"ok":false,"error":"admin authentication required"}`, http.StatusForbidden)
		default:
			http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	role, cfEmail := s.authenticateRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"authenticated": role == authAdmin,
		"cf_email":      cfEmail,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Token)), []byte(s.token)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid token"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sf_token",
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func redactToken(tok string) string {
	if len(tok) <= 10 {
		return "••••••••"
	}
	return tok[:7] + "••••••••" + tok[len(tok)-4:]
}

func (s *Server) handleHubInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	espCount := len(s.esp32Relays)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"hub_token_redacted":  redactToken(s.token),
		"join_token_ttl_sec":  int(DefaultJoinTokenTTL.Seconds()),
		"esp32_relays_online": espCount,
	})
}

func (s *Server) handleCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok, exp := s.joinTokens.Create(DefaultJoinTokenTTL)
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":         true,
		"join_token": tok,
		"expires_at": exp,
		"ttl_sec":    int(DefaultJoinTokenTTL.Seconds()),
	})
}

func (s *Server) handleJoinExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		JoinToken string `json:"join_token"`
		NodeID    string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}
	if !s.joinTokens.Consume(body.JoinToken) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "one-time join token is invalid, expired, or already used"})
		return
	}
	nodeTok := s.nodeCreds.Issue(body.NodeID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"node_token": nodeTok,
	})
}

func (s *Server) stateFilePath() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, "hub-nodes.json")
}

func (s *Server) vaultFilePath() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, "vault.enc")
}

func (s *Server) loadPersistedNodes() {
	p := s.stateFilePath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var list []protocol.NodeInfo
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	for i := range list {
		n := list[i]
		n.Online = false
		n.KeyringLocked = nil
		n.KeyringUnlockPending = false
		n.KeyringUnlockError = ""
		if n.PowerState != protocol.PowerSleeping {
			n.PowerState = protocol.PowerOffline
		}
		s.nodes[n.NodeID] = &n
	}
}

func (s *Server) persistNodesLocked() {
	p := s.stateFilePath()
	if p == "" {
		return
	}
	list := make([]protocol.NodeInfo, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		cp.KeyringUnlockPending = false
		cp.KeyringUnlockError = ""
		list = append(list, cp)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].NodeID < list[j].NodeID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, append(b, '\n'), 0600)
}

func (s *Server) ListNodes() []protocol.NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]protocol.NodeInfo, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		if st, ok := s.keyringStatus[n.NodeID]; ok {
			cp.KeyringUnlockPending = st.pending
			cp.KeyringUnlockError = st.err
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"nodes":       s.ListNodes(),
		"wake_relays": s.ListWakeRelays(),
	})
}

func (s *Server) ListWakeRelays() []protocol.WakeRelaySummary {
	recs := s.wakeReg.List()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]protocol.WakeRelaySummary, 0, len(recs))
	for _, rec := range recs {
		_, online := s.esp32Relays[rec.ID]
		out = append(out, protocol.WakeRelaySummary{
			ID:              rec.ID,
			Name:            rec.Name,
			Online:          online,
			FirmwareVersion: rec.FirmwareVersion,
			CreatedAt:       rec.CreatedAt,
			LastSeenAt:      rec.LastSeenAt,
		})
	}
	return out
}

func (s *Server) handleWakeRelays(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"wake_relays": s.ListWakeRelays(),
		})
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
			return
		}
		rec, tok, err := s.wakeReg.Create(body.Name)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok": true,
			"relay": protocol.WakeRelaySummary{
				ID:        rec.ID,
				Name:      rec.Name,
				Online:    false,
				CreatedAt: rec.CreatedAt,
			},
			"token":   tok,
			"ws_path": "/hub/ws/wake",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWakeRelayByID(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/wake-relays/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]

	if len(parts) == 2 && parts[1] == "rotate" && r.Method == http.MethodPost {
		rec, tok, ok := s.wakeReg.Rotate(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "wake relay not found"})
			return
		}
		s.mu.Lock()
		if conn := s.esp32Relays[id]; conn != nil {
			delete(s.esp32Relays, id)
			conn.close()
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"relay": protocol.WakeRelaySummary{
				ID:              rec.ID,
				Name:            rec.Name,
				Online:          false,
				FirmwareVersion: rec.FirmwareVersion,
				CreatedAt:       rec.CreatedAt,
				LastSeenAt:      rec.LastSeenAt,
			},
			"token":   tok,
			"ws_path": "/hub/ws/wake",
		})
		return
	}

	if len(parts) == 1 && r.Method == http.MethodDelete {
		if !s.wakeReg.Delete(id) {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "wake relay not found"})
			return
		}
		s.mu.Lock()
		if conn := s.esp32Relays[id]; conn != nil {
			delete(s.esp32Relays, id)
			conn.close()
		}
		for _, n := range s.nodes {
			if n.WoL != nil && n.WoL.WakeRelayID == id {
				n.WoL.WakeRelayID = ""
			}
		}
		s.persistNodesLocked()
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request) {
	vp := s.vaultFilePath()
	if vp == "" {
		http.Error(w, `{"ok":false,"error":"hub vault storage disabled"}`, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(vp)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, `{"ok":false,"error":"vault not found on hub"}`, http.StatusNotFound)
				return
			}
			http.Error(w, fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
		if err != nil || len(body) == 0 {
			http.Error(w, `{"ok":false,"error":"empty vault payload"}`, http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(vp, body, 0600); err != nil {
			http.Error(w, fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	nodeID := parts[0]
	role, _ := s.authenticateRequest(r)

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPatch:
			if role != authAdmin {
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin authentication required"})
				return
			}
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
				return
			}
			clean := strings.TrimSpace(body.Name)
			if clean == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "machine name cannot be empty"})
				return
			}
			if runes := []rune(clean); len(runes) > 80 {
				clean = string(runes[:80])
			}
			s.mu.Lock()
			n, exists := s.nodes[nodeID]
			if !exists {
				s.mu.Unlock()
				writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "node not found"})
				return
			}
			n.Name = clean
			n.CustomName = true
			s.persistNodesLocked()
			cp := *n
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node": cp})
			return
		case http.MethodDelete:
			if role != authAdmin {
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin authentication required"})
				return
			}
			s.mu.Lock()
			if _, exists := s.nodes[nodeID]; !exists {
				s.mu.Unlock()
				writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "node not found"})
				return
			}
			active := s.agents[nodeID]
			delete(s.agents, nodeID)
			delete(s.nodes, nodeID)
			if p := s.pendingKeyringUnlocks[nodeID]; p != nil {
				if p.timer != nil {
					p.timer.Stop()
				}
				p.password = ""
				delete(s.pendingKeyringUnlocks, nodeID)
			}
			delete(s.keyringStatus, nodeID)
			s.persistNodesLocked()
			s.mu.Unlock()

			s.nodeCreds.Revoke(nodeID)
			if active != nil {
				active.close()
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node_id": nodeID})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	if parts[1] == "wol" {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if role != authAdmin {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin authentication required"})
			return
		}
		var body struct {
			WoL *protocol.NodeWolConfig `json:"wol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
			return
		}
		s.mu.Lock()
		n, exists := s.nodes[nodeID]
		if !exists {
			s.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "node not found"})
			return
		}
		if n.IsVPS {
			s.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Wake-on-LAN cannot be bound to a VPS"})
			return
		}
		if body.WoL == nil || (strings.TrimSpace(body.WoL.MAC) == "" && strings.TrimSpace(body.WoL.WakeRelayID) == "") {
			n.WoL = nil
		} else {
			mac := strings.TrimSpace(body.WoL.MAC)
			relayID := strings.TrimSpace(body.WoL.WakeRelayID)
			if mac == "" || relayID == "" {
				s.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "both MAC address and wake_relay_id must be provided to bind Wake-on-LAN"})
				return
			}
			if _, isESP := s.wakeReg.Get(relayID); !isESP {
				s.mu.Unlock()
				writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": fmt.Sprintf("wake relay %q not found", relayID)})
				return
			}
			port := body.WoL.Port
			if port <= 0 {
				port = 9
			}
			n.WoL = &protocol.NodeWolConfig{
				MAC:         mac,
				BroadcastIP: strings.TrimSpace(body.WoL.BroadcastIP),
				Port:        port,
				WakeRelayID: relayID,
			}
		}
		s.persistNodesLocked()
		cp := *n
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node": cp})
		return
	}

	if parts[1] == "unlock-keyring" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if role != authAdmin {
			writeJSON(w, http.StatusForbidden, protocol.UnlockKeyringResponse{OK: false, NodeID: nodeID, Error: "admin authentication required"})
			return
		}
		var req protocol.UnlockKeyringRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, protocol.UnlockKeyringResponse{OK: false, NodeID: nodeID, Error: "invalid request body"})
			return
		}
		if req.Password == "" {
			writeJSON(w, http.StatusBadRequest, protocol.UnlockKeyringResponse{OK: false, NodeID: nodeID, Error: "please enter the keyring password"})
			return
		}

		s.mu.RLock()
		_, exists := s.nodes[nodeID]
		agent := s.agents[nodeID]
		s.mu.RUnlock()

		if !exists {
			writeJSON(w, http.StatusNotFound, protocol.UnlockKeyringResponse{OK: false, NodeID: nodeID, Error: "node not found"})
			return
		}
		if agent == nil {
			writeJSON(w, http.StatusServiceUnavailable, protocol.UnlockKeyringResponse{OK: false, NodeID: nodeID, Error: "target node is offline"})
			return
		}

		res, status := s.unlockWithAgent(nodeID, agent, req.Password, 8*time.Second)
		writeJSON(w, status, res)
		return
	}

	if parts[1] != "power" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req protocol.PowerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.PowerResponse{OK: false, NodeID: nodeID, Error: "invalid request body"})
		return
	}
	if req.KeyringPassword != "" && role != authAdmin {
		writeJSON(w, http.StatusForbidden, protocol.PowerResponse{OK: false, NodeID: nodeID, Error: "admin authentication required"})
		return
	}

	s.mu.RLock()
	node, exists := s.nodes[nodeID]
	var nodeCopy protocol.NodeInfo
	if exists {
		nodeCopy = *node
	}
	agent := s.agents[nodeID]
	s.mu.RUnlock()

	if exists && nodeCopy.IsVPS && (req.Action == protocol.ActionSoftSleep || req.Action == protocol.ActionHardSleep || req.Action == protocol.ActionPowerOff) {
		writeJSON(w, http.StatusBadRequest, protocol.PowerResponse{
			OK:     false,
			NodeID: nodeID,
			Error:  "refusing to sleep or power off a VPS / virtual machine (would make it unreachable without provider console reboot)",
		})
		return
	}

	if req.Action == protocol.ActionWake {
		if agent != nil && nodeCopy.PowerState == protocol.PowerSleeping {
			s.evictAgent(nodeID, agent, true)
			agent = nil
		}

		var softWakeErr error
		if agent != nil {
			ack, err := s.sendAndWait(agent, protocol.ControlFrame{
				Type:   "power-cmd",
				Action: string(protocol.ActionWake),
			}, s.softWakeTimeout)
			if err == nil {
				if !ack.OK {
					writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{OK: false, NodeID: nodeID, Error: ack.Error})
					return
				}
				s.updateNodePowerState(nodeID, ack.PowerState)
				resp := protocol.PowerResponse{
					OK:         true,
					NodeID:     nodeID,
					Method:     "direct-soft-wake",
					PowerState: ack.PowerState,
				}
				if req.KeyringPassword != "" {
					uRes, _ := s.unlockWithAgent(nodeID, agent, req.KeyringPassword, 8*time.Second)
					resp.KeyringUnlocked = uRes.OK
					resp.KeyringError = uRes.Error
				}
				writeJSON(w, http.StatusOK, resp)
				return
			}
			softWakeErr = err
			s.evictAgent(nodeID, agent, false)
			agent = nil
		}

		// Target is offline, sleeping, or had a dead zombie socket: route via bound ESP32 Wake-on-LAN relay.
		mac := strings.TrimSpace(req.MAC)
		bcast := strings.TrimSpace(req.BroadcastIP)
		relayID := strings.TrimSpace(req.RelayNodeID)
		port := 9

		if exists && nodeCopy.WoL != nil {
			if mac == "" {
				mac = strings.TrimSpace(nodeCopy.WoL.MAC)
			}
			if bcast == "" {
				bcast = strings.TrimSpace(nodeCopy.WoL.BroadcastIP)
			}
			if relayID == "" {
				relayID = strings.TrimSpace(nodeCopy.WoL.WakeRelayID)
			}
			if nodeCopy.WoL.Port > 0 {
				port = nodeCopy.WoL.Port
			}
		}

		if mac == "" || relayID == "" {
			status := http.StatusBadRequest
			msg := "Wake-on-LAN is not bound for this machine (bind MAC + Wake Relay manually first)"
			if softWakeErr != nil {
				status = http.StatusServiceUnavailable
				msg = fmt.Sprintf("soft-wake failed (%v) and Wake-on-LAN is not bound", softWakeErr)
			}
			writeJSON(w, status, protocol.PowerResponse{
				OK:     false,
				NodeID: nodeID,
				Error:  msg,
			})
			return
		}

		s.mu.RLock()
		espRelay := s.esp32Relays[relayID]
		s.mu.RUnlock()

		if espRelay == nil {
			writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{
				OK:     false,
				NodeID: nodeID,
				Error:  fmt.Sprintf("bound wake relay %q is currently offline", relayID),
			})
			return
		}

		if req.KeyringPassword != "" {
			s.queueWakeKeyringUnlock(nodeID, req.KeyringPassword)
		}

		if err := s.sendESP32Wake(espRelay, mac, bcast, port, 5*time.Second); err != nil {
			if req.KeyringPassword != "" {
				s.clearWakeKeyringUnlock(nodeID)
			}
			writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{
				OK:     false,
				NodeID: nodeID,
				Error:  err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, protocol.PowerResponse{
			OK:           true,
			NodeID:       nodeID,
			Method:       "wol-esp32-relay",
			Relays:       []string{relayID},
			UnlockQueued: req.KeyringPassword != "",
		})
		return
	}

	if agent == nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{
			OK:     false,
			NodeID: nodeID,
			Error:  "target node is offline",
		})
		return
	}

	ack, err := s.sendAndWait(agent, protocol.ControlFrame{
		Type:   "power-cmd",
		Action: string(req.Action),
	}, 6*time.Second)
	if err != nil {
		if req.Action == protocol.ActionHardSleep || req.Action == protocol.ActionPowerOff {
			s.evictAgent(nodeID, agent, false)
		}
		writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{OK: false, NodeID: nodeID, Error: err.Error()})
		return
	}
	if !ack.OK {
		writeJSON(w, http.StatusServiceUnavailable, protocol.PowerResponse{OK: false, NodeID: nodeID, Error: ack.Error})
		return
	}
	if req.Action == protocol.ActionHardSleep {
		s.evictAgent(nodeID, agent, true)
	} else if req.Action == protocol.ActionPowerOff {
		s.evictAgent(nodeID, agent, false)
	} else if ack.PowerState != "" {
		s.updateNodePowerState(nodeID, ack.PowerState)
	}
	writeJSON(w, http.StatusOK, protocol.PowerResponse{
		OK:         true,
		NodeID:     nodeID,
		Method:     "direct-agent",
		PowerState: ack.PowerState,
	})
}

func (s *Server) selectRelayAgents(targetID string, targetInfo *protocol.NodeInfo, preferredRelay string) []*activeAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if preferredRelay != "" {
		if a := s.agents[preferredRelay]; a != nil {
			return []*activeAgent{a}
		}
	}

	targetSubnets := map[string]bool{}
	if targetInfo != nil {
		for _, cidr := range targetInfo.SubnetCIDRs {
			targetSubnets[cidr] = true
		}
	}

	var sameSubnet []*activeAgent
	var allOnline []*activeAgent

	for id, a := range s.agents {
		if id == targetID {
			continue
		}
		if n, ok := s.nodes[id]; ok {
			if n.IsVPS {
				// Cloud VPS agents cannot send Layer-2 WoL Magic Packets to a home LAN.
				continue
			}
			if len(targetSubnets) > 0 {
				for _, cidr := range n.SubnetCIDRs {
					if targetSubnets[cidr] {
						sameSubnet = append(sameSubnet, a)
						break
					}
				}
			}
		}
		allOnline = append(allOnline, a)
	}

	if len(sameSubnet) > 0 {
		return sameSubnet
	}
	return allOnline
}

func (s *Server) updateNodePowerState(nodeID string, state protocol.PowerState) {
	if state == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[nodeID]; ok {
		n.PowerState = state
		n.LastSeen = time.Now().UTC()
		s.persistNodesLocked()
	}
}

func (s *Server) evictAgent(nodeID string, agent *activeAgent, sleeping bool) {
	if agent == nil {
		return
	}
	s.mu.Lock()
	if s.agents[nodeID] == agent {
		delete(s.agents, nodeID)
		if n, exists := s.nodes[nodeID]; exists {
			n.Online = false
			n.KeyringLocked = nil
			n.LastSeen = time.Now().UTC()
			if sleeping {
				n.PowerState = protocol.PowerSleeping
			} else if n.PowerState != protocol.PowerSleeping {
				n.PowerState = protocol.PowerOffline
			}
			s.persistNodesLocked()
		}
	}
	s.mu.Unlock()
	agent.close()
}

func (s *Server) queueWakeKeyringUnlock(nodeID, password string) {
	if password == "" {
		return
	}
	ttl := s.keyringUnlockTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	entry := &pendingKeyringUnlock{
		password:  password,
		expiresAt: time.Now().Add(ttl),
	}

	s.mu.Lock()
	if prev := s.pendingKeyringUnlocks[nodeID]; prev != nil {
		if prev.timer != nil {
			prev.timer.Stop()
		}
		prev.password = ""
	}
	entry.timer = time.AfterFunc(ttl, func() {
		s.expirePendingKeyringUnlock(nodeID, entry)
	})
	s.pendingKeyringUnlocks[nodeID] = entry
	s.keyringStatus[nodeID] = keyringUnlockStatus{pending: true}
	s.mu.Unlock()
}

func (s *Server) expirePendingKeyringUnlock(nodeID string, expected *pendingKeyringUnlock) {
	s.mu.Lock()
	if cur := s.pendingKeyringUnlocks[nodeID]; cur == expected {
		cur.password = ""
		delete(s.pendingKeyringUnlocks, nodeID)
		delete(s.keyringStatus, nodeID)
	}
	s.mu.Unlock()
}

func (s *Server) clearWakeKeyringUnlock(nodeID string) {
	s.mu.Lock()
	if cur := s.pendingKeyringUnlocks[nodeID]; cur != nil {
		if cur.timer != nil {
			cur.timer.Stop()
		}
		cur.password = ""
		delete(s.pendingKeyringUnlocks, nodeID)
	}
	delete(s.keyringStatus, nodeID)
	s.mu.Unlock()
}

func (s *Server) consumePendingKeyringUnlock(nodeID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.pendingKeyringUnlocks[nodeID]
	if cur == nil {
		return "", false
	}
	if cur.timer != nil {
		cur.timer.Stop()
	}
	pw := cur.password
	exp := cur.expiresAt
	cur.password = ""
	delete(s.pendingKeyringUnlocks, nodeID)
	if pw == "" || !time.Now().Before(exp) {
		delete(s.keyringStatus, nodeID)
		return "", false
	}
	return pw, true
}

func (s *Server) runAutoKeyringUnlock(nodeID string, agent *activeAgent, password string) {
	_, _ = s.unlockWithAgent(nodeID, agent, password, 10*time.Second)
}

func (s *Server) unlockWithAgent(nodeID string, agent *activeAgent, password string, timeout time.Duration) (protocol.UnlockKeyringResponse, int) {
	s.mu.Lock()
	s.keyringStatus[nodeID] = keyringUnlockStatus{pending: true}
	s.mu.Unlock()

	ack, err := s.sendAndWait(agent, protocol.ControlFrame{
		Type:     "unlock-keyring",
		Password: password,
	}, timeout)
	if err != nil {
		s.mu.Lock()
		s.keyringStatus[nodeID] = keyringUnlockStatus{pending: false, err: err.Error()}
		s.mu.Unlock()
		return protocol.UnlockKeyringResponse{
			OK:     false,
			NodeID: nodeID,
			Error:  err.Error(),
		}, http.StatusServiceUnavailable
	}

	if !ack.OK {
		errMsg := ack.Error
		if errMsg == "" {
			errMsg = "failed to unlock keyring"
		}
		s.mu.Lock()
		if n, ok := s.nodes[nodeID]; ok && ack.KeyringLocked != nil {
			kl := *ack.KeyringLocked
			n.KeyringLocked = &kl
		}
		s.keyringStatus[nodeID] = keyringUnlockStatus{pending: false, err: errMsg}
		s.mu.Unlock()
		return protocol.UnlockKeyringResponse{
			OK:            false,
			NodeID:        nodeID,
			KeyringLocked: ack.KeyringLocked,
			Error:         errMsg,
		}, http.StatusUnauthorized
	}

	locked := false
	if ack.KeyringLocked != nil {
		locked = *ack.KeyringLocked
	}
	s.mu.Lock()
	if n, ok := s.nodes[nodeID]; ok {
		kl := locked
		n.KeyringLocked = &kl
	}
	delete(s.keyringStatus, nodeID)
	s.mu.Unlock()
	return protocol.UnlockKeyringResponse{
		OK:            true,
		NodeID:        nodeID,
		KeyringLocked: &locked,
	}, http.StatusOK
}

func (s *Server) sendAndWait(agent *activeAgent, frame protocol.ControlFrame, timeout time.Duration) (protocol.ControlFrame, error) {
	reqID := newRandomID(8)
	frame.ReqID = reqID
	ch := make(chan protocol.ControlFrame, 1)

	s.mu.Lock()
	s.pendingReq[reqID] = &pendingAck{ch: ch}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pendingReq, reqID)
		s.mu.Unlock()
	}()

	if err := agent.send(frame); err != nil {
		return protocol.ControlFrame{}, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		select {
		case resp := <-ch:
			return resp, nil
		default:
		}
		return protocol.ControlFrame{}, errors.New("agent timed out acknowledging command")
	case <-agent.closed:
		select {
		case resp := <-ch:
			return resp, nil
		default:
		}
		return protocol.ControlFrame{}, errors.New("agent disconnected before acknowledging command")
	}
}

func upgradeTunnelConn(w http.ResponseWriter, r *http.Request, customProto string) (net.Conn, error) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return ws.UpgradeServer(w, r)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, errors.New("hijacking not supported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + customProto + "\r\nConnection: Upgrade\r\n\r\n")
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return wrapHijackedConn(conn, rw), nil
}

func (s *Server) handleControlTunnel(w http.ResponseWriter, r *http.Request) {
	role, boundNodeID := s.authenticateRequest(r)
	hConn, err := upgradeTunnelConn(w, r, "ssh-fleet-control")
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(hConn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	handshakeTimeout := s.agentReadTimeout
	if handshakeTimeout <= 0 || handshakeTimeout > 15*time.Second {
		handshakeTimeout = 15 * time.Second
	}
	if handshakeTimeout < 2*time.Second {
		handshakeTimeout = 2 * time.Second
	}
	_ = hConn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	if !scanner.Scan() {
		_ = hConn.Close()
		return
	}

	var reg protocol.ControlFrame
	if err := json.Unmarshal(scanner.Bytes(), &reg); err != nil || reg.Type != "register" || reg.Node == nil || strings.TrimSpace(reg.Node.NodeID) == "" {
		_ = hConn.Close()
		return
	}

	regNodeID := strings.TrimSpace(reg.Node.NodeID)
	if role == authNode && regNodeID != boundNodeID {
		_ = hConn.Close()
		return
	}

	now := time.Now().UTC()
	node := *reg.Node
	node.NodeID = regNodeID
	node.Online = true
	node.KeyringUnlockPending = false
	node.KeyringUnlockError = ""
	if node.PowerState == "" || node.PowerState == protocol.PowerOffline || node.PowerState == protocol.PowerSleeping {
		node.PowerState = protocol.PowerActive
	}
	node.ConnectedAt = now
	node.LastSeen = now

	agent := &activeAgent{
		nodeID: node.NodeID,
		conn:   hConn,
		closed: make(chan struct{}),
	}

	s.mu.Lock()
	if old := s.agents[node.NodeID]; old != nil {
		old.close()
	}
	if prevNode := s.nodes[node.NodeID]; prevNode != nil {
		if prevNode.WoL != nil {
			node.WoL = prevNode.WoL
		}
		if prevNode.CustomName && strings.TrimSpace(prevNode.Name) != "" {
			node.Name = prevNode.Name
			node.CustomName = true
		}
	}
	s.agents[node.NodeID] = agent
	s.nodes[node.NodeID] = &node
	s.persistNodesLocked()
	s.mu.Unlock()

	_ = agent.send(protocol.ControlFrame{Type: "register-ack", OK: true})

	if pw, ok := s.consumePendingKeyringUnlock(node.NodeID); ok {
		if node.KeyringLocked != nil && !*node.KeyringLocked {
			s.mu.Lock()
			delete(s.keyringStatus, node.NodeID)
			s.mu.Unlock()
		} else {
			go s.runAutoKeyringUnlock(node.NodeID, agent, pw)
		}
	}

	defer func() {
		agent.close()
		s.mu.Lock()
		if s.agents[node.NodeID] == agent {
			delete(s.agents, node.NodeID)
			if n, exists := s.nodes[node.NodeID]; exists {
				n.Online = false
				n.KeyringLocked = nil
				n.LastSeen = time.Now().UTC()
				if n.PowerState != protocol.PowerSleeping {
					n.PowerState = protocol.PowerOffline
				}
				s.persistNodesLocked()
			}
		}
		s.mu.Unlock()
	}()

	for {
		_ = hConn.SetReadDeadline(time.Now().Add(s.agentReadTimeout))
		if !scanner.Scan() {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var frame protocol.ControlFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			continue
		}

		switch frame.Type {
		case "ping":
			s.mu.Lock()
			if n, exists := s.nodes[node.NodeID]; exists {
				n.LastSeen = time.Now().UTC()
				if frame.PowerState != "" {
					n.PowerState = frame.PowerState
				}
				if frame.KeyringLocked != nil {
					kl := *frame.KeyringLocked
					n.KeyringLocked = &kl
					if !kl {
						if st, ok := s.keyringStatus[node.NodeID]; ok && !st.pending {
							delete(s.keyringStatus, node.NodeID)
						}
					}
				}
			}
			s.mu.Unlock()
			_ = agent.send(protocol.ControlFrame{Type: "pong"})
		case "state-update":
			s.mu.Lock()
			if n, exists := s.nodes[node.NodeID]; exists {
				if frame.Node != nil {
					upd := *frame.Node
					upd.NodeID = node.NodeID
					upd.Online = true
					upd.ConnectedAt = n.ConnectedAt
					upd.LastSeen = time.Now().UTC()
					upd.WoL = n.WoL
					if n.CustomName && strings.TrimSpace(n.Name) != "" {
						upd.Name = n.Name
						upd.CustomName = true
					}
					upd.KeyringUnlockPending = false
					upd.KeyringUnlockError = ""
					if upd.KeyringLocked == nil {
						upd.KeyringLocked = n.KeyringLocked
					}
					s.nodes[node.NodeID] = &upd
				} else if frame.PowerState != "" {
					n.PowerState = frame.PowerState
					n.LastSeen = time.Now().UTC()
				}
				s.persistNodesLocked()
			}
			s.mu.Unlock()
		case "power-ack", "wol-ack", "unlock-keyring-ack":
			if frame.Type == "unlock-keyring-ack" && frame.KeyringLocked != nil {
				s.mu.Lock()
				if n, exists := s.nodes[node.NodeID]; exists {
					kl := *frame.KeyringLocked
					n.KeyringLocked = &kl
				}
				s.mu.Unlock()
			}
			if frame.ReqID != "" {
				s.mu.RLock()
				p := s.pendingReq[frame.ReqID]
				s.mu.RUnlock()
				if p != nil {
					select {
					case p.ch <- frame:
					default:
					}
				}
			}
		}
	}
}

func (s *Server) handleAgentStream(w http.ResponseWriter, r *http.Request) {
	streamID := strings.TrimSpace(r.URL.Query().Get("stream_id"))
	if streamID == "" {
		http.Error(w, "missing stream_id", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	ch := s.streams[streamID]
	s.mu.RUnlock()
	if ch == nil {
		http.Error(w, "unknown or expired stream_id", http.StatusNotFound)
		return
	}

	wrapped, err := upgradeTunnelConn(w, r, "ssh-fleet-stream")
	if err != nil {
		return
	}
	select {
	case ch <- wrapped:
	default:
		_ = wrapped.Close()
	}
}

func (s *Server) handleClientProxy(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		http.Error(w, "missing node_id", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	agent := s.agents[nodeID]
	s.mu.RUnlock()
	if agent == nil {
		http.Error(w, "node is offline", http.StatusServiceUnavailable)
		return
	}

	streamID := newRandomID(12)
	streamCh := make(chan net.Conn, 1)

	s.mu.Lock()
	s.streams[streamID] = streamCh
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.streams, streamID)
		s.mu.Unlock()
	}()

	if err := agent.send(protocol.ControlFrame{
		Type:     "open-ssh-stream",
		StreamID: streamID,
	}); err != nil {
		http.Error(w, "failed to reach agent", http.StatusBadGateway)
		return
	}

	var agentConn net.Conn
	select {
	case agentConn = <-streamCh:
	case <-time.After(10 * time.Second):
		http.Error(w, "agent stream timeout", http.StatusGatewayTimeout)
		return
	case <-r.Context().Done():
		return
	}

	wrappedClient, err := upgradeTunnelConn(w, r, "ssh-fleet-proxy")
	if err != nil {
		_ = agentConn.Close()
		return
	}
	spliceConns(wrappedClient, agentConn)
}

func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	ws, err := UpgradeWebSocket(w, r)
	if err != nil {
		return
	}
	defer ws.Close()

	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = "agent"
	}

	if mode == "agent" {
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		if nodeID == "" {
			_ = ws.WriteText("missing node_id\r\n")
			return
		}
		s.mu.RLock()
		agent := s.agents[nodeID]
		s.mu.RUnlock()
		if agent == nil {
			_ = ws.WriteText("target agent is offline\r\n")
			return
		}

		streamID := newRandomID(12)
		streamCh := make(chan net.Conn, 1)
		s.mu.Lock()
		s.streams[streamID] = streamCh
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.streams, streamID)
			s.mu.Unlock()
		}()

		if err := agent.send(protocol.ControlFrame{
			Type:     "open-shell-stream",
			StreamID: streamID,
		}); err != nil {
			_ = ws.WriteText("failed to contact agent\r\n")
			return
		}

		var agentConn net.Conn
		select {
		case agentConn = <-streamCh:
		case <-time.After(10 * time.Second):
			_ = ws.WriteText("timed out waiting for agent shell stream\r\n")
			return
		case <-r.Context().Done():
			return
		}
		defer agentConn.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				n, rErr := agentConn.Read(buf)
				if n > 0 {
					if wErr := ws.WriteBinary(buf[:n]); wErr != nil {
						break
					}
				}
				if rErr != nil {
					break
				}
			}
			_ = ws.Close()
		}()
		go func() {
			defer wg.Done()
			for {
				op, payload, rErr := ws.ReadMessage()
				if rErr != nil {
					break
				}
				if op == 0x1 || op == 0x2 {
					if _, wErr := agentConn.Write(payload); wErr != nil {
						break
					}
				}
			}
			_ = agentConn.Close()
		}()
		wg.Wait()
		return
	}

	// mode == "ssh": read initial JSON spec from WebSocket.
	_, initPayload, err := ws.ReadMessage()
	if err != nil {
		return
	}
	var spec struct {
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user"`
		NodeID     string `json:"node_id"`
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(initPayload, &spec); err != nil {
		_ = ws.WriteText("invalid ssh session spec\r\n")
		return
	}

	var tempFiles []string
	defer func() {
		for _, f := range tempFiles {
			_ = os.Remove(f)
		}
	}()

	sshArgs := []string{"-tt", "-o", "StrictHostKeyChecking=accept-new"}
	if strings.TrimSpace(spec.PrivateKey) != "" {
		kf, kErr := os.CreateTemp("", "sf-webssh-key-*")
		if kErr == nil {
			keyStr := spec.PrivateKey
			if !strings.HasSuffix(keyStr, "\n") {
				keyStr += "\n"
			}
			_, _ = kf.WriteString(keyStr)
			_ = kf.Chmod(0600)
			_ = kf.Close()
			tempFiles = append(tempFiles, kf.Name())
			sshArgs = append(sshArgs, "-i", kf.Name(), "-o", "IdentitiesOnly=yes")
		}
	}

	if spec.NodeID != "" {
		selfBin, _ := os.Executable()
		if selfBin != "" {
			listenAddr := "127.0.0.1:8090"
			if s.httpSrv != nil && s.httpSrv.Addr != "" {
				if strings.HasPrefix(s.httpSrv.Addr, ":") {
					listenAddr = "127.0.0.1" + s.httpSrv.Addr
				} else {
					listenAddr = s.httpSrv.Addr
				}
			}
			_ = listenAddr
			// Spawn internal loopback bridge if needed; simplest portable path uses local sf config or agent stream.
			sshArgs = append(sshArgs, "-o", fmt.Sprintf("ProxyCommand=\"%s\" proxy %s", selfBin, spec.NodeID))
		}
		dest := spec.NodeID
		if spec.User != "" {
			dest = spec.User + "@" + dest
		}
		sshArgs = append(sshArgs, dest)
	} else {
		if spec.Port > 0 && spec.Port != 22 {
			sshArgs = append(sshArgs, "-p", strconv.Itoa(spec.Port))
		}
		dest := spec.Host
		if spec.User != "" {
			dest = spec.User + "@" + dest
		}
		sshArgs = append(sshArgs, dest)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("script"); err == nil {
			quoted := "ssh"
			for _, a := range sshArgs {
				quoted += " '" + strings.ReplaceAll(a, "'", "'\"'\"'") + "'"
			}
			cmd = exec.Command("script", "-q", "-c", quoted, "/dev/null")
		}
	}
	if cmd == nil {
		cmd = exec.Command("ssh", sshArgs...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = ws.WriteText("stdin pipe error: " + err.Error() + "\r\n")
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = ws.WriteText("stdout pipe error: " + err.Error() + "\r\n")
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = ws.WriteText("stderr pipe error: " + err.Error() + "\r\n")
		return
	}
	if err := cmd.Start(); err != nil {
		_ = ws.WriteText("failed to start ssh: " + err.Error() + "\r\n")
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pipeOut := func(rd io.Reader) {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rErr := rd.Read(buf)
			if n > 0 {
				if wErr := ws.WriteBinary(buf[:n]); wErr != nil {
					break
				}
			}
			if rErr != nil {
				break
			}
		}
	}
	go pipeOut(stdout)
	go pipeOut(stderr)

	go func() {
		for {
			op, payload, rErr := ws.ReadMessage()
			if rErr != nil {
				break
			}
			if op == 0x1 || op == 0x2 {
				if _, wErr := stdin.Write(payload); wErr != nil {
					break
				}
			}
		}
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	wg.Wait()
	_ = cmd.Wait()
}

func (s *Server) handleESP32WakeTunnel(w http.ResponseWriter, r *http.Request) {
	relayID := ""
	registered := false
	if rec, ok := s.wakeReg.VerifyBearer(r.Header.Get("Authorization")); ok {
		relayID = rec.ID
		registered = true
	} else if role, _ := s.authenticateRequest(r); role == authAdmin {
		relayID = "esp32-" + newRandomID(4)
	} else {
		http.Error(w, `{"ok":false,"error":"invalid wake relay credential"}`, http.StatusUnauthorized)
		return
	}

	conn, err := ws.UpgradeServer(w, r)
	if err != nil {
		return
	}
	relay := &esp32WakeRelay{
		id: relayID,
		ws: conn,
		pending: make(map[string]chan struct {
			ok  bool
			err string
		}),
		closed: make(chan struct{}),
	}

	s.mu.Lock()
	if prev := s.esp32Relays[relayID]; prev != nil {
		prev.close()
	}
	s.esp32Relays[relayID] = relay
	s.mu.Unlock()

	if registered {
		s.wakeReg.MarkSeen(relayID, "")
	}

	defer func() {
		relay.close()
		s.mu.Lock()
		if s.esp32Relays[relayID] == relay {
			delete(s.esp32Relays, relayID)
		}
		s.mu.Unlock()
		if registered {
			s.wakeReg.MarkSeen(relayID, "")
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.esp32ReadTimeout))
		_, payload, rErr := conn.ReadMessage()
		if rErr != nil {
			return
		}
		var msg struct {
			T               string `json:"t"`
			FirmwareVersion string `json:"firmwareVersion,omitempty"`
			RequestID       string `json:"requestId,omitempty"`
			OK              bool   `json:"ok,omitempty"`
			Error           string `json:"error,omitempty"`
		}
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}
		switch msg.T {
		case "hello":
			if registered {
				s.wakeReg.MarkSeen(relayID, strings.TrimSpace(msg.FirmwareVersion))
			}
			ack, _ := json.Marshal(map[string]any{"t": "hello-ack", "agentId": relayID})
			_ = conn.WriteText(string(ack))
		case "ping":
			if registered {
				s.wakeReg.MarkSeen(relayID, "")
			}
			pong, _ := json.Marshal(map[string]any{"t": "pong", "ts": time.Now().UnixMilli()})
			_ = conn.WriteText(string(pong))
		case "wake-ack":
			relay.mu.Lock()
			ch := relay.pending[msg.RequestID]
			delete(relay.pending, msg.RequestID)
			relay.mu.Unlock()
			if ch != nil {
				ch <- struct {
					ok  bool
					err string
				}{ok: msg.OK, err: msg.Error}
			}
		}
	}
}

func (s *Server) sendESP32Wake(relay *esp32WakeRelay, mac, broadcastIP string, port int, timeout time.Duration) error {
	if port <= 0 {
		port = 9
	}
	reqID := newRandomID(8)
	ch := make(chan struct {
		ok  bool
		err string
	}, 1)

	relay.mu.Lock()
	relay.pending[reqID] = ch
	relay.mu.Unlock()

	defer func() {
		relay.mu.Lock()
		delete(relay.pending, reqID)
		relay.mu.Unlock()
	}()

	payload := map[string]any{
		"t":         "wake",
		"requestId": reqID,
		"mac":       mac,
		"port":      port,
	}
	if broadcastIP != "" {
		payload["broadcastIp"] = broadcastIP
	}
	b, _ := json.Marshal(payload)
	if err := relay.ws.WriteText(string(b)); err != nil {
		return err
	}

	select {
	case res := <-ch:
		if !res.ok {
			if res.err == "" {
				return errors.New("esp32 wake failed")
			}
			return errors.New(res.err)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("esp32 wake relay timed out")
	case <-relay.closed:
		return errors.New("esp32 wake relay disconnected")
	}
}

func spliceConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newRandomID(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
