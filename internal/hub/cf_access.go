package hub

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cfJWKSRefreshTTL       = 10 * time.Minute
	cfJWKSMinForceInterval = 10 * time.Second
	cfClockSkewSeconds     = 60
)

type cfAccessVerifier struct {
	teamDomain string
	audTags    map[string]struct{}
	jwksURL    string
	httpClient *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newCFAccessVerifier(teamDomain, audCSV, jwksURLOverride string) (*cfAccessVerifier, error) {
	td := strings.ToLower(strings.TrimSpace(teamDomain))
	td = strings.TrimPrefix(td, "https://")
	td = strings.TrimPrefix(td, "http://")
	td = strings.TrimRight(td, "/")
	if idx := strings.IndexByte(td, '/'); idx >= 0 {
		td = td[:idx]
	}

	audTags := make(map[string]struct{})
	for _, part := range strings.Split(audCSV, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			audTags[p] = struct{}{}
		}
	}

	jwksOverride := strings.TrimSpace(jwksURLOverride)
	if td == "" && len(audTags) == 0 && jwksOverride == "" {
		return nil, nil
	}
	if len(audTags) == 0 {
		return nil, errors.New("cloudflare access JWT verifier requires CFAccessAUD when team domain or JWKS URL is set")
	}
	if td == "" && jwksOverride == "" {
		return nil, errors.New("cloudflare access JWT verifier requires CFAccessTeamDomain")
	}

	jwksURL := jwksOverride
	if jwksURL == "" {
		jwksURL = "https://" + td + "/cdn-cgi/access/certs"
	}

	return &cfAccessVerifier{
		teamDomain: td,
		audTags:    audTags,
		jwksURL:    jwksURL,
		httpClient: &http.Client{Timeout: 8 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
	}, nil
}

func (v *cfAccessVerifier) VerifyRequest(r *http.Request) (string, bool) {
	if v == nil || r == nil {
		return "", false
	}
	tok := strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion"))
	if tok == "" {
		if c, err := r.Cookie("CF_Authorization"); err == nil {
			tok = strings.TrimSpace(c.Value)
		}
	}
	if tok == "" {
		return "", false
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "RS256" {
		return "", false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Iss        string          `json:"iss"`
		Email      string          `json:"email"`
		CommonName string          `json:"common_name"`
		Exp        float64         `json:"exp"`
		Nbf        float64         `json:"nbf"`
		Aud        json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", false
	}

	now := time.Now().Unix()
	if claims.Exp <= 0 || now > int64(claims.Exp)+cfClockSkewSeconds {
		return "", false
	}
	if claims.Nbf > 0 && now+cfClockSkewSeconds < int64(claims.Nbf) {
		return "", false
	}

	if v.teamDomain != "" {
		wantIss := "https://" + v.teamDomain
		gotIss := strings.TrimRight(strings.ToLower(strings.TrimSpace(claims.Iss)), "/")
		if gotIss != wantIss {
			return "", false
		}
	}

	if !v.audMatches(claims.Aud) {
		return "", false
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !v.verifyWithKeys(hdr.Kid, digest[:], sigBytes) {
		return "", false
	}

	identity := strings.ToLower(strings.TrimSpace(claims.Email))
	if identity == "" {
		identity = strings.ToLower(strings.TrimSpace(claims.CommonName))
	}
	return identity, true
}

func (v *cfAccessVerifier) audMatches(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		_, ok := v.audTags[strings.TrimSpace(single)]
		return ok
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		for _, a := range multi {
			if _, ok := v.audTags[strings.TrimSpace(a)]; ok {
				return true
			}
		}
	}
	return false
}

func (v *cfAccessVerifier) verifyWithKeys(kid string, digest, sig []byte) bool {
	keys := v.getKeys(kid)
	for _, pub := range keys {
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig) == nil {
			return true
		}
	}
	return false
}

func (v *cfAccessVerifier) getKeys(kid string) []*rsa.PublicKey {
	v.mu.RLock()
	fresh := time.Since(v.fetchedAt) < cfJWKSRefreshTTL && len(v.keys) > 0
	var matched []*rsa.PublicKey
	if fresh {
		if kid != "" {
			if k := v.keys[kid]; k != nil {
				matched = []*rsa.PublicKey{k}
			}
		} else {
			for _, k := range v.keys {
				matched = append(matched, k)
			}
		}
	}
	canForceRefresh := time.Since(v.fetchedAt) >= cfJWKSMinForceInterval
	v.mu.RUnlock()

	if len(matched) > 0 || (fresh && !canForceRefresh) {
		return matched
	}

	if err := v.refreshJWKS(); err != nil {
		// Fall back to cached keys on transient JWKS outage.
		v.mu.RLock()
		defer v.mu.RUnlock()
		if kid != "" {
			if k := v.keys[kid]; k != nil {
				return []*rsa.PublicKey{k}
			}
			return nil
		}
		var all []*rsa.PublicKey
		for _, k := range v.keys {
			all = append(all, k)
		}
		return all
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	if kid != "" {
		if k := v.keys[kid]; k != nil {
			return []*rsa.PublicKey{k}
		}
		return nil
	}
	var all []*rsa.PublicKey
	for _, k := range v.keys {
		all = append(all, k)
	}
	return all
}

func (v *cfAccessVerifier) refreshJWKS() error {
	resp, err := v.httpClient.Get(v.jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	nextKeys := make(map[string]*rsa.PublicKey)
	for i, jwk := range doc.Keys {
		if jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		pub, err := parseRSAPublicKey(jwk.N, jwk.E)
		if err != nil {
			continue
		}
		id := jwk.Kid
		if id == "" {
			id = fmt.Sprintf("key-%d", i)
		}
		nextKeys[id] = pub
	}
	if len(nextKeys) == 0 {
		return errors.New("jwks contained no valid RSA public keys")
	}

	v.mu.Lock()
	v.keys = nextKeys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil || len(nBytes) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	var eVal int
	for _, b := range eBytes {
		eVal = (eVal << 8) | int(b)
	}
	if eVal < 3 {
		return nil, errors.New("RSA exponent too small")
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < 1024 {
		return nil, errors.New("RSA key size too small")
	}
	return &rsa.PublicKey{N: n, E: eVal}, nil
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if zoneIdx := strings.IndexByte(host, '%'); zoneIdx >= 0 {
		host = host[:zoneIdx]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
