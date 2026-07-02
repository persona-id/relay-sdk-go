package persona

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	testAPIKey      = "persona_api_key"
	testRelayToken  = "relay_token_abc123"
	testRelaySecret = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	testTokenKeyID  = "abc123"
)

type capturedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

type mockPersona struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []capturedRequest

	signer          blindrsa.Signer
	publicKeyB64    string
	challengeMac    string
	challengeBase64 string
}

func newTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(spki)
}

func newMockPersona(t *testing.T, handler func(m *mockPersona, w http.ResponseWriter, r *http.Request)) *mockPersona {
	t.Helper()

	priv, pubB64 := newTestKey(t)

	macBytes := make([]byte, 32)
	if _, err := rand.Read(macBytes); err != nil {
		t.Fatalf("failed to generate mac: %v", err)
	}
	mac := hex.EncodeToString(macBytes)
	challengeJSON, _ := json.Marshal(map[string]any{
		"token_type":  2,
		"issuer_name": "persona",
		"origin_info": "https://withpersona.com",
		"expires_at":  "2026-06-25T20:00:00Z",
		"mac":         mac,
	})

	m := &mockPersona{
		signer:          blindrsa.NewSigner(priv),
		publicKeyB64:    pubB64,
		challengeMac:    mac,
		challengeBase64: base64.RawURLEncoding.EncodeToString(challengeJSON),
	}

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requests = append(m.requests, capturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   body,
		})
		m.mu.Unlock()

		r.Body = io.NopCloser(bytes.NewReader(body))
		handler(m, w, r)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockPersona) calls() []capturedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *mockPersona) client() *Persona {
	return New(Options{APIKey: testAPIKey, BaseURL: m.server.URL})
}

func readBody(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, title string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{{"title": title}},
	})
}

func (m *mockPersona) blindSign(t *testing.T, body []byte) string {
	t.Helper()
	var req struct {
		BlindedToken string `json:"blindedToken"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to parse privacy-passes body: %v", err)
	}
	blinded, err := base64.RawURLEncoding.DecodeString(req.BlindedToken)
	if err != nil {
		t.Fatalf("failed to decode blinded token: %v", err)
	}
	sig, err := m.signer.BlindSign(blinded)
	if err != nil {
		t.Fatalf("blind sign failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}
