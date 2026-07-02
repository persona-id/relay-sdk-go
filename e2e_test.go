package persona

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var hexNonceRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestFullPrivacyPassFlow exercises the complete relay lifecycle against a mock Persona
// server. The HTTP API is mocked, but all blind RSA cryptography is real end-to-end.
func TestFullPrivacyPassFlow(t *testing.T) {
	e2eClaimPayload := `{"claim_type":"age_over18_united_kingdom","status":"success"}`

	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "generate-claim"):
			writeJSON(w, map[string]any{"claim-payload": e2eClaimPayload, "token-consumed": true})
		case strings.Contains(r.URL.Path, "/challenge"):
			writeJSON(w, map[string]any{
				"challenge":    m.challengeBase64,
				"token-key":    m.publicKeyB64,
				"token-key-id": testTokenKeyID,
			})
		case strings.Contains(r.URL.Path, "privacy-passes"):
			writeJSON(w, map[string]any{"blind-sig": m.blindSign(t, readBody(r))})
		case strings.Contains(r.URL.Path, "/relays"):
			writeJSON(w, map[string]any{
				"relay-token":                testRelayToken,
				"relay-secret":               testRelaySecret,
				"relay-session-access-token": "jwt.session.token",
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	})

	ctx := context.Background()
	persona := m.client()

	// Step 1: create a relay session.
	relay, err := persona.Relays.Create(ctx, CreateRelayParams{ClaimType: "age_over18_united_kingdom"})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if relay.RelayToken != testRelayToken || relay.RelaySecret != testRelaySecret {
		t.Fatalf("unexpected relay: %+v", relay)
	}

	// Step 2: issue a Privacy Pass token via the blind RSA flow.
	issue, err := persona.Relays.IssuePrivacyPass(ctx, IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(issue.PrivacyPassToken)
	if err != nil {
		t.Fatalf("failed to decode privacy pass token: %v", err)
	}
	var payload struct {
		TokenNonce string         `json:"token_nonce"`
		Signature  string         `json:"signature"`
		KeyID      string         `json:"key_id"`
		Challenge  map[string]any `json:"challenge"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("failed to parse token payload: %v", err)
	}
	if !hexNonceRegex.MatchString(payload.TokenNonce) {
		t.Errorf("expected 64-char hex nonce, got %q", payload.TokenNonce)
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if payload.KeyID != testTokenKeyID {
		t.Errorf("expected key_id %q, got %q", testTokenKeyID, payload.KeyID)
	}
	if mac, _ := payload.Challenge["mac"].(string); mac != m.challengeMac {
		t.Errorf("expected challenge mac %q, got %q", m.challengeMac, mac)
	}

	// Step 3: redeem the Privacy Pass token for a claim.
	claim, err := persona.Relays.GenerateClaim(ctx, GenerateClaimParams{
		PrivacyPassToken: issue.PrivacyPassToken,
		RelayToken:       relay.RelayToken,
		RelaySecret:      relay.RelaySecret,
	})
	if err != nil {
		t.Fatalf("generate claim failed: %v", err)
	}
	if claim.ClaimPayload != e2eClaimPayload || !claim.TokenConsumed {
		t.Fatalf("unexpected claim: %+v", claim)
	}
}
