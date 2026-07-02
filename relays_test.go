package persona

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

var createRelayBody = map[string]any{
	"relay-token":                testRelayToken,
	"relay-secret":               "secret-uuid-1234",
	"relay-session-access-token": "jwt.session.token",
}

func defaultCreateParams() CreateRelayParams {
	return CreateRelayParams{ClaimType: "age_over18_united_kingdom", EncryptionKeyPEM: nil}
}

// ── Persona client configuration ────────────────────────────────────────────

func TestBaseURLOverride(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, createRelayBody)
	})

	_, err := m.client().Relays.Create(context.Background(), defaultCreateParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := m.calls()
	if len(calls) != 1 || calls[0].Path != "/api/privacy/v1/relays" {
		t.Fatalf("expected request to /api/privacy/v1/relays, got %+v", calls)
	}
}

// ── relays.Create ───────────────────────────────────────────────────────────

func TestCreateReturnsTokens(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, createRelayBody)
	})

	res, err := m.client().Relays.Create(context.Background(), defaultCreateParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RelayToken != testRelayToken || res.RelaySecret != "secret-uuid-1234" || res.RelaySessionAccessToken != "jwt.session.token" {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestCreateSendsNoAuthHeaderWithoutAPIKey(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, createRelayBody)
	})

	persona := New(Options{BaseURL: m.server.URL}) // no API key
	if _, err := persona.Relays.Create(context.Background(), defaultCreateParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth := m.calls()[0].Header.Get("Authorization"); auth != "" {
		t.Fatalf("expected no Authorization header, got %q", auth)
	}
}

func TestCreateForwardsClaimTypeAndNullEncryptionKey(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, createRelayBody)
	})

	if _, err := m.client().Relays.Create(context.Background(), defaultCreateParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(m.calls()[0].Body, &body); err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}
	if body["claimType"] != "age_over18_united_kingdom" {
		t.Errorf("expected claimType forwarded, got %v", body["claimType"])
	}
	if v, ok := body["encryptionKeyPem"]; !ok || v != nil {
		t.Errorf("expected encryptionKeyPem null, got %v (present=%v)", v, ok)
	}
}

func TestCreateForwardsEncryptionKeyWhenProvided(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, createRelayBody)
	})

	pem := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n"
	params := defaultCreateParams()
	params.EncryptionKeyPEM = ptr(pem)
	if _, err := m.client().Relays.Create(context.Background(), params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body map[string]any
	_ = json.Unmarshal(m.calls()[0].Body, &body)
	if body["encryptionKeyPem"] != pem {
		t.Errorf("expected encryptionKeyPem forwarded, got %v", body["encryptionKeyPem"])
	}
}

func TestCreateBubblesUpPersonaErrors(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{
		{400, "Bad Request Test"},
		{401, "Unauthorized Test"},
		{404, "Not Found Test"},
		{503, "Service Unavailable Test"},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
				writeError(w, tc.status, tc.title)
			})

			_, err := m.client().Relays.Create(context.Background(), defaultCreateParams())
			assertPersonaError(t, err, tc.status, tc.title)
		})
	}
}

// ── IssuePrivacyPass ─────────────────────────────────────────────────────────

// issuanceHandler mocks the challenge + privacy-passes calls for a successful issuance.
func issuanceHandler(t *testing.T) func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
	return func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/challenge"):
			writeJSON(w, map[string]any{
				"challenge":    m.challengeBase64,
				"token-key":    m.publicKeyB64,
				"token-key-id": testTokenKeyID,
			})
		case strings.Contains(r.URL.Path, "privacy-passes"):
			body := readBody(r)
			writeJSON(w, map[string]any{"blind-sig": m.blindSign(t, body)})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}
}

func TestIssuePrivacyPassChallengeErrors(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{{400, "Bad Request"}, {401, "Unauthorized"}, {404, "Not Found"}, {503, "Service Unavailable"}}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
				writeError(w, tc.status, tc.title)
			})
			_, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
			assertPersonaError(t, err, tc.status, tc.title)
		})
	}
}

func TestIssuePrivacyPassPrivacyPassesErrors(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{{400, "Bad Request"}, {401, "Unauthorized"}, {404, "Not Found"}, {503, "Service Unavailable"}}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/challenge") {
					writeJSON(w, map[string]any{
						"challenge":    m.challengeBase64,
						"token-key":    m.publicKeyB64,
						"token-key-id": testTokenKeyID,
					})
					return
				}
				writeError(w, tc.status, tc.title)
			})
			_, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
			assertPersonaError(t, err, tc.status, tc.title)
		})
	}
}

func TestIssuePrivacyPassReturnsToken(t *testing.T) {
	m := newMockPersona(t, issuanceHandler(t))
	res, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PrivacyPassToken == "" {
		t.Fatal("expected non-empty privacy pass token")
	}
}

func TestIssuePrivacyPassChallengeCallShape(t *testing.T) {
	m := newMockPersona(t, issuanceHandler(t))
	if _, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	challenge := findCall(m.calls(), "/challenge")
	if challenge == nil {
		t.Fatal("expected a challenge call")
	}
	if challenge.Path != "/api/privacy/v1/relays/challenge" {
		t.Errorf("unexpected challenge path: %s", challenge.Path)
	}
	var body map[string]any
	_ = json.Unmarshal(challenge.Body, &body)
	if body["claimType"] != "age_over18_united_kingdom" {
		t.Errorf("expected claimType in challenge body, got %v", body["claimType"])
	}
	if auth := challenge.Header.Get("Authorization"); auth != "" {
		t.Errorf("expected no auth header on challenge, got %q", auth)
	}
}

func TestIssuePrivacyPassPrivacyPassesAuth(t *testing.T) {
	m := newMockPersona(t, issuanceHandler(t))
	if _, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	call := findCall(m.calls(), "privacy-passes")
	if call == nil {
		t.Fatal("expected a privacy-passes call")
	}
	if got := call.Header.Get("Authorization"); got != "Bearer "+testAPIKey {
		t.Errorf("expected Bearer auth, got %q", got)
	}
	if got := call.Header.Get("Persona-Relay-Secret"); got != "" {
		t.Errorf("expected no relay secret header, got %q", got)
	}
	var body map[string]any
	_ = json.Unmarshal(call.Body, &body)
	if _, ok := body["relayToken"]; ok {
		t.Error("expected no relayToken in privacy-passes body")
	}
}

// challengeOnlyHandler serves a challenge response with the given base64url challenge
// and fails the test if any other endpoint is hit.
func challengeOnlyHandler(t *testing.T, challengeB64 string) func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
	return func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/challenge") {
			t.Errorf("unexpected path: %s", r.URL.Path)
			return
		}
		writeJSON(w, map[string]any{
			"challenge":    challengeB64,
			"token-key":    m.publicKeyB64,
			"token-key-id": testTokenKeyID,
		})
	}
}

func TestIssuePrivacyPassRejectsMissingMac(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"x"}`))
	m := newMockPersona(t, challengeOnlyHandler(t, challenge))
	_, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
	assertPersonaError(t, err, int(StatusBadGateway), "Challenge missing mac")
}

func TestIssuePrivacyPassRejectsNonStringMac(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString([]byte(`{"mac":123}`))
	m := newMockPersona(t, challengeOnlyHandler(t, challenge))
	_, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
	assertPersonaError(t, err, int(StatusBadGateway), "Failed to parse challenge")
}

func TestIssuePrivacyPassEchoesFullChallenge(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/challenge"):
			challenge := base64.RawURLEncoding.EncodeToString([]byte(`{"mac":"` + m.challengeMac + `","extra":"keep-me"}`))
			writeJSON(w, map[string]any{
				"challenge":    challenge,
				"token-key":    m.publicKeyB64,
				"token-key-id": testTokenKeyID,
			})
		case strings.Contains(r.URL.Path, "privacy-passes"):
			writeJSON(w, map[string]any{"blind-sig": m.blindSign(t, readBody(r))})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	})

	res, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(res.PrivacyPassToken)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}
	var payload struct {
		Challenge map[string]any `json:"challenge"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	if payload.Challenge["extra"] != "keep-me" {
		t.Errorf("expected extra challenge field echoed back, got %v", payload.Challenge["extra"])
	}
}

func TestIssuePrivacyPassMakesTwoCalls(t *testing.T) {
	m := newMockPersona(t, issuanceHandler(t))
	if _, err := m.client().Relays.IssuePrivacyPass(context.Background(), IssuePrivacyPassParams{ClaimType: "age_over18_united_kingdom"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(m.calls()); n != 2 {
		t.Fatalf("expected exactly 2 calls, got %d", n)
	}
}

// ── GenerateClaim ─────────────────────────────────────────────────────────────

var claimPayload = `{"age_over_18":true,"country":"GB"}`

func defaultGenerateParams() GenerateClaimParams {
	return GenerateClaimParams{
		PrivacyPassToken: base64.RawURLEncoding.EncodeToString([]byte(`{"token_nonce":"abc","signature":"def","key_id":"ghi"}`)),
		RelayToken:       testRelayToken,
		RelaySecret:      testRelaySecret,
	}
}

func redemptionBody() map[string]any {
	return map[string]any{"claim-payload": claimPayload, "token-consumed": true}
}

func TestGenerateClaimErrors(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{{400, "Bad Request"}, {401, "Unauthorized"}, {404, "Not Found"}, {503, "Service Unavailable"}}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
				writeError(w, tc.status, tc.title)
			})
			_, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams())
			assertPersonaError(t, err, tc.status, tc.title)
		})
	}
}

func TestGenerateClaimReturnsClaim(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redemptionBody())
	})
	res, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ClaimPayload != claimPayload || !res.TokenConsumed {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestGenerateClaimPrivateTokenAuth(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redemptionBody())
	})
	params := defaultGenerateParams()
	if _, err := m.client().Relays.GenerateClaim(context.Background(), params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.calls()[0].Header.Get("Authorization")
	if got != "PrivateToken token="+params.PrivacyPassToken {
		t.Fatalf("unexpected authorization: %q", got)
	}
}

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestGenerateClaimIdempotencyKey(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redemptionBody())
	})
	if _, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	key := m.calls()[0].Header.Get("Idempotency-Key")
	if !uuidRegex.MatchString(key) {
		t.Fatalf("expected UUID idempotency key, got %q", key)
	}
}

func TestGenerateClaimSingleCallOnSuccess(t *testing.T) {
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redemptionBody())
	})
	if _, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(m.calls()); n != 1 {
		t.Fatalf("expected exactly 1 call, got %d", n)
	}
}

func TestGenerateClaimRetriesAndSucceeds(t *testing.T) {
	failCount := 2
	calls := 0
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		if calls < failCount {
			calls++
			writeError(w, 503, "Service Unavailable")
			return
		}
		writeJSON(w, redemptionBody())
	})
	res, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ClaimPayload != claimPayload {
		t.Fatalf("unexpected claim payload: %q", res.ClaimPayload)
	}
	if n := len(m.calls()); n != 3 {
		t.Fatalf("expected 3 calls, got %d", n)
	}
}

func TestGenerateClaimSameIdempotencyKeyAcrossRetries(t *testing.T) {
	calls := 0
	m := newMockPersona(t, func(m *mockPersona, w http.ResponseWriter, r *http.Request) {
		if calls < 2 {
			calls++
			writeError(w, 503, "Service Unavailable")
			return
		}
		writeJSON(w, redemptionBody())
	})
	if _, err := m.client().Relays.GenerateClaim(context.Background(), defaultGenerateParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := m.calls()
	if len(seen) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(seen))
	}
	k0 := seen[0].Header.Get("Idempotency-Key")
	for i, c := range seen {
		if c.Header.Get("Idempotency-Key") != k0 {
			t.Fatalf("idempotency key differs at call %d", i)
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func assertPersonaError(t *testing.T, err error, status int, title string) {
	t.Helper()
	var perr *PersonaError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *PersonaError, got %T: %v", err, err)
	}
	if perr.StatusCode != status {
		t.Errorf("expected status %d, got %d", status, perr.StatusCode)
	}
	if perr.Title != title {
		t.Errorf("expected title %q, got %q", title, perr.Title)
	}
}

func findCall(calls []capturedRequest, substr string) *capturedRequest {
	for i := range calls {
		if strings.Contains(calls[i].Path, substr) {
			return &calls[i]
		}
	}
	return nil
}
