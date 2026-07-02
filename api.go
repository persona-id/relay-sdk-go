package persona

import (
	"context"
	"crypto/rand"
	"fmt"
)

const maxRetries = 3

var defaultRetryStatuses = map[HTTPStatusCode]bool{
	StatusRateLimited:         true,
	StatusInternalServerError: true,
	StatusBadGateway:          true,
	StatusServiceUnavailable:  true,
	StatusGatewayTimeout:      true,
}

func defaultShouldRetry(err *PersonaError) bool {
	return defaultRetryStatuses[HTTPStatusCode(err.StatusCode)]
}

type createRelayAPIResponse struct {
	RelayToken              string `json:"relay-token"`
	RelaySecret             string `json:"relay-secret"`
	RelaySessionAccessToken string `json:"relay-session-access-token"`
}

type challengeAPIResponse struct {
	Challenge  string `json:"challenge"`
	TokenKey   string `json:"token-key"`
	TokenKeyID string `json:"token-key-id"`
}

type issuePrivacyPassAPIResponse struct {
	BlindSig string `json:"blind-sig"`
}

type generateClaimAPIResponse struct {
	ClaimPayload  string `json:"claim-payload"`
	TokenConsumed bool   `json:"token-consumed"`
}

type personaAPI struct {
	client *client
	apiKey string
}

func newPersonaAPI(opts Options) *personaAPI {
	return &personaAPI{
		client: newClient(opts.BaseURL, resolveHTTPClient(opts.HTTPClient)),
		apiKey: opts.APIKey,
	}
}

func (a *personaAPI) createRelay(ctx context.Context, claimType string, encryptionKeyPEM *string) (*createRelayAPIResponse, error) {
	return withRetries(ctx, retryOptions{maxRetries: maxRetries, shouldRetry: defaultShouldRetry}, func() (*createRelayAPIResponse, error) {
		var resp createRelayAPIResponse
		body := map[string]any{"claimType": claimType, "encryptionKeyPem": encryptionKeyPEM}
		if err := a.client.post(ctx, "/api/privacy/v1/relays", body, nil, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	})
}

func (a *personaAPI) getChallenge(ctx context.Context, claimType string) (*challengeAPIResponse, error) {
	return withRetries(ctx, retryOptions{maxRetries: maxRetries, shouldRetry: defaultShouldRetry}, func() (*challengeAPIResponse, error) {
		var resp challengeAPIResponse
		body := map[string]any{"claimType": claimType}
		if err := a.client.post(ctx, "/api/privacy/v1/relays/challenge", body, nil, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	})
}

func (a *personaAPI) issuePrivacyPass(ctx context.Context, blindedToken, keyID string) (*issuePrivacyPassAPIResponse, error) {
	return withRetries(ctx, retryOptions{maxRetries: maxRetries, shouldRetry: defaultShouldRetry}, func() (*issuePrivacyPassAPIResponse, error) {
		var resp issuePrivacyPassAPIResponse
		body := map[string]any{"blindedToken": blindedToken, "keyId": keyID}
		headers := map[string]string{"Authorization": "Bearer " + a.apiKey}
		if err := a.client.post(ctx, "/api/v1/privacy-passes", body, headers, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	})
}

func (a *personaAPI) redeemRelay(ctx context.Context, relayToken, privacyPassToken, relaySecret string) (*generateClaimAPIResponse, error) {
	idempotencyKey, err := newUUIDv4()
	if err != nil {
		return nil, err
	}

	shouldRetry := func(e *PersonaError) bool {
		return defaultShouldRetry(e) || HTTPStatusCode(e.StatusCode) == StatusForbidden
	}

	return withRetries(ctx, retryOptions{maxRetries: maxRetries, shouldRetry: shouldRetry}, func() (*generateClaimAPIResponse, error) {
		var resp generateClaimAPIResponse
		headers := map[string]string{
			"Authorization":        "PrivateToken token=" + privacyPassToken,
			"Persona-Relay-Secret": relaySecret,
			"Idempotency-Key":      idempotencyKey,
		}
		path := fmt.Sprintf("/api/privacy/v1/relays/%s/generate-claim", relayToken)
		if err := a.client.post(ctx, path, map[string]any{}, headers, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	})
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to generate idempotency key", Details: err.Error()}
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
