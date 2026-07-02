package persona

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const blindRSAVariant = blindrsa.SHA384PSSRandomized

type Relays struct {
	api *personaAPI
}

type CreateRelayParams struct {
	ClaimType        string
	EncryptionKeyPEM *string
}

type CreateRelayResponse struct {
	RelayToken              string
	RelaySecret             string
	RelaySessionAccessToken string
}

type IssuePrivacyPassParams struct {
	ClaimType string
}

type IssuePrivacyPassResponse struct {
	PrivacyPassToken string
}

type GenerateClaimParams struct {
	PrivacyPassToken string
	RelayToken       string
	RelaySecret      string
}

type GenerateClaimResponse struct {
	ClaimPayload  string
	TokenConsumed bool
}

type relayChallenge struct {
	TokenType  int    `json:"token_type"`
	IssuerName string `json:"issuer_name"`
	OriginInfo string `json:"origin_info"`
	ExpiresAt  string `json:"expires_at"`
	Mac        string `json:"mac"`
}

type tokenPayload struct {
	TokenNonce string          `json:"token_nonce"`
	Signature  string          `json:"signature"`
	KeyID      string          `json:"key_id"`
	Challenge  json.RawMessage `json:"challenge"`
}

func (r *Relays) Create(ctx context.Context, params CreateRelayParams) (*CreateRelayResponse, error) {
	resp, err := r.api.createRelay(ctx, params.ClaimType, params.EncryptionKeyPEM)
	if err != nil {
		return nil, err
	}
	return &CreateRelayResponse{
		RelayToken:              resp.RelayToken,
		RelaySecret:             resp.RelaySecret,
		RelaySessionAccessToken: resp.RelaySessionAccessToken,
	}, nil
}

// IssuePrivacyPass issues a Privacy Pass token via the blind RSA flow:
//
//  1. Fetch the challenge and public key from the challenge endpoint.
//  2. Generate a random nonce and construct the 98-byte token input.
//  3. Blind the token input with Persona's public key.
//  4. Submit the blinded token for blind signing.
//  5. Unblind the signature and assemble the PrivateToken.
func (r *Relays) IssuePrivacyPass(ctx context.Context, params IssuePrivacyPassParams) (*IssuePrivacyPassResponse, error) {
	// Step 1: Fetch the challenge from the dedicated challenge endpoint.
	challengeResp, err := r.api.getChallenge(ctx, params.ClaimType)
	if err != nil {
		return nil, err
	}
	keyID := challengeResp.TokenKeyID

	// Step 2: Decode the challenge JSON and extract the MAC.
	challengeBytes, err := base64.RawURLEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusBadGateway), Title: "Failed to decode challenge", Details: err.Error()}
	}
	var challengeObj relayChallenge
	if err := json.Unmarshal(challengeBytes, &challengeObj); err != nil {
		return nil, &PersonaError{StatusCode: int(StatusBadGateway), Title: "Failed to parse challenge", Details: err.Error()}
	}
	if challengeObj.Mac == "" {
		return nil, &PersonaError{StatusCode: int(StatusBadGateway), Title: "Challenge missing mac", Details: "challenge response did not include a string mac"}
	}
	challengeMac := challengeObj.Mac

	// Step 3: Generate a nonce and build the token input.
	nonce, err := generateNonce()
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to generate nonce", Details: err.Error()}
	}
	tokenInput := buildTokenInput(nonce, challengeMac, keyID)

	// Step 4: Blind the token input using Persona's public key.
	publicKey, err := importPublicKey(challengeResp.TokenKey)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusBadGateway), Title: "Failed to import public key", Details: err.Error()}
	}

	blindClient, err := blindrsa.NewClient(blindRSAVariant, publicKey)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to initialize blind RSA client", Details: err.Error()}
	}

	blindedMsg, state, err := blindClient.Blind(rand.Reader, tokenInput)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to blind token", Details: err.Error()}
	}

	// Step 5: Submit the blinded token to Persona for blind signing.
	privacyPassResp, err := r.api.issuePrivacyPass(ctx, base64.RawURLEncoding.EncodeToString(blindedMsg), keyID)
	if err != nil {
		return nil, err
	}

	// Step 6: Unblind the signature.
	blindSig, err := base64.RawURLEncoding.DecodeString(privacyPassResp.BlindSig)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusBadGateway), Title: "Failed to decode blind signature", Details: err.Error()}
	}

	signature, err := blindClient.Finalize(state, blindSig)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to finalize signature", Details: err.Error()}
	}

	// Step 7: Construct and return the PrivateToken.
	payload := tokenPayload{
		TokenNonce: nonce,
		Signature:  base64.RawURLEncoding.EncodeToString(signature),
		KeyID:      keyID,
		Challenge:  challengeBytes,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Failed to encode Privacy Pass token", Details: err.Error()}
	}

	return &IssuePrivacyPassResponse{
		PrivacyPassToken: base64.RawURLEncoding.EncodeToString(payloadBytes),
	}, nil
}

func (r *Relays) GenerateClaim(ctx context.Context, params GenerateClaimParams) (*GenerateClaimResponse, error) {
	resp, err := r.api.redeemRelay(ctx, params.RelayToken, params.PrivacyPassToken, params.RelaySecret)
	if err != nil {
		return nil, err
	}
	return &GenerateClaimResponse{
		ClaimPayload:  resp.ClaimPayload,
		TokenConsumed: resp.TokenConsumed,
	}, nil
}
