package persona

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// tokenInputLength is the size of the Privacy Pass token input in bytes:
// 2 (token type) + 32 (H(nonce)) + 32 (H(challengeMac)) + 32 (H(keyId)).
const tokenInputLength = 98

// buildTokenInput constructs the 98-byte Privacy Pass token input per RFC 9578:
//
//	0x0002 (2 bytes) || H(nonce) (32) || H(challengeMac) (32) || H(keyId) (32)
//
// All inputs are hashed as their plain UTF-8 string bytes with SHA-256.
func buildTokenInput(nonce, challengeMac, keyID string) []byte {
	out := make([]byte, 0, tokenInputLength)
	out = append(out, 0x00, 0x02)

	hNonce := sha256.Sum256([]byte(nonce))
	out = append(out, hNonce[:]...)

	hMac := sha256.Sum256([]byte(challengeMac))
	out = append(out, hMac[:]...)

	hKeyID := sha256.Sum256([]byte(keyID))
	out = append(out, hKeyID[:]...)

	return out
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("persona: failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func importPublicKey(publicKeyBase64URL string) (*rsa.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(publicKeyBase64URL)
	if err != nil {
		return nil, fmt.Errorf("persona: failed to decode token key: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("persona: failed to parse token key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("persona: token key is not an RSA public key")
	}
	return rsaPub, nil
}
