package persona

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

const (
	testNonce        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testChallengeMac = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testKeyID        = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestBuildTokenInputLength(t *testing.T) {
	result := buildTokenInput(testNonce, testChallengeMac, testKeyID)
	if len(result) != 98 {
		t.Fatalf("expected 98 bytes, got %d", len(result))
	}
}

func TestBuildTokenInputTokenType(t *testing.T) {
	result := buildTokenInput(testNonce, testChallengeMac, testKeyID)
	if result[0] != 0x00 || result[1] != 0x02 {
		t.Fatalf("expected token type 0x0002, got 0x%02x%02x", result[0], result[1])
	}
}

func TestBuildTokenInputEmbedsHashes(t *testing.T) {
	result := buildTokenInput(testNonce, testChallengeMac, testKeyID)

	hNonce := sha256.Sum256([]byte(testNonce))
	if !bytes.Equal(result[2:34], hNonce[:]) {
		t.Errorf("SHA-256(nonce) not embedded at bytes 2-33")
	}

	hMac := sha256.Sum256([]byte(testChallengeMac))
	if !bytes.Equal(result[34:66], hMac[:]) {
		t.Errorf("SHA-256(challengeMac) not embedded at bytes 34-65")
	}

	hKeyID := sha256.Sum256([]byte(testKeyID))
	if !bytes.Equal(result[66:98], hKeyID[:]) {
		t.Errorf("SHA-256(keyId) not embedded at bytes 66-97")
	}
}

func TestBuildTokenInputDiffersByNonce(t *testing.T) {
	a := buildTokenInput(strings.Repeat("a", 64), testChallengeMac, testKeyID)
	b := buildTokenInput(strings.Repeat("b", 64), testChallengeMac, testKeyID)
	if bytes.Equal(a, b) {
		t.Error("expected different token input for different nonces")
	}
}

func TestGenerateNonceFormat(t *testing.T) {
	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nonce) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(nonce))
	}
	for _, c := range nonce {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("nonce contains non-hex character %q", c)
		}
	}
	other, _ := generateNonce()
	if nonce == other {
		t.Error("expected unique nonces across calls")
	}
}
