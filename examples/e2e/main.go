// Command e2e exercises the full Persona relay flow against the live Persona API.
//
// It is a manual integration-testing helper, not part of the importable SDK. Provide a
// Persona API key via PERSONA_API_KEY and run it from the repo root:
//
//	PERSONA_API_KEY=<key> go run ./examples/e2e
//
// Optional environment variables:
//
//		PERSONA_CLAIM_TYPE  claim type to request (default "live_human_presence")
//		PERSONA_DOMAIN      Persona domain (default "withpersona.com").
//	                     The API base becomes "https://api.<domain>"
//		                    and the hosted relay flow becomes "https://relay.<domain>/relay".
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"

	persona "github.com/persona-id/relay-sdk-go"
)

const defaultDomain = "withpersona.com"

func main() {
	apiKey := os.Getenv("PERSONA_API_KEY")
	if apiKey == "" {
		log.Fatal("PERSONA_API_KEY is required")
	}

	claimType := os.Getenv("PERSONA_CLAIM_TYPE")
	if claimType == "" {
		claimType = "live_human_presence"
	}

	domain := os.Getenv("PERSONA_DOMAIN")
	if domain == "" {
		domain = defaultDomain
	}

	client := persona.New(persona.Options{
		APIKey:  apiKey,
		BaseURL: fmt.Sprintf("https://api.%s", domain),
	})

	hostedBaseURL := fmt.Sprintf("https://relay.%s/relay", domain)

	ctx := context.Background()

	// 1. Create a relay session.
	relay, err := client.Relays.Create(ctx, persona.CreateRelayParams{ClaimType: claimType})
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	fmt.Println("relay created:")
	fmt.Printf("  relayToken:              %s\n", relay.RelayToken)
	fmt.Printf("  relaySecret:             %s\n", relay.RelaySecret)
	fmt.Printf("  relaySessionAccessToken: %s\n", relay.RelaySessionAccessToken)
	fmt.Println()

	// 2. Open the hosted relay flow in a browser so the user can complete it.
	// Redemption only succeeds after the hosted flow has been completed.
	hostedURL := buildHostedURL(hostedBaseURL, relay.RelaySessionAccessToken)
	fmt.Println("open the hosted relay flow and complete it:")
	fmt.Printf("  %s\n", hostedURL)
	if err := openBrowser(hostedURL); err != nil {
		fmt.Printf("  (could not open browser automatically: %v)\n", err)
	}
	fmt.Print("\npress Enter once you have completed the hosted flow... ")
	bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()

	// 3. Issue a Privacy Pass token via the blind RSA flow.
	issued, err := client.Relays.IssuePrivacyPass(ctx, persona.IssuePrivacyPassParams{ClaimType: claimType})
	if err != nil {
		log.Fatalf("issue: %v", err)
	}
	fmt.Println("privacy pass issued:")
	fmt.Printf("  privacyPassToken: %s\n", issued.PrivacyPassToken)
	fmt.Println()

	// 4. Redeem the token for a claim.
	claim, err := client.Relays.GenerateClaim(ctx, persona.GenerateClaimParams{
		PrivacyPassToken: issued.PrivacyPassToken,
		RelayToken:       relay.RelayToken,
		RelaySecret:      relay.RelaySecret,
	})
	if err != nil {
		log.Fatalf("generateClaim: %v", err)
	}
	fmt.Println("claim generated:")
	fmt.Printf("  claimPayload:  %s\n", claim.ClaimPayload)
	fmt.Printf("  tokenConsumed: %t\n", claim.TokenConsumed)
}

// buildHostedURL builds the hosted relay flow URL for the given session access token.
func buildHostedURL(baseURL, relaySessionAccessToken string) string {
	q := url.Values{}
	q.Set("relay-session-access-token", relaySessionAccessToken)
	q.Set("theme", "auto")
	return baseURL + "?" + q.Encode()
}

// openBrowser opens the given URL in the system's default browser.
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}
