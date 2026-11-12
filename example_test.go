package persona_test

import (
	"context"
	"fmt"
	"log"

	persona "github.com/persona-id/relay-sdk-go"
)

func Example() {
	ctx := context.Background()
	client := persona.New(persona.Options{APIKey: "<YOUR_API_KEY>"})

	relay, err := client.Relays.Create(ctx, "live_human_presence", nil)
	if err != nil {
		log.Fatal(err)
	}

	issued, err := client.Relays.IssuePrivacyPass(ctx, "live_human_presence")
	if err != nil {
		log.Fatal(err)
	}

	claim, err := client.Relays.GenerateClaim(ctx, issued.PrivacyPassToken, relay.RelayToken, relay.RelaySecret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claim.ClaimPayload, claim.TokenConsumed)
}
