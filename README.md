# Persona Go Server SDK

The official Go server library for Persona integration.

For full documentation, see
[Relay Server SDK Reference](https://docs.withpersona.com/relay-server-sdk-reference).

## Installation

```sh
go get github.com/persona-id/relay-sdk-go
```

## Usage

```go
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
```
