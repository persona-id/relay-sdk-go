# Changelog

## [0.2.0](https://github.com/persona-id/relay-sdk-internal/compare/relay-sdk-go-v0.1.1...relay-sdk-go-v0.2.0) (2026-11-12)


### ⚠ BREAKING CHANGES

* **go:** Relays methods take their required arguments positionally and end with opts ...RequestOption: Create(ctx, claimType, encryptionKeyJWK, opts...), IssuePrivacyPass(ctx, claimType, opts...) and GenerateClaim(ctx, privacyPassToken, relayToken, relaySecret, opts...). CreateRelayParams, IssuePrivacyPassParams and GenerateClaimParams are removed, and CreateRelayResponse is renamed to Relay. EncryptionKeyPEM is removed: claim payloads are encrypted only with an RSA public JWK (RSA-OAEP-256, built with NewEncryptionJWK), and a nil key opts out. Every request sends Persona-Version: 2026-09-29.

### Features

* **go:** require an encryption JWK, pass Relays arguments positionally and pin Persona-Version 2026-09-29 ([#48](https://github.com/persona-id/relay-sdk-internal/issues/48)) ([a89c964](https://github.com/persona-id/relay-sdk-internal/commit/a89c964c05d554956eea1e92d543c6a91ff06c4c))

## [0.1.1](https://github.com/persona-id/relay-sdk-internal/compare/relay-sdk-go-v0.1.0...relay-sdk-go-v0.1.1) (2026-08-24)


### Features

* infer Relay sandbox from API key ([79b06bb](https://github.com/persona-id/relay-sdk-internal/commit/79b06bb9c48bd5879f4f5ff6e13059b41d2307b1))

## 0.1.0 (2026-07-02)


### Features

* Go server SDK for Relay integration ([9ab6731](https://github.com/persona-id/relay-sdk-go-internal/commit/9ab6731c8fb7c8453a70c9d231768f09eb558193))
