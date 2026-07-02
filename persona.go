// Package persona is the official Go server library for Persona's Relay feature.
//
// For full documentation, see https://docs.withpersona.com/relay-server-sdk-reference.
package persona

import (
	"net/http"
	"time"
)

type Options struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

type Persona struct {
	Relays *Relays
}

func New(opts Options) *Persona {
	api := newPersonaAPI(opts)
	return &Persona{
		Relays: &Relays{api: api},
	}
}

func resolveHTTPClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: requestTimeoutMS * time.Millisecond}
}
