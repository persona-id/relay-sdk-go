package persona

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	defaultBaseURL   = "https://api.withpersona.com"
	requestTimeoutMS = 10_000
)

type apiError struct {
	Title   string         `json:"title"`
	Details string         `json:"details,omitempty"`
	Code    string         `json:"code,omitempty"`
	Meta    map[string]any `json:"meta,omitempty"`
}

type apiErrorResponse struct {
	Errors []apiError `json:"errors"`
}

type client struct {
	baseURL    string
	httpClient *http.Client
}

func newClient(baseURL string, httpClient *http.Client) *client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &client{baseURL: baseURL, httpClient: httpClient}
}

func (c *client) post(ctx context.Context, path string, body any, headers map[string]string, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return &PersonaError{StatusCode: int(StatusBadRequest), Title: "Failed to encode request body", Details: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return &PersonaError{StatusCode: int(StatusBadGateway), Title: "Failed to build request", Details: err.Error()}
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errorFromResponse(res)
	}

	if out == nil {
		return nil
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return transportError(err)
	}
	if err := json.Unmarshal(resBody, out); err != nil {
		return &PersonaError{StatusCode: res.StatusCode, Title: "Failed to decode Persona response", Details: err.Error()}
	}
	return nil
}

func transportError(err error) *PersonaError {
	if isTimeout(err) {
		return &PersonaError{StatusCode: int(StatusGatewayTimeout), Title: "Request to Persona timed out"}
	}
	return &PersonaError{StatusCode: int(StatusBadGateway), Title: "Network error", Details: err.Error()}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	var timeoutErr interface{ Timeout() bool }
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

func errorFromResponse(res *http.Response) *PersonaError {
	resBody, _ := io.ReadAll(res.Body)

	var parsed apiErrorResponse
	if err := json.Unmarshal(resBody, &parsed); err == nil && len(parsed.Errors) > 0 {
		return personaErrorFromStatus(HTTPStatusCode(res.StatusCode), parsed.Errors[0])
	}

	return personaErrorFromStatus(HTTPStatusCode(res.StatusCode), apiError{
		Details: fmt.Sprintf("unexpected response body: %s", string(resBody)),
	})
}
