package persona

import "fmt"

type HTTPStatusCode int

const (
	StatusOK                  HTTPStatusCode = 200
	StatusBadRequest          HTTPStatusCode = 400
	StatusUnauthorized        HTTPStatusCode = 401
	StatusForbidden           HTTPStatusCode = 403
	StatusNotFound            HTTPStatusCode = 404
	StatusRateLimited         HTTPStatusCode = 429
	StatusInternalServerError HTTPStatusCode = 500
	StatusBadGateway          HTTPStatusCode = 502
	StatusServiceUnavailable  HTTPStatusCode = 503
	StatusGatewayTimeout      HTTPStatusCode = 504
)

type PersonaError struct {
	StatusCode int
	Title      string
	Details    string
	Code       string
	Meta       map[string]any
}

func (e *PersonaError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("persona: %s (%s) [status %d]", e.Title, e.Details, e.StatusCode)
	}
	return fmt.Sprintf("persona: %s [status %d]", e.Title, e.StatusCode)
}

var defaultTitles = map[HTTPStatusCode]string{
	StatusBadRequest:          "Bad request",
	StatusUnauthorized:        "Unauthorized",
	StatusForbidden:           "Forbidden",
	StatusNotFound:            "Not found",
	StatusRateLimited:         "Rate limited",
	StatusInternalServerError: "Internal server error",
	StatusBadGateway:          "Bad gateway",
	StatusServiceUnavailable:  "Service unavailable",
	StatusGatewayTimeout:      "Gateway timeout",
}

func personaErrorFromStatus(status HTTPStatusCode, apiErr apiError) *PersonaError {
	title := apiErr.Title
	if title == "" {
		if def, ok := defaultTitles[status]; ok {
			title = def
		} else {
			title = "Internal server error"
		}
	}
	return &PersonaError{
		StatusCode: int(status),
		Title:      title,
		Details:    apiErr.Details,
		Code:       apiErr.Code,
		Meta:       apiErr.Meta,
	}
}
