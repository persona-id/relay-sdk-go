package persona

import (
	"context"
	"errors"
	"testing"
)

func alwaysRetry(*PersonaError) bool { return true }

func TestWithRetriesReturnsImmediatelyOnSuccess(t *testing.T) {
	calls := 0
	result, err := withRetries(context.Background(), retryOptions{maxRetries: 3, shouldRetry: alwaysRetry}, func() (string, error) {
		calls++
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %q", result)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestWithRetriesExhaustsAndReturnsLastError(t *testing.T) {
	calls := 0
	final := &PersonaError{StatusCode: int(StatusInternalServerError), Title: "Internal server error"}
	_, err := withRetries(context.Background(), retryOptions{maxRetries: 3, shouldRetry: alwaysRetry}, func() (string, error) {
		calls++
		return "", final
	})
	if !errors.Is(err, final) {
		t.Fatalf("expected final error, got %v", err)
	}
	if calls != 4 { // 1 initial + 3 retries
		t.Fatalf("expected 4 calls, got %d", calls)
	}
}

func TestWithRetriesReturnsLastOfVaryingErrors(t *testing.T) {
	errs := []*PersonaError{
		{StatusCode: 500, Title: "Internal Server Error"},
		{StatusCode: 503, Title: "Service Unavailable"},
		{StatusCode: 502, Title: "Bad Gateway"},
		{StatusCode: 429, Title: "Rate Limited"},
	}
	calls := 0
	_, err := withRetries(context.Background(), retryOptions{maxRetries: 3, shouldRetry: alwaysRetry}, func() (string, error) {
		e := errs[calls]
		calls++
		return "", e
	})
	if !errors.Is(err, errs[3]) {
		t.Fatalf("expected last error, got %v", err)
	}
	if calls != 4 {
		t.Fatalf("expected 4 calls, got %d", calls)
	}
}

func TestWithRetriesNoRetryWhenShouldRetryFalse(t *testing.T) {
	calls := 0
	want := &PersonaError{StatusCode: int(StatusBadRequest), Title: "Bad request"}
	_, err := withRetries(context.Background(), retryOptions{maxRetries: 3, shouldRetry: func(*PersonaError) bool { return false }}, func() (string, error) {
		calls++
		return "", want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected bad request error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestWithRetriesNoRetryOnNonPersonaError(t *testing.T) {
	calls := 0
	want := errors.New("network boom")
	_, err := withRetries(context.Background(), retryOptions{maxRetries: 2, shouldRetry: alwaysRetry}, func() (string, error) {
		calls++
		return "", want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected raw error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestWithRetriesSucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	result, err := withRetries(context.Background(), retryOptions{maxRetries: 3, shouldRetry: alwaysRetry}, func() (string, error) {
		calls++
		if calls < 3 {
			return "", &PersonaError{StatusCode: 500, Title: "Internal server error"}
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %q", result)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}
