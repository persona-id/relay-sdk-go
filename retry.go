package persona

import (
	"context"
	"errors"
	"time"
)

const baseRetryDelay = 100 * time.Millisecond

type retryOptions struct {
	maxRetries  int
	shouldRetry func(*PersonaError) bool
}

// withRetries calls fn, retrying up to opts.maxRetries times with exponential
// backoff (baseRetryDelay, 2x, 4x, ...).
//
// A call is only retried when it returns a *PersonaError for which
// opts.shouldRetry reports true. Any other error (including a non-PersonaError)
// is returned immediately. The context aborts both the wait and the retry loop.
func withRetries[T any](ctx context.Context, opts retryOptions, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error

	for retry := 0; retry <= opts.maxRetries; retry++ {
		if retry > 0 {
			delay := baseRetryDelay * (1 << (retry - 1))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return zero, ctx.Err()
			case <-timer.C:
			}
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		var perr *PersonaError
		if !errors.As(err, &perr) || (opts.shouldRetry != nil && !opts.shouldRetry(perr)) {
			return zero, err
		}
		lastErr = err
	}

	return zero, lastErr
}
