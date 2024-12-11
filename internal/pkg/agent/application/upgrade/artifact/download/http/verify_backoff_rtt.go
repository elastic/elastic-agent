package http

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func WithBackoff(rtt http.RoundTripper, logger *logger.Logger) http.RoundTripper {
	if rtt == nil {
		rtt = http.DefaultTransport
	}

	return &BackoffRoundTripper{next: rtt, logger: logger}
}

type BackoffRoundTripper struct {
	next   http.RoundTripper
	logger *logger.Logger
}

func (btr *BackoffRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	exp := backoff.NewExponentialBackOff()
	boCtx := backoff.WithContext(exp, req.Context())

	opNotify := func(err error, retryAfter time.Duration) {
		btr.logger.Warnf("request failed: %s, retrying in %s", err, retryAfter)
	}

	var resp *http.Response
	var err error
	opFunc := func() error {
		resp, err = btr.next.RoundTrip(req)
		if err != nil {
			return err
		}

		if resp.StatusCode >= 400 {
			return errors.New(fmt.Sprintf("received response status: %d", resp.StatusCode))
		}

		return nil
	}

	return resp, backoff.RetryNotify(opFunc, boCtx, opNotify)
}
